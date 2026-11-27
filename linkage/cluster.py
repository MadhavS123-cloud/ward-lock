"""Group the same patient across records and assign one fake id.

Names are normalized, then compared with rapidfuzz. Word order is ignored.
A score of 80 or more is the same person. "Ramesh K." matches "Ramesh Kumar"
because K. is an initial. "Suresh Kumar" does not.

A shared name is not enough when the chart numbers disagree. Two people
called Harish Pandey stay apart. A phone, Aadhaar, ABHA, or hospital number
still joins records when the name is missing or spelled differently.
A score from 70 up to 80 does not link. No link is safer than a wrong one.
"""

from __future__ import annotations

import re

from rapidfuzz import fuzz

from pseudonym.hmac import patient_id
from utils.translit import to_latin

# rapidfuzz token scores are 0-100. 80 links a person. Below that, do not guess.
_MATCH = 80

# Titles are not part of the name. श्री रमेश कुमार and Ramesh Kumar share one id.
# sahaba is the old transliteration of साहब; sahab is the plain spelling.
_HONORIFICS = {
    "ji", "sahab", "sahib", "sahaba", "didi",
    "shri", "shree", "sri", "smt", "shrimati", "kumari",
    "mr", "mrs", "ms", "miss", "master",
}

# These are not the patient's own name.
_RELATIVE_CUES = {"C/O", "S/O", "D/O", "W/O", "KIN"}
_PATIENT_FIELDS = {"patientname", "fullname", "name"}
_SKIP_FIELDS = {
    "guardianname", "fathername", "mothername", "spousename", "husbandname",
    "wifename", "relativename", "attendantname", "doctorname", "doctor",
    "consultant", "physician", "surgeon", "medicine", "drug", "dose", "dosage",
}

# A facility string sits in a name field on FHIR bundles. It is not a person.
_ORG_WORDS = {
    "hospital", "charitable", "multispeciality", "multispecialty",
    "clinic", "diagnostics", "pharmacy", "healthcare", "pathlab",
    "laboratory", "laboratories", "nursing", "institute",
}
# Field path pieces that belong to someone else, or to the hospital.
_SKIP_PATH = (
    "organization", "practitioner", "author", "performer", "contact",
    "guardian", "mother", "father", "spouse", "husband", "wife",
    "relative", "attendant", "hospital", "doctor",
)
_PHONE_HINTS = ("mobile", "phone", "telecom", "contactno", "phoneno")
_UHID_LEAFS = {
    "uhid", "mrn", "patientref", "patientid", "hospitalno",
    "ipdno", "ipd", "opdno", "registrationno",
}
_DEV_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")


def normalize_name(name: str) -> str:
    """Lowercase a name, transliterate Hindi, and drop ji/shri/sahab.

    रमेश कुमार and Ramesh Kumar both become ramesh kumar, so they share one id.
    """
    text = to_latin(name.strip()).lower()
    text = re.sub(r"[^a-z\s]", " ", text)
    tokens = [token for token in text.split() if token not in _HONORIFICS]
    return " ".join(tokens)


def assign_patients(records: list[dict], findings: list[dict]) -> list[dict]:
    """Copy records and set patient to a PSN- id, or null when unsure."""
    by_record: dict[int, list[dict]] = {}
    for item in findings:
        by_record.setdefault(int(item.get("record", 0)), []).append(item)

    chosen: list[str | None] = []
    charts: list[dict[str, set[str]]] = []
    for index, record in enumerate(records):
        hits = by_record.get(index, [])
        if not isinstance(record, dict):
            chosen.append(None)
            charts.append(_empty_chart())
            continue
        chosen.append(_select_name(record, hits))
        charts.append(_chart_ids(hits))

    labels = _link_labels(chosen, charts)
    linked: list[dict] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            linked.append(record)
            continue
        copy = dict(record)
        copy["patient"] = labels[index]
        linked.append(copy)
    return linked


def _select_name(record: dict, items: list[dict]) -> str | None:
    """Patient name only. Relatives, doctors, and hospitals are left out."""
    kept = []
    for item in items:
        if item.get("type") != "name":
            continue
        if item.get("cue") in _RELATIVE_CUES:
            continue
        if _path_skipped(str(item.get("field", ""))):
            continue
        kept.append(item)
    return _person_name(_choose_name(record, kept))


def _person_name(name: str | None) -> str | None:
    """Drop a facility string. A one-letter stub is not a person either."""
    if not name:
        return None
    tokens = name.split()
    if any(token in _ORG_WORDS for token in tokens):
        return None
    if len(tokens) == 1 and len(tokens[0]) < 4:
        return None
    return name


def _path_skipped(field: str) -> bool:
    low = field.lower()
    return any(token in low for token in _SKIP_PATH)


def _empty_chart() -> dict[str, set[str]]:
    return {"phone": set(), "aadhaar": set(), "abha": set(), "uhid": set(), "email": set()}


def _digits(text: str) -> str:
    return "".join(ch for ch in text.translate(_DEV_DIGITS) if ch.isdigit())


def _phone_key(text: str) -> str | None:
    raw = _digits(text)
    if raw.startswith("91") and len(raw) >= 12:
        raw = raw[2:]
    if len(raw) == 11 and raw.startswith("0"):
        raw = raw[1:]
    if len(raw) != 10 or raw[0] not in "6789":
        return None
    return raw


def _uhid_key(text: str) -> str | None:
    raw = _digits(text).lstrip("0")
    if len(raw) < 5 or len(raw) > 16:
        return None
    return raw


def _chart_ids(items: list[dict]) -> dict[str, set[str]]:
    """Identifiers that belong to this visit, not a bill or a reference."""
    chart = _empty_chart()
    for item in items:
        kind = item.get("type")
        field = str(item.get("field", ""))
        low = field.lower()
        if "reference" in low or "fullurl" in low or "bill" in low:
            continue
        text = str(item.get("text", ""))
        if kind == "phone" and any(hint in low for hint in _PHONE_HINTS):
            key = _phone_key(text)
            if key:
                chart["phone"].add(key)
        elif kind == "aadhaar":
            raw = _digits(text)
            if len(raw) == 12:
                chart["aadhaar"].add(raw)
        elif kind == "abha":
            raw = _digits(text)
            if len(raw) == 14:
                chart["abha"].add(raw)
        elif kind == "email" and "@" in text:
            chart["email"].add(text.strip().lower())
        elif kind in {"uhid", "mrn"} and (
            _leaf(field) in _UHID_LEAFS or "identifier" in low or "uhid" in low or "mrn" in low
        ):
            key = _uhid_key(text)
            if key:
                chart["uhid"].add(key)
    return chart


def _charts_conflict(left: dict[str, set[str]], right: dict[str, set[str]]) -> bool:
    """True when both records name a chart and the charts cannot be one person.

    A second hospital number does not split a person who shares a phone:
    those two rows are already joined on the phone before names are compared.
    """
    for key in ("phone", "aadhaar", "abha", "email", "uhid"):
        if left[key] and right[key] and not (left[key] & right[key]):
            return True
    return False


def _merge_charts(left: dict[str, set[str]], right: dict[str, set[str]]) -> dict[str, set[str]]:
    return {key: set(left[key]) | set(right[key]) for key in left}


def _link_labels(names: list[str | None], charts: list[dict[str, set[str]]]) -> list[str | None]:
    """One PSN- id per person. Homonyms with the same spelling get different ids."""
    count = len(names)
    parent = list(range(count))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> int:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left
        return find(left)

    buckets: dict[tuple[str, str], list[int]] = {}
    for index, chart in enumerate(charts):
        for key, values in chart.items():
            for value in values:
                buckets.setdefault((key, value), []).append(index)
    for members in buckets.values():
        head = members[0]
        for other in members[1:]:
            union(head, other)

    def groups() -> dict[int, list[int]]:
        grouped: dict[int, list[int]] = {}
        for index in range(count):
            if names[index] or any(charts[index][key] for key in charts[index]):
                grouped.setdefault(find(index), []).append(index)
        return grouped

    def payloads(grouped: dict[int, list[int]]):
        merged: dict[int, dict[str, set[str]]] = {}
        canon: dict[int, str | None] = {}
        for root, members in grouped.items():
            chart = _empty_chart()
            for index in members:
                chart = _merge_charts(chart, charts[index])
            named = [names[index] for index in members if names[index]]
            merged[root] = chart
            canon[root] = min(named) if named else None
        return merged, canon

    grouped = groups()
    merged, canon = payloads(grouped)
    evidenced = [
        root
        for root, name in canon.items()
        if name and any(merged[root][key] for key in merged[root])
    ]
    for left_i, left in enumerate(evidenced):
        for right in evidenced[left_i + 1 :]:
            root_left, root_right = find(left), find(right)
            if root_left == root_right:
                continue
            left_name, right_name = canon.get(root_left), canon.get(root_right)
            if not left_name or not right_name:
                continue
            if _name_score(left_name, right_name) < _MATCH:
                continue
            if _charts_conflict(merged[root_left], merged[root_right]):
                continue
            # Fold the chart numbers first, so the next pair sees the conflict.
            combined = _merge_charts(merged[root_left], merged[root_right])
            kept = min(left_name, right_name)
            union(root_left, root_right)
            winner = find(root_left)
            merged[winner] = combined
            canon[winner] = kept

    grouped = groups()
    merged, canon = payloads(grouped)
    evidenced = [
        root
        for root, name in canon.items()
        if name and any(merged[root][key] for key in merged[root])
    ]
    for root, name in list(canon.items()):
        if not name or any(merged[root][key] for key in merged[root]):
            continue
        fits = []
        for other in evidenced:
            other_root = find(other)
            other_name = canon.get(other_root)
            if not other_name or _name_score(name, other_name) < _MATCH:
                continue
            if _charts_conflict(merged[root], merged[other_root]):
                continue
            fits.append(other_root)
        # Two Harish Pandeys both fit a row that has no chart number. Leave it.
        if len(set(fits)) == 1:
            union(root, fits[0])

    grouped = groups()
    merged, canon = payloads(grouped)
    by_name: dict[str, list[int]] = {}
    prepared = []
    for root, members in grouped.items():
        name = canon.get(root)
        if not name:
            continue
        chart = merged[root]
        key = _chart_key(chart)
        prepared.append((members, name, key))
        by_name.setdefault(name, []).append(root)
    shared = {name for name, roots in by_name.items() if len(roots) > 1}

    labels: list[str | None] = [None] * count
    for members, name, key in prepared:
        if name in shared:
            # Same spelling, different charts. The key keeps the ids apart.
            token = patient_id(name + "|" + key) if key else None
        else:
            token = patient_id(name)
        for index in members:
            labels[index] = token
    for root, members in grouped.items():
        if canon.get(root):
            continue
        key = _chart_key(merged[root])
        if not key:
            continue
        token = patient_id("id:" + key)
        for index in members:
            labels[index] = token
    return labels


def _chart_key(chart: dict[str, set[str]]) -> str:
    """Stable tie-break when one spelling belongs to more than one person."""
    for kind in ("aadhaar", "abha", "phone", "email", "uhid"):
        if chart[kind]:
            return kind + ":" + min(chart[kind])
    return ""


def _choose_name(record: dict, items: list[dict]) -> str | None:
    """Pick this record's own name. Relatives and doctors are ignored."""
    from_findings: list[tuple[str, str]] = []
    for item in items:
        if item.get("type") != "name":
            continue
        if item.get("cue") in _RELATIVE_CUES:
            continue
        field = _leaf(str(item.get("field", "")))
        if field in _SKIP_FIELDS:
            continue
        text = str(item.get("text", "")).strip()
        if text:
            from_findings.append((field, text))

    patient_texts = [text for field, text in from_findings if field in _PATIENT_FIELDS]
    if not patient_texts:
        patient_texts = _field_names(record)
    pool = patient_texts or [text for _, text in from_findings]

    norms = list(dict.fromkeys(normalize_name(text) for text in pool))
    norms = [name for name in norms if name]
    if not norms:
        return None
    if len(norms) == 1:
        return norms[0]
    # Two different people named on one record: do not pick one.
    for left_i, left in enumerate(norms):
        for right in norms[left_i + 1 :]:
            if _name_score(left, right) < _MATCH:
                return None
    return norms[0]


def _field_names(record: dict) -> list[str]:
    found = []
    for key, value in record.items():
        if _leaf(str(key)) in _PATIENT_FIELDS and isinstance(value, str) and value.strip():
            found.append(value.strip())
    return found


def _name_score(left: str, right: str) -> float:
    """rapidfuzz score for two names. Word order does not matter.

    Each word is scored with fuzz.ratio against the best word on the other
    side. A one-letter word is an initial: "k" matches "kumar". The lowest
    word score is the name score, so a shared surname cannot hide "Suresh"
    versus "Ramesh".
    """
    left_words = left.split()
    right_words = right.split()
    if not left_words or not right_words:
        return 0.0
    pairs = [
        (_token_score(word, other), left_i, right_i)
        for left_i, word in enumerate(left_words)
        for right_i, other in enumerate(right_words)
    ]
    pairs.sort(reverse=True)
    used_left: set[int] = set()
    used_right: set[int] = set()
    taken: list[float] = []
    for score, left_i, right_i in pairs:
        if left_i in used_left or right_i in used_right or score <= 0:
            continue
        used_left.add(left_i)
        used_right.add(right_i)
        taken.append(score)
    if not taken:
        return 0.0
    score = min(taken)
    leftover = (len(left_words) - len(used_left)) + (len(right_words) - len(used_right))
    # A spare word (Sunita versus Sunita Devi) is not a sure link.
    if leftover:
        return min(score, _MATCH - 1)
    return score


def _token_score(left: str, right: str) -> float:
    """Score one word. A single letter matches a word that starts with it."""
    if len(left) == 1 or len(right) == 1:
        short, full = (left, right) if len(left) <= len(right) else (right, left)
        if len(short) == 1 and full.startswith(short):
            return 100.0
        return 0.0
    return float(fuzz.ratio(left, right))


def _leaf(field: str) -> str:
    leaf = field.split(".")[-1]
    leaf = re.sub(r"\[\d+\]", "", leaf)
    return re.sub(r"[^a-z0-9]", "", leaf.lower())
