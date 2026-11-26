"""Group the same patient across records and assign one fake id.

Names are normalized, then compared with rapidfuzz. Word order is ignored.
A score of 80 or more is the same person, so those records share one HMAC id.
"Ramesh K." matches "Ramesh Kumar" because K. is an initial. "Suresh Kumar"
does not, and gets his own id. A score from 70 up to 80 is a weak match:
patient stays null.
"""

from __future__ import annotations

import re
import unicodedata

from rapidfuzz import fuzz

from pseudonym.hmac import patient_id

try:
    from indic_transliteration import sanscript
    from indic_transliteration.sanscript import transliterate as _transliterate
except ImportError:  # Hindi names then keep only their Latin letters
    sanscript = None
    _transliterate = None

# rapidfuzz token scores are 0-100. 80 links a person. 70-80 is too close to guess.
_MATCH = 80
_WEAK = 70

# Honorifics, including the Latin form साहब gets from transliteration (sahaba).
_HONORIFICS = {"ji", "sahab", "sahib", "sahaba", "didi"}

# These are not the patient's own name.
_RELATIVE_CUES = {"C/O", "S/O", "D/O", "W/O"}
_PATIENT_FIELDS = {"patientname", "fullname", "name"}
_SKIP_FIELDS = {
    "guardianname", "fathername", "mothername", "spousename", "husbandname",
    "wifename", "relativename", "attendantname", "doctorname", "doctor",
    "consultant", "physician", "surgeon", "medicine", "drug", "dose", "dosage",
}


def normalize_name(name: str) -> str:
    """Lowercase a name, transliterate Hindi, and drop ji/sahab/didi."""
    text = _to_latin(name.strip()).lower()
    text = re.sub(r"[^a-z\s]", " ", text)
    tokens = [token for token in text.split() if token not in _HONORIFICS]
    return " ".join(tokens)


def assign_patients(records: list[dict], findings: list[dict]) -> list[dict]:
    """Copy records and set patient to a PSN- id, or null when unsure."""
    by_record: dict[int, list[dict]] = {}
    for item in findings:
        by_record.setdefault(int(item.get("record", 0)), []).append(item)

    chosen: list[str | None] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            chosen.append(None)
            continue
        chosen.append(_choose_name(record, by_record.get(index, [])))

    scored = _score_pairs(chosen)
    weak = _weak_rows(chosen, scored)
    groups = _cluster(chosen, weak, scored)

    ids: dict[int, str] = {}
    for members in groups.values():
        # One stable name per person, so file order does not change the id.
        canonical = min(chosen[index] for index in members)
        fake = patient_id(canonical)
        for index in members:
            ids[index] = fake

    linked: list[dict] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            linked.append(record)
            continue
        copy = dict(record)
        copy["patient"] = None if weak[index] else ids.get(index)
        linked.append(copy)
    return linked


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


def _score_pairs(names: list[str | None]) -> dict[tuple[int, int], float]:
    scored: dict[tuple[int, int], float] = {}
    for left_i, left in enumerate(names):
        if not left:
            continue
        for right_i in range(left_i + 1, len(names)):
            right = names[right_i]
            if right:
                scored[(left_i, right_i)] = _name_score(left, right)
    return scored


def _lookup(scored: dict[tuple[int, int], float], left: int, right: int) -> float:
    if left > right:
        left, right = right, left
    return scored.get((left, right), 0.0)


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


def _weak_rows(names: list[str | None], scored: dict[tuple[int, int], float]) -> list[bool]:
    """True when this row must not get an id.

    No name is unset. The closest other name scoring from 70 up to 80 is a
    weak match and is unset. An initial that fits two different people is
    unset too, so "Ramesh K." is not given to both Kumar and Kishore.
    """
    flags = [not name for name in names]
    for index, name in enumerate(names):
        if not name:
            continue
        best = 0.0
        for other in range(len(names)):
            if other == index or not names[other]:
                continue
            best = max(best, _lookup(scored, index, other))
        if _WEAK <= best < _MATCH:
            flags[index] = True
    for index in _ambiguous(names, scored):
        flags[index] = True
    return flags


def _ambiguous(names: list[str | None], scored: dict[tuple[int, int], float]) -> set[int]:
    """Rows whose strong matches are not one person."""
    neighbors: dict[int, set[int]] = {index: set() for index, name in enumerate(names) if name}
    for (left, right), score in scored.items():
        if score >= _MATCH:
            neighbors[left].add(right)
            neighbors[right].add(left)
    bad: set[int] = set()
    for index, group in neighbors.items():
        others = list(group)
        for left_i, left in enumerate(others):
            for right in others[left_i + 1 :]:
                if _lookup(scored, left, right) < _MATCH:
                    bad.add(index)
                    break
    return bad


def _cluster(
    names: list[str | None],
    weak: list[bool],
    scored: dict[tuple[int, int], float],
) -> dict[int, list[int]]:
    """Union rows whose name score is 80 or higher."""
    active = [index for index, name in enumerate(names) if name and not weak[index]]
    parent = {index: index for index in active}

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    for pos, left in enumerate(active):
        for right in active[pos + 1 :]:
            if _lookup(scored, left, right) >= _MATCH:
                union(left, right)

    groups: dict[int, list[int]] = {}
    for index in active:
        groups.setdefault(find(index), []).append(index)
    return groups


def _to_latin(text: str) -> str:
    """Romanize Devanagari and drop accent marks so fuzzy match sees ASCII."""
    if not re.search(r"[\u0900-\u097F]", text):
        return text
    if _transliterate is None or sanscript is None:
        return re.sub(r"[\u0900-\u097F]+", " ", text)
    try:
        latin = _transliterate(text, sanscript.DEVANAGARI, sanscript.IAST)
    except Exception:
        # Keep going with the Latin letters. A transliteration miss is not fatal.
        return re.sub(r"[\u0900-\u097F]+", " ", text)
    plain = unicodedata.normalize("NFD", latin)
    return "".join(char for char in plain if not unicodedata.combining(char))


def _leaf(field: str) -> str:
    leaf = field.split(".")[-1]
    leaf = re.sub(r"\[\d+\]", "", leaf)
    return re.sub(r"[^a-z0-9]", "", leaf.lower())
