"""Find personal information in hospital records.

Regex only. No language model and no network calls.

Names after "Dr." are kept (they are not returned). Names after C/O, S/o,
D/o, and W/o are returned so a later stage can remove them. Medicine names
and doses, such as "Dolo 650", "Ramipril 5 mg", and "1-0-1", are never
returned.

Hindi names in Devanagari are romanized with indic-transliteration when that
library is installed. Detection still works without it.
"""

from __future__ import annotations

import re

try:
    from indic_transliteration import sanscript
    from indic_transliteration.sanscript import transliterate as _transliterate
except ImportError:  # optional local library
    sanscript = None
    _transliterate = None

# One Devanagari syllable is a letter plus its vowel signs. A word is several
# syllables. Digits (०-९) are left out so doses are not treated as names.
_HI_SYLLABLE = r"[\u0904-\u0939\u0958-\u095F][\u0900-\u0903\u093A-\u094D\u0951-\u0954\u0962-\u0963]*"
_HI_WORD = rf"(?:{_HI_SYLLABLE})+"
_HI_SEQ = rf"{_HI_WORD}(?:\s+{_HI_WORD}){{0,2}}"

# A full word is at least two letters, so the "S" in "S/o" is not a name.
# Initials keep their dots: "A." and "A.K."
_EN_WORD = r"(?:[A-Z](?:\.[A-Z])+\.?|[A-Z]\.|[A-Z][A-Za-z'\-]{1,})"
_EN_SEQ = rf"{_EN_WORD}(?:\s+{_EN_WORD}){{1,2}}"  # two or three words
_LOOSE_WORD = r"(?:[A-Za-z](?:\.[A-Za-z])+\.?|[A-Za-z]\.|[A-Za-z][A-Za-z'\-]{1,})"
_LOOSE_SEQ = rf"{_LOOSE_WORD}(?:\s+{_LOOSE_WORD}){{0,2}}"

_GAP = r"(?:\.\s*|\s+)"  # "Dr.Mehta", "Dr Mehta", but not "Dream"

def _fold(word: str) -> str:
    """Build a case-insensitive regex for one ASCII word."""
    return "".join(
        f"[{char.lower()}{char.upper()}]" if char.isalpha() else re.escape(char)
        for char in word
    )


def _any(words: list[str]) -> str:
    # Longer titles first so "Miss" wins over "Ms" and "Patient" over "Pt".
    ordered = sorted(words, key=len, reverse=True)
    return "(?:" + "|".join(_fold(word) for word in ordered) + ")"


_TITLES = _any(
    ["Mr", "Mrs", "Ms", "Miss", "Shri", "Shree", "Smt", "Sri", "Kumari", "Master", "Pt", "Patient"]
)
_DOCTOR = _any(["Dr", "Doctor"])
_RELATIVE = r"(?:[Cc]|[Ss]|[Dd]|[Ww])\s*/\s*[Oo]"

# Doctor names are protected spans: the detector sees them and then skips them.
_DOCTOR_EN = re.compile(rf"(?<!\w){_DOCTOR}{_GAP}(?:{_EN_SEQ}|{_EN_WORD})")
_DOCTOR_HI = re.compile(rf"(?:डॉ|डॉक्टर)\.?\s*{_HI_SEQ}")

# Medicines and doses. These spans are never reported as personal information.
_MEDICINE = re.compile(
    r"(?i)"
    r"(?:(?:\b(?:tab|tablet|cap|capsule|inj|injection|syp|syrup)\.?\s+)?"
    r"\b[A-Za-z]{3,}\s+\d{3,4}\b)"  # Dolo 650
    r"|"
    r"(?:\b[A-Za-z]{3,}\s+\d+(?:\.\d+)?\s*(?:mg|mcg|gm|g|ml|iu|%)\b)"  # Ramipril 5 mg
    r"|"
    r"(?:\b\d+\s*-\s*\d+\s*-\s*\d+\b)"  # 1-0-1
    r"|"
    r"(?:\b\d+(?:\.\d+)?\s*(?:mg|mcg|gm|g|ml|iu)\b)"
)

_EMAIL = re.compile(r"(?<![\w.])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?!\w)")
# Optional +91 or a leading 0, then a 10-digit mobile. Spaces and hyphens may
# sit between the digits: 98765 43210, +91-9876543210.
_MOBILE = re.compile(r"(?<!\d)(?:\+?\s*91[\s\-]?|0)?[6-9](?:[\s\-]?\d){9}(?!\d)")
# STD landline with a separator, for example 011-23456789.
_LANDLINE = re.compile(r"(?<!\d)0\d{2,4}[\s\-]\d{6,8}(?!\d)")
_AADHAAR = re.compile(r"(?<!\d)(?:\d{4}[\s\-]\d{4}[\s\-]\d{4}|\d{12})(?!\d)")
_ABHA_GROUP = re.compile(r"(?<!\d)\d{2}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}(?!\d)")
_ABHA_PLAIN = re.compile(r"(?<!\d)\d{14}(?!\d)")
_ABHA_LABEL = re.compile(
    r"(?<!\w)" + _fold("ABHA") + r"[\s:.#\-]*(?:\d[\s\-]?){13}\d"
)
_UHID = re.compile(
    r"(?<!\w)" + _fold("UHID") + r"[\s:.#\-/]{0,5}([A-Za-z0-9][A-Za-z0-9/\-]{3,23})"
)
_MRN = re.compile(
    r"(?<!\w)" + _fold("MRN") + r"[\s:.#\-/]{0,5}([A-Za-z0-9][A-Za-z0-9/\-]{3,23})"
)
_RELATIVE_NAME = re.compile(
    rf"(?<!\w)({_RELATIVE})\s+({_LOOSE_SEQ}|{_HI_SEQ})"
)
_TITLE_NAME = re.compile(rf"(?<!\w)({_TITLES}){_GAP}({_EN_SEQ}|{_EN_WORD}|{_HI_SEQ})")
_EN_NAME = re.compile(rf"\b({_EN_SEQ})\b")
_HI_RUN = re.compile(rf"{_HI_WORD}(?:\s+{_HI_WORD})*")
_HI_WORD_RE = re.compile(_HI_WORD)

# Clinical words that look like capitalized names but are not people.
_NOT_NAMES = {
    "tab", "tablet", "cap", "capsule", "inj", "injection", "syp", "syrup",
    "oral", "dose", "dosage", "mg", "mcg", "ml", "gm", "od", "bd", "tds",
    "hs", "sos", "rx", "sig", "prn", "stat", "blood", "sugar", "pressure",
    "general", "medicine", "department", "hospital", "ward", "opd", "ipd",
    "male", "female", "year", "years", "old", "test", "report", "normal",
    "daily", "morning", "evening", "night", "after", "before", "food",
    "fever", "pain", "cough", "cold", "acute", "chronic", "left", "right",
    "mild", "moderate", "severe", "date", "time", "room", "bed", "unit",
    "care", "health", "medical", "emergency", "review", "advice", "continue",
    "start", "stop", "take", "days", "day", "week", "weeks", "month", "months",
    "hour", "hours", "history", "diagnosis", "admission", "discharge",
    "patient", "follow", "outpatient", "inpatient", "negative", "positive",
    "diabetes", "hypertension", "white", "cell", "count", "heart", "rate",
    "new", "delhi", "mumbai", "india", "type", "known", "case", "since",
    "complaint", "chief", "present", "illness", "examination", "investigation",
    "treatment", "given", "advised", "doctor", "dr", "with", "from", "and",
    "the", "for", "was", "has", "his", "her", "age", "sex",
    "is", "are", "of", "on", "in", "to", "at", "by", "as", "be", "or",
    "pt", "yrs", "yo",
}

# Short Hindi words that join a sentence. They are not names.
_HI_STOP = {
    "का", "की", "के", "को", "में", "से", "पर", "और", "या", "एक", "यह", "वह",
    "ये", "वे", "ने", "है", "हैं", "था", "थी", "थे", "हो", "नहीं", "नाम",
    "रोगी", "मरीज", "उम्र", "वर्ष", "साल", "दवा", "गोली", "तक", "लिए",
    "गया", "गई", "किया", "दिया", "रहा", "रही", "रहे", "तथा", "लेकिन", "अगर",
    "जब", "तब", "भी", "ही", "तो", "डॉ", "डॉक्टर", "का",
}

_BLANK = {"na", "n/a", "nil", "null", "none", "-", "--"}

# Leaf names are compared with spaces and underscores removed.
_ID_KEYS = {
    "aadhaar": "aadhaar",
    "aadhar": "aadhaar",
    "aadhaarno": "aadhaar",
    "aadharno": "aadhaar",
    "aadhaarnumber": "aadhaar",
    "email": "email",
    "emailid": "email",
    "mobile": "phone",
    "mobileno": "phone",
    "mobilenumber": "phone",
    "phone": "phone",
    "phoneno": "phone",
    "phonenumber": "phone",
    "contact": "phone",
    "contactno": "phone",
    "uhid": "uhid",
    "uhidno": "uhid",
    "mrn": "mrn",
    "mrnno": "mrn",
    "abha": "abha",
    "abhano": "abha",
    "abhanumber": "abha",
    "abhaid": "abha",
}
_NAME_KEYS = {
    "patientname", "guardianname", "fathername", "mothername", "spousename",
    "husbandname", "wifename", "relativename", "attendantname", "fullname",
    "name", "patient",
}
# doctor_name is kept, the same way a name after "Dr." is kept.
_DOCTOR_KEYS = {
    "doctorname", "doctor", "consultant", "physician", "surgeon",
    "consultingdoctor", "treatingdoctor",
}
# A column that holds only a drug or a dose is not scanned for names.
_MEDICINE_KEYS = {
    "medicine", "medicines", "medication", "medications", "drug", "drugs",
    "dose", "dosage", "prescription", "rx",
}

_PRIORITY = {
    "email": 0,
    "abha": 1,
    "uhid": 2,
    "mrn": 2,
    "aadhaar": 3,
    "phone": 4,
    "name": 5,
}


def find_personal_info(records: list[dict] | str) -> list[dict]:
    """Return personal information found in records or in one text string.

    Each item is a dictionary with type, text, record, and field. Hindi names
    also include latin when indic-transliteration is available. A relative
    name includes cue, such as "S/o".
    """
    if isinstance(records, str):
        found = _scan(records, 0, "")
    else:
        found = []
        for index, record in enumerate(records):
            if isinstance(record, str):
                found.extend(_scan(record, index, ""))
                continue
            if not isinstance(record, dict):
                continue
            for field, text in _walk(record):
                found.extend(_scan(text, index, field))
    found.sort(key=lambda item: (item["record"], item["field"], item["start"]))
    return [_public(item) for item in found]


def _walk(value: object, prefix: str = ""):
    """Yield (field path, text) for every leaf in a record."""
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk(item, path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            path = f"{prefix}[{index}]" if prefix else f"[{index}]"
            yield from _walk(item, path)
        return
    text = _as_text(value)
    if text and text.strip():
        yield prefix, text


def _as_text(value: object) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return None


def _scan(text: str, record: int, field: str) -> list[dict]:
    leaf = _leaf(field)
    protected = _protected_spans(text)
    # Doctor columns and pure drug columns are not name sources.
    skip_names = leaf in _DOCTOR_KEYS or leaf in _MEDICINE_KEYS
    found: list[dict] = []

    if leaf in _ID_KEYS:
        value = text.strip()
        kind = _ID_KEYS[leaf]
        if _id_value_ok(kind, value):
            start = text.find(value)
            found.append(_item(kind, value, start, start + len(value), record, field))

    if not skip_names and leaf in _NAME_KEYS:
        plain = _plain_name(text, protected)
        if plain is not None:
            name, start, end = plain
            found.append(_item("name", name, start, end, record, field))

    if not skip_names:
        found.extend(_prefixed_names(text, record, field))
        found.extend(_english_names(text, record, field))
        found.extend(_hindi_names(text, record, field))

    found.extend(_contact_ids(text, record, field))
    found = [item for item in found if _keep_name(item, protected)]
    return _resolve(found)


def _protected_spans(text: str) -> list[tuple[int, int]]:
    """Spans we must not treat as removable personal information."""
    spans = []
    for pattern in (_DOCTOR_EN, _DOCTOR_HI, _MEDICINE):
        for match in pattern.finditer(text):
            spans.append((match.start(), match.end()))
    return spans


def _keep_name(item: dict, protected: list[tuple[int, int]]) -> bool:
    if item["type"] != "name":
        return True
    span = (item["start"], item["end"])
    return not _overlaps_any(span, protected)


def _prefixed_names(text: str, record: int, field: str) -> list[dict]:
    found = []
    for match in _RELATIVE_NAME.finditer(text):
        item = _name_from_match(match, record, field, allow_single=True)
        if item is not None:
            found.append(item)
    for match in _TITLE_NAME.finditer(text):
        item = _name_from_match(match, record, field, allow_single=True)
        if item is not None:
            found.append(item)
    return found


def _name_from_match(match: re.Match, record: int, field: str, allow_single: bool) -> dict | None:
    cue = re.sub(r"\s+", "", match.group(1)).upper().rstrip(".")
    # C/O is stored with the slash the records use. Titles stay as MR, SMT, ...
    if "/" in cue:
        cue = cue[0] + "/O"
    body = match.group(2)
    kept = _clean_tokens(body.split(), allow_single=allow_single)
    if kept is None:
        return None
    located = _locate(match.group(0), match.start(), kept)
    if located is None:
        return None
    name, start, end = located
    return _item("name", name, start, end, record, field, cue=cue)


def _english_names(text: str, record: int, field: str) -> list[dict]:
    found = []
    for match in _EN_NAME.finditer(text):
        kept = _clean_tokens(match.group(1).split(), allow_single=False)
        if kept is None:
            continue
        located = _locate(match.group(0), match.start(), kept)
        if located is None:
            continue
        name, start, end = located
        found.append(_item("name", name, start, end, record, field))
    return found


def _hindi_names(text: str, record: int, field: str) -> list[dict]:
    """Split a Hindi sentence on grammar words and keep the name pieces."""
    found = []
    for run in _HI_RUN.finditer(text):
        group: list[re.Match] = []

        def flush() -> None:
            if not group:
                return
            start = run.start() + group[0].start()
            end = run.start() + group[-1].end()
            name = text[start:end]
            tokens = name.split()
            # A single Hindi word in a sentence is too easy to get wrong.
            # One-word names still match after C/O, S/o, D/o, W/o and in name fields.
            if _plausible(tokens, allow_single=False):
                found.append(_item("name", name, start, end, record, field))
            group.clear()

        for word in _HI_WORD_RE.finditer(run.group(0)):
            if word.group(0) in _HI_STOP:
                flush()
                continue
            group.append(word)
        flush()
    return found


def _contact_ids(text: str, record: int, field: str) -> list[dict]:
    found = []
    for match in _EMAIL.finditer(text):
        found.append(_item("email", match.group(0), match.start(), match.end(), record, field))
    for match in _ABHA_LABEL.finditer(text):
        if _digit_count(match.group(0)) == 14:
            found.append(_item("abha", match.group(0), match.start(), match.end(), record, field))
    for pattern in (_ABHA_GROUP, _ABHA_PLAIN):
        for match in pattern.finditer(text):
            digits = _digits(match.group(0))
            if len(digits) == 14 and len(set(digits)) > 1:
                found.append(_item("abha", match.group(0), match.start(), match.end(), record, field))
    for match in _UHID.finditer(text):
        if _id_token_ok(match.group(1)):
            found.append(_item("uhid", match.group(0), match.start(), match.end(), record, field))
    for match in _MRN.finditer(text):
        if _id_token_ok(match.group(1)):
            found.append(_item("mrn", match.group(0), match.start(), match.end(), record, field))
    for match in _AADHAAR.finditer(text):
        digits = _digits(match.group(0))
        if len(digits) != 12 or len(set(digits)) == 1:
            continue
        # 91 plus a mobile is a phone that happens to be 12 characters.
        if digits.startswith("91") and digits[2] in "6789":
            found.append(_item("phone", match.group(0), match.start(), match.end(), record, field))
            continue
        found.append(_item("aadhaar", match.group(0), match.start(), match.end(), record, field))
    for match in _MOBILE.finditer(text):
        digits = _digits(match.group(0))
        if len(digits) in {10, 11, 12} and len(set(digits)) > 1:
            found.append(_item("phone", match.group(0), match.start(), match.end(), record, field))
    for match in _LANDLINE.finditer(text):
        digits = _digits(match.group(0))
        if 10 <= len(digits) <= 12 and len(set(digits)) > 1:
            found.append(_item("phone", match.group(0), match.start(), match.end(), record, field))
    return found


def _plain_name(text: str, protected: list[tuple[int, int]]) -> tuple[str, int, int] | None:
    """Use a whole name-field value when it is only a person's name."""
    stripped = text.strip()
    if not stripped or stripped.lower() in _BLANK:
        return None
    if not re.fullmatch(rf"{_LOOSE_SEQ}|{_HI_SEQ}", stripped):
        return None
    start = text.find(stripped)
    end = start + len(stripped)
    if _overlaps_any((start, end), protected):
        return None
    kept = _clean_tokens(stripped.split(), allow_single=True)
    if kept is None:
        return None
    return _locate(text, 0, kept)


def _clean_tokens(tokens: list[str], allow_single: bool) -> list[str] | None:
    # A token list that still contains "Dr" is a doctor name. Keep it.
    if any(_letters(token).lower() in {"dr", "doctor"} for token in tokens):
        return None
    cleaned = list(tokens)
    while cleaned and _drop_token(cleaned[0]):
        cleaned.pop(0)
    while cleaned and _drop_token(cleaned[-1]):
        cleaned.pop()
    if not _plausible(cleaned, allow_single=allow_single):
        return None
    return cleaned


def _plausible(tokens: list[str], allow_single: bool) -> bool:
    if not tokens:
        return False
    if not allow_single and len(tokens) < 2:
        return False
    if len(tokens) == 1 and len(_letters(tokens[0])) < 2:
        return False
    if not any(len(_letters(token)) >= 2 for token in tokens):
        return False
    return True


def _drop_token(token: str) -> bool:
    if token in _HI_STOP:
        return True
    word = token.strip(".").lower()
    return word in _NOT_NAMES


def _locate(source: str, offset: int, tokens: list[str]) -> tuple[str, int, int] | None:
    """Map kept tokens back to a span in the original text."""
    first = source.find(tokens[0])
    last = source.rfind(tokens[-1])
    if first < 0 or last < 0:
        return None
    start = offset + first
    end = offset + last + len(tokens[-1])
    return source[first:last + len(tokens[-1])], start, end


def _item(
    kind: str,
    text: str,
    start: int,
    end: int,
    record: int,
    field: str,
    cue: str = "",
) -> dict:
    item = {
        "type": kind,
        "text": text,
        "record": record,
        "field": field,
        "start": start,
        "end": end,
        "cue": cue,
    }
    if kind == "name" and _has_devanagari(text):
        latin = _to_latin(text)
        if latin:
            item["latin"] = latin
    return item


def _to_latin(hindi: str) -> str:
    """Romanize a Hindi name. Empty when the library is not installed."""
    if _transliterate is None or sanscript is None:
        return ""
    scheme = getattr(sanscript, "IAST", None)
    if scheme is None:
        return ""
    try:
        return _transliterate(hindi, sanscript.DEVANAGARI, scheme).strip()
    except Exception:
        return ""


def _resolve(candidates: list[dict]) -> list[dict]:
    """Drop overlapping hits. A longer, more specific hit wins."""
    ordered = sorted(
        candidates,
        key=lambda item: (
            item["start"],
            -(item["end"] - item["start"]),
            _PRIORITY.get(item["type"], 9),
            0 if item.get("cue") else 1,
        ),
    )
    kept: list[dict] = []
    for item in ordered:
        span = (item["start"], item["end"])
        if any(_overlaps(span, (old["start"], old["end"])) for old in kept):
            continue
        kept.append(item)
    return kept


def _public(item: dict) -> dict:
    result = {
        "type": item["type"],
        "text": item["text"],
        "record": item["record"],
        "field": item["field"],
    }
    if item.get("cue"):
        result["cue"] = item["cue"]
    if item.get("latin"):
        result["latin"] = item["latin"]
    return result


def _leaf(field: str) -> str:
    leaf = field.split(".")[-1]
    leaf = re.sub(r"\[\d+\]", "", leaf)
    return re.sub(r"[^a-z0-9]", "", leaf.lower())


def _id_value_ok(kind: str, value: str) -> bool:
    if not value or value.lower() in _BLANK:
        return False
    digits = _digits(value)
    if kind == "email":
        return "@" in value
    if kind == "phone":
        return len(digits) >= 10
    if kind == "aadhaar":
        return len(digits) == 12 and len(set(digits)) > 1
    if kind == "abha":
        return len(digits) == 14 and len(set(digits)) > 1
    if kind in {"uhid", "mrn"}:
        return _id_token_ok(value)
    return False


def _id_token_ok(value: str) -> bool:
    return len(value) >= 4 and any(char.isdigit() for char in value)


def _digits(text: str) -> str:
    return re.sub(r"\D", "", text)


def _digit_count(text: str) -> int:
    return sum(char.isdigit() for char in text)


def _letters(token: str) -> str:
    return re.sub(r"[^A-Za-z\u0900-\u097F]", "", token)


def _has_devanagari(text: str) -> bool:
    return bool(re.search(r"[\u0900-\u097F]", text))


def _overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _overlaps_any(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    return any(_overlaps(span, other) for other in spans)
