"""Remove names, phones, emails, and ids. Medical values stay as written.

A protect-list cancels removal of a disease or a medicine. Parkinson's,
bukhar, Dolo, Ramipril, sugar, and bp are left as they were written, including
when they sit inside a longer tagged span.
"""

from __future__ import annotations

import re

from detection.engine import mask_personal_text
from utils.medical import is_medical_span, is_medical_token

# Shown where a personal value was removed. Keys stay, so the file shape stays.
_TOKEN = "[REDACTED]"

# Same cap as detection. Past this depth the value is copied unchanged so a
# deeply nested export cannot raise RecursionError.
_MAX_DEPTH = 128

# A personal token must not be cut out of a longer word such as Ramipril.
_EDGE = r"A-Za-z0-9\u0900-\u097F"

# Whole fields that are identifiers. "patient" is the fake id, so it is not here.
_WIPE = {
    "patientname", "guardianname", "fathername", "mothername", "spousename",
    "husbandname", "wifename", "relativename", "attendantname", "fullname", "name",
    "aadhaar", "aadhar", "aadhaarno", "aadharno", "aadhaarnumber",
    "pan", "panno", "pannumber", "payerpan", "pancard", "panid",
    "pin", "pincode", "zip", "zipcode", "postalcode", "postcode",
    "pmjayid", "policyno", "policynumber", "policyid",
    "insuranceid", "insuranceno", "memberid", "tpaid",
    "firstname", "lastname", "middlename", "surname", "givenname", "familyname",
    "abha", "abhano", "abhanumber", "abhaid",
    "uhid", "uhidno", "mrn", "mrnno",
    "mobile", "mobileno", "mobilenumber",
    "phone", "phoneno", "phonenumber", "contact", "contactno",
    "email", "emailid",
    "address", "doctorname", "dateofbirth", "dob",
}

# Same idea as the privacy stage: these fields are clinical and are copied through.
_CLINICAL = (
    "medicine", "medication", "drug", "dose", "dosage", "prescription",
    "vital", "diagnosis", "diagnos", "bp", "pulse", "spo2", "temperature",
    "heartrate",
)

# A whole column of places. "Village/Mohalla" becomes villagemohalla.
# "city" in a registration row is the village. Hospital wards are a
# different column ("ward") and are not listed here.
_PLACE_LEAVES = {
    "village", "gaon", "gram", "city", "street", "pata", "mohalla",
    "locality", "landmark", "house", "houseno", "housenumber", "hno",
}

# Free-text places. A hospital line such as "Ward: 4 (Medicine)" does not
# start with Address, so it stays. "gram positive" stays because the word
# after gram is not a capitalized place name.
_ADDRESS_LINE = re.compile(r"(?im)^[ \t]*address\b[^\n]*|^[ \t]*पता\b[^\n]*")
_HOUSE = re.compile(
    r"(?i)(?<![A-Za-z])(?:h\.?[ \t]*no\.?|house|makan[ \t]+no\.?)[ \t]*\d{1,6}\b"
    r"|मकान[ \t]+नं\.?[ \t]*[0-9\u0966-\u096F]{1,6}"
)
_VILLAGE_CUE = re.compile(
    r"(?i:\b(?:vill\.?|village|gram)\b)[ \t]*[:.]?[ \t]*"
    r"[A-Z][A-Za-z]+(?:[ \t]+(?:Kalan|Khurd|[A-Z][a-z]+))?"
)
_HI_VILLAGE = re.compile(
    r"(?:ग्राम|गाँव|गांव)[ \t]*[:：]?[ \t]*"
    r"(?:[\u0904-\u0939\u0958-\u095F][\u0900-\u097F]*)"
    r"(?:[ \t]+[\u0904-\u0939\u0958-\u095F][\u0900-\u097F]*){0,2}"
)

# A given name with nothing around it except these cues. "ASHA workers"
# is all capitals, and "Dr. Ramesh" is behind "Dr.", so neither matches.
_ATTENDANT = re.compile(r"(?<![A-Za-z])([A-Z][a-z]{2,})(?=['’]s attendant\b)")
_KA_BP = re.compile(
    r"(?<!Dr\. )(?<!Dr )(?<![A-Za-z])([A-Z][a-z]{2,})(?=\s+ka\s+BP\b)"
)
_MOHD = re.compile(
    r"(?<!Dr\. )(?<!Dr )(?<![A-Za-z])(?:Mohd|Md)\.\s+[A-Z][a-z]{2,}\b"
)
_GIVEN_SKIP = {
    "patient", "sample", "review", "doctor", "address", "house", "ward",
    "tablet", "blood", "sugar", "fever", "pain", "daily", "morning",
    "evening", "night", "discharge", "medicine", "hospital", "village",
    "attendant", "primary", "essential", "general", "continue", "advised",
}


def sanitize(records: list[dict], findings: list[dict], policy: dict) -> list[dict]:
    """Return copies with personal information replaced by [REDACTED].

    ``findings`` is the list from detection. A name, phone, email, or id is
    removed from the field where it was found. Identifier columns from the
    policy are cleared even when detection missed them. Medicines, doses,
    vitals, and diagnoses are not edited.
    """
    wipe = set(_WIPE)
    for name in policy.get("direct_identifiers") or []:
        wipe.add(_leaf(str(name)))
    wipe.discard("patient")

    grouped: dict[int, list[dict]] = {}
    for item in findings:
        grouped.setdefault(int(item.get("record", -1)), []).append(item)

    output: list[dict] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            output.append(record)
            continue
        try:
            output.append(_redact_record(record, grouped.get(index, []), wipe))
        except RecursionError:
            output.append(record)
    return output


def _redact_record(record: dict, findings: list[dict], wipe: set[str]) -> dict:
    by_field: dict[str, list[str]] = {}
    for item in findings:
        text = str(item.get("text") or "").strip()
        if not text:
            continue
        by_field.setdefault(str(item.get("field") or ""), []).append(text)
    cleaned = _walk(record, "", by_field, wipe)
    return cleaned if isinstance(cleaned, dict) else record


def _walk(
    value: object,
    path: str,
    by_field: dict[str, list[str]],
    wipe: set[str],
    depth: int = 0,
) -> object:
    if depth > _MAX_DEPTH:
        return value
    leaf = _leaf(path) if path else ""
    # A clinical field, or a whole clinical object, is kept byte for byte.
    if leaf and _is_clinical(leaf):
        return value
    # An identifier column is removed as a whole, including nested address parts.
    # A village, street, or gaon column is a place even when the value is one word.
    if leaf and (leaf in wipe or _is_place_leaf(leaf)):
        if value is None or (isinstance(value, str) and not value.strip()):
            return value
        return _TOKEN
    if isinstance(value, dict):
        # A key can be the personal data (a patient name, a UHID, a CSV header).
        # The child path stays the original key so a detected value still lines up.
        rebuilt: dict = {}
        used: set[str] = set()
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            cleaned = _walk(item, child, by_field, wipe, depth + 1)
            renamed = _unique_key(mask_personal_text(str(key)), used)
            rebuilt[renamed] = cleaned
        return rebuilt
    if isinstance(value, list):
        return [
            _walk(item, f"{path}[{index}]", by_field, wipe, depth + 1)
            for index, item in enumerate(value)
        ]
    if isinstance(value, str):
        if path in by_field:
            value = _cut(value, by_field[path])
        return _scrub_free_text(value)
    return value


def _cut(text: str, pieces: list[str]) -> str:
    """Replace each detected span. Longer spans go first so a full name wins.

    A span that is only a disease or a medicine is not touched. If a name
    span also contains one of those words, the word is kept and the name goes.
    """
    for piece in sorted(set(pieces), key=len, reverse=True):
        if is_medical_span(piece):
            continue
        pattern = re.compile(
            rf"(?<![{_EDGE}]){re.escape(piece)}(?![{_EDGE}])"
        )
        text = pattern.sub(lambda match: _redact_span(match.group(0)), text)
    return text


def _redact_span(span: str) -> str:
    """Replace a span with [REDACTED], leaving medical words in place."""
    if not _WORD.search(span) or not any(is_medical_token(word) for word in _WORD.findall(span)):
        return _TOKEN
    parts = re.split(r"(\s+)", span)
    out: list[str] = []
    pending = False
    for part in parts:
        if not part:
            continue
        if part.isspace():
            if not pending:
                out.append(part)
            continue
        if is_medical_token(part):
            if pending:
                out.append(_TOKEN)
                out.append(" ")
                pending = False
            elif out and not out[-1].isspace():
                out.append(" ")
            out.append(part)
            continue
        pending = True
    if pending:
        if out and not out[-1].isspace():
            out.append(" ")
        out.append(_TOKEN)
    return "".join(out).strip()


_WORD = re.compile(r"[0-9A-Za-z\u0900-\u097F]+(?:['’][A-Za-z]+)?")


def _unique_key(key: str, used: set[str]) -> str:
    """Keep a renamed header from colliding with another column."""
    if key not in used:
        used.add(key)
        return key
    number = 2
    while f"{key}_{number}" in used:
        number += 1
    fresh = f"{key}_{number}"
    used.add(fresh)
    return fresh


def _is_clinical(leaf: str) -> bool:
    return any(part in leaf for part in _CLINICAL)


def _is_place_leaf(leaf: str) -> bool:
    """True for a column that holds a village, house line, or locality.

    An ABHA address is an id, not a place column. A ward column is the
    hospital ward and is left for the clinical text to keep.
    """
    if not leaf or "abha" in leaf:
        return False
    if leaf in _PLACE_LEAVES or "village" in leaf:
        return True
    return leaf.startswith("address") or leaf.endswith("address")


def _scrub_free_text(text: str) -> str:
    """Remove place lines and bare given names that a column wipe cannot see.

    Clinical fields never reach this function. A line that only shares the
    word "ward" with an address, such as "Ward: 4 (Medicine)", is not an
    address line and is not changed.
    """
    if not text or text == _TOKEN:
        return text
    text = _ADDRESS_LINE.sub(_TOKEN, text)
    text = _HOUSE.sub(_TOKEN, text)
    text = _VILLAGE_CUE.sub(_TOKEN, text)
    text = _HI_VILLAGE.sub(_TOKEN, text)
    text = _ATTENDANT.sub(lambda match: _given(match.group(1)), text)
    text = _KA_BP.sub(lambda match: _given(match.group(1)), text)
    text = _MOHD.sub(_TOKEN, text)
    return text


def _given(token: str) -> str:
    """Blank one given name. A medical word in the same slot stays."""
    if is_medical_token(token) or token.lower() in _GIVEN_SKIP:
        return token
    return _TOKEN


def _leaf(field: str) -> str:
    leaf = field.split(".")[-1]
    leaf = re.sub(r"\[\d+\]", "", leaf)
    return re.sub(r"[^a-z0-9]", "", leaf.lower())
