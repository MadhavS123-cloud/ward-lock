"""Remove names, phones, emails, and ids. Medical values stay as written.

A protect-list cancels removal of a disease or a medicine. Parkinson's,
bukhar, Dolo, Ramipril, sugar, and bp are left as they were written, including
when they sit inside a longer tagged span.
"""

from __future__ import annotations

import re

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
    "pan", "panno", "pannumber",
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
    if leaf and leaf in wipe:
        if value is None or (isinstance(value, str) and not value.strip()):
            return value
        return _TOKEN
    if isinstance(value, dict):
        return {
            key: _walk(item, f"{path}.{key}" if path else str(key), by_field, wipe, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _walk(item, f"{path}[{index}]", by_field, wipe, depth + 1)
            for index, item in enumerate(value)
        ]
    if isinstance(value, str) and path in by_field:
        return _cut(value, by_field[path])
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


def _is_clinical(leaf: str) -> bool:
    return any(part in leaf for part in _CLINICAL)


def _leaf(field: str) -> str:
    leaf = field.split(".")[-1]
    leaf = re.sub(r"\[\d+\]", "", leaf)
    return re.sub(r"[^a-z0-9]", "", leaf.lower())
