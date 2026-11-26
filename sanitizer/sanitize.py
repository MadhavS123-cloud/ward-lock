"""Remove names, phones, emails, and ids. Medical values stay as written."""

from __future__ import annotations

import re

# Shown where a personal value was removed. Keys stay, so the file shape stays.
_TOKEN = "[REDACTED]"

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
        output.append(_redact_record(record, grouped.get(index, []), wipe))
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


def _walk(value: object, path: str, by_field: dict[str, list[str]], wipe: set[str]) -> object:
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
            key: _walk(item, f"{path}.{key}" if path else str(key), by_field, wipe)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _walk(item, f"{path}[{index}]", by_field, wipe)
            for index, item in enumerate(value)
        ]
    if isinstance(value, str) and path in by_field:
        return _cut(value, by_field[path])
    return value


def _cut(text: str, pieces: list[str]) -> str:
    """Replace each detected span. Longer spans go first so a full name wins."""
    for piece in sorted(set(pieces), key=len, reverse=True):
        pattern = re.compile(
            rf"(?<![{_EDGE}]){re.escape(piece)}(?![{_EDGE}])"
        )
        text = pattern.sub(_TOKEN, text)
    return text


def _is_clinical(leaf: str) -> bool:
    return any(part in leaf for part in _CLINICAL)


def _leaf(field: str) -> str:
    leaf = field.split(".")[-1]
    leaf = re.sub(r"\[\d+\]", "", leaf)
    return re.sub(r"[^a-z0-9]", "", leaf.lower())
