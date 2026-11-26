"""Generalize quasi-identifiers. Clinical facts stay as written.

Every date for one patient moves by the same number of days, so the length
of a hospital stay does not change. The shift comes from RAKSHA_SECRET, so
the same patient always moves by the same amount. Exact ages become 10-year
bands (47 becomes 40-49). Medicines, doses, vitals, and diagnoses are not
edited.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from datetime import datetime, timedelta

_ENV = "RAKSHA_SECRET"
# Shift is in this many days either side of the real date, never zero.
_SPAN = 365

# Field names that must be copied unchanged. Matched after punctuation is removed.
_CLINICAL = (
    "medicine",
    "medication",
    "drug",
    "dose",
    "dosage",
    "prescription",
    "vital",
    "diagnosis",
    "diagnos",
    "bp",
    "pulse",
    "spo2",
    "temperature",
    "heartrate",
)

_AGE_FIELDS = {"age", "patientage", "ageyears", "yearsold", "ageinyears"}

# 2024-03-15 or 2024/03/15, including a time glued on with T.
_YMD = re.compile(r"(?<!\d)(\d{4})[-/](\d{1,2})[-/](\d{1,2})(?!\d)")
# Indian day-month-year: 15/03/2024, 15-03-2024, 15.03.2024.
_DMY = re.compile(r"(?<!\d)(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})(?!\d)")
# "age 47" or "47 years old". A bare "5 years" can be a disease duration, so it stays.
_AGE_PHRASE = re.compile(
    r"(?i)\b(?:age|aged)\s*:?\s*(\d{1,3})\b|\b(\d{1,3})\s*(?:years?\s*old|y/o|yrs?\s*old)\b"
)
_AGE_NUMBER = re.compile(r"\b(\d{1,3})\b")
_ALREADY_BAND = re.compile(r"\d{1,3}-\d{1,3}")

# Stop before Python's recursion limit. Deeper values are copied unchanged.
_MAX_DEPTH = 128


def generalize(records: list[dict]) -> list[dict]:
    """Return copies with shifted dates and banded ages."""
    secret = os.environ.get(_ENV, "").strip()
    if not secret:
        raise ValueError("RAKSHA_SECRET is not set")

    shifts: dict[str, int] = {}
    output: list[dict] = []
    for record in records:
        if not isinstance(record, dict):
            output.append(record)
            continue
        try:
            key = _shift_key(record)
            if key not in shifts:
                shifts[key] = _shift_days(secret, key)
            output.append(_apply(record, shifts[key]))
        except RecursionError:
            output.append(record)
    return output


def _shift_key(record: dict) -> str:
    """Same patient id means the same shift. An unlinked row uses its own dates."""
    patient = record.get("patient")
    if isinstance(patient, str) and patient.strip():
        return patient.strip()
    return "unlinked:" + "|".join(_date_texts(record))


def _shift_days(secret: str, key: str) -> int:
    """Map the secret and the patient key onto one non-zero day offset."""
    digest = hmac.new(
        secret.encode("utf-8"),
        f"date-shift:{key}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    shift = (int(digest[:8], 16) % (_SPAN * 2 + 1)) - _SPAN
    if shift == 0:
        shift = 1
    return shift


def _apply(record: dict, days: int) -> dict:
    return {key: _apply_value(value, str(key), days) for key, value in record.items()}


def _apply_value(value: object, field: str, days: int, depth: int = 0) -> object:
    if depth > _MAX_DEPTH:
        return value
    leaf = _leaf(field)
    # Medicines, doses, vitals, and diagnoses are clinical. Leave them alone.
    if leaf and _is_clinical(leaf):
        return value
    if isinstance(value, dict):
        return {
            key: _apply_value(item, str(key), days, depth + 1) for key, item in value.items()
        }
    if isinstance(value, list):
        return [_apply_value(item, field, days, depth + 1) for item in value]
    if leaf in _AGE_FIELDS:
        return _band_age_value(value)
    if isinstance(value, str):
        return _band_age_phrases(_shift_dates(value, days))
    return value


def _band_age_value(value: object) -> object:
    """Turn an age field into a 10-year band. 47 becomes 40-49."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return _band(value) if 0 <= value <= 130 else value
    if isinstance(value, float) and value.is_integer():
        age = int(value)
        return _band(age) if 0 <= age <= 130 else value
    if isinstance(value, str):
        if _ALREADY_BAND.search(value):
            return value
        return _AGE_NUMBER.sub(_replace_age_number, value)
    return value


def _band_age_phrases(text: str) -> str:
    def replace(match: re.Match) -> str:
        raw = match.group(1) or match.group(2)
        age = int(raw)
        if not 0 <= age <= 130:
            return match.group(0)
        return match.group(0).replace(raw, _band(age), 1)

    return _AGE_PHRASE.sub(replace, text)


def _replace_age_number(match: re.Match) -> str:
    age = int(match.group(1))
    if 0 <= age <= 130:
        return _band(age)
    return match.group(0)


def _band(age: int) -> str:
    start = (age // 10) * 10
    return f"{start}-{start + 9}"


def _shift_dates(text: str, days: int) -> str:
    """Move every real calendar date. Doses such as 1-0-1 are not dates."""
    spans: list[tuple[int, int, str]] = []
    for match in _YMD.finditer(text):
        spans.append((match.start(), match.end(), _render(match, "ymd", days)))
    for match in _DMY.finditer(text):
        # Skip a match that sits inside a year-month-day hit.
        if any(start <= match.start() and match.end() <= end for start, end, _ in spans):
            continue
        spans.append((match.start(), match.end(), _render(match, "dmy", days)))
    if not spans:
        return text
    spans.sort()
    pieces: list[str] = []
    cursor = 0
    for start, end, replacement in spans:
        if start < cursor:
            continue
        pieces.append(text[cursor:start])
        pieces.append(replacement)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _render(match: re.Match, kind: str, days: int) -> str:
    """Shift one date and keep its separator. An impossible date is left as-is."""
    raw = match.group(0)
    try:
        if kind == "ymd":
            year, month, day = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
            shifted = datetime(year, month, day) + timedelta(days=days)
            sep = "/" if "/" in raw else "-"
            return f"{shifted.year:04d}{sep}{shifted.month:02d}{sep}{shifted.day:02d}"
        first, second, year = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        # Indian records are day/month/year. If only one side can be a month, use that.
        if first > 12 and second <= 12:
            day, month = first, second
        elif second > 12 and first <= 12:
            month, day = first, second
        else:
            day, month = first, second
        shifted = datetime(year, month, day) + timedelta(days=days)
    except ValueError:
        return raw
    if "/" in raw:
        sep = "/"
    elif "." in raw:
        sep = "."
    else:
        sep = "-"
    return f"{shifted.day:02d}{sep}{shifted.month:02d}{sep}{shifted.year:04d}"


def _date_texts(record: dict) -> list[str]:
    found: list[str] = []

    def walk(value: object, field: str, depth: int = 0) -> None:
        if depth > _MAX_DEPTH:
            return
        leaf = _leaf(field) if field else ""
        if leaf and _is_clinical(leaf):
            return
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, str(key), depth + 1)
            return
        if isinstance(value, list):
            for item in value:
                walk(item, field, depth + 1)
            return
        if isinstance(value, str):
            found.extend(match.group(0) for match in _YMD.finditer(value))
            found.extend(match.group(0) for match in _DMY.finditer(value))

    walk(record, "")
    return found


def _is_clinical(leaf: str) -> bool:
    return any(part in leaf for part in _CLINICAL)


def _leaf(field: str) -> str:
    leaf = field.split(".")[-1]
    leaf = re.sub(r"\[\d+\]", "", leaf)
    return re.sub(r"[^a-z0-9]", "", leaf.lower())
