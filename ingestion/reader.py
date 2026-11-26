"""Read local hospital files. Broken files are quarantined, not raised.

Nothing is downloaded. The SHA-256 hash is of the raw file bytes, taken
before any text decoding, so the digest does not depend on the encoding.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

# Tried in this order. latin-1 can decode every byte, so it is the fallback
# when the file is not valid UTF-8 (including a UTF-8 BOM, via utf-8-sig).
_ENCODINGS = ("utf-8-sig", "latin-1")
_SUPPORTED = {".json", ".jsonl", ".csv"}


def read_file(path: Path) -> dict:
    """Read one JSON, JSONL, or CSV file.

    Returns a dictionary:
      records      list of record dictionaries (empty when quarantined)
      shape        how the file held those records: object, list, records,
                   jsonl, or csv. Empty when quarantined
      sha256       hex digest of the raw file, or None if it could not be read
      encoding     "utf-8" or "latin-1", or None when decoding did not happen
      quarantined  True when the file is missing, unreadable, or not valid
      reason       short explanation when quarantined, otherwise ""
      path         the path that was requested

    Parser errors are not copied into ``reason``. Those messages can quote
    the file, and a hospital file may contain patient data.
    """
    source = Path(path)
    result = {
        "path": str(source),
        "sha256": None,
        "encoding": None,
        "shape": "",
        "records": [],
        "quarantined": False,
        "reason": "",
    }

    try:
        raw = source.read_bytes()
    except FileNotFoundError:
        return _quarantine(result, "file not found")
    except OSError:
        return _quarantine(result, "could not read file")

    result["sha256"] = hashlib.sha256(raw).hexdigest()

    suffix = source.suffix.lower()
    if suffix not in _SUPPORTED:
        label = suffix or "(none)"
        return _quarantine(result, f"unsupported format '{label}'")

    try:
        text, encoding = _decode(raw)
    except UnicodeError:
        return _quarantine(result, "could not decode file")

    result["encoding"] = encoding

    try:
        if suffix == ".json":
            result["records"], result["shape"] = _parse_json(text)
        elif suffix == ".jsonl":
            result["records"] = _parse_jsonl(text)
            result["shape"] = "jsonl"
        else:
            result["records"] = _parse_csv(text)
            result["shape"] = "csv"
    except RecursionError:
        return _quarantine(result, "JSON nesting is too deep")
    except (ValueError, csv.Error):
        return _quarantine(result, f"invalid {suffix[1:]} file")

    return result


def _decode(raw: bytes) -> tuple[str, str]:
    """Decode raw bytes as UTF-8, then latin-1."""
    last_error: UnicodeError | None = None
    for codec in _ENCODINGS:
        try:
            text = raw.decode(codec)
        except UnicodeError as exc:
            last_error = exc
            continue
        # utf-8-sig is how we accept a BOM. Call it utf-8 in the result.
        name = "utf-8" if codec == "utf-8-sig" else codec
        return text, name
    if last_error is not None:
        raise last_error
    raise UnicodeError("could not decode file")


def _parse_json(text: str) -> tuple[list[dict], str]:
    """Accept one object, a list of objects, or {\"records\": [...]}."""
    if not text.strip():
        raise ValueError("JSON file is empty")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("JSON is not valid") from exc
    if isinstance(data, list):
        return _as_records(data), "list"
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        return _as_records(data["records"]), "records"
    if isinstance(data, dict):
        return [data], "object"
    raise ValueError("JSON must be an object or a list of objects")


def _parse_jsonl(text: str) -> list[dict]:
    """One JSON object per line. Blank lines are skipped."""
    records: list[dict] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSONL line {line_number} is not valid JSON") from exc
        if not isinstance(item, dict):
            raise ValueError(f"JSONL line {line_number} is not an object")
        records.append(item)
    return records


def _parse_csv(text: str) -> list[dict]:
    """Read a header row, then one dictionary per data row."""
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return []
    records: list[dict] = []
    for row_number, row in enumerate(reader, start=2):
        # Extra cells are stored under None. That sheet does not match its header.
        if None in row:
            raise ValueError(f"CSV row {row_number} has more columns than the header")
        records.append({key: value for key, value in row.items() if key is not None})
    return records


def _as_records(rows: list) -> list[dict]:
    records: list[dict] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"record {index} is not an object")
        records.append(row)
    return records


def _quarantine(result: dict, reason: str) -> dict:
    """Drop any partial records and mark the file so the pipeline can stop."""
    result["records"] = []
    result["quarantined"] = True
    result["reason"] = reason
    return result
