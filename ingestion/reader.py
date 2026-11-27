"""Read local hospital files. Broken files are quarantined, not raised.

Nothing is downloaded. The SHA-256 hash is of the raw file bytes, taken
before any text decoding, so the digest does not depend on the encoding.

JSON, JSONL, CSV, TSV, and plain text are read. Anything else is quarantined
with a fixed reason token, never with a quote from the file. A JSON tree
deeper than the scanner can walk is quarantined too, so a buried name is
not copied out unread.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

# utf-8-sig accepts a BOM. utf-16 is checked from the BOM before this list.
# cp1252 comes before latin-1 so a Windows export is not misread as latin-1.
# latin-1 can decode every byte, so it is the last resort.
_ENCODINGS = ("utf-8-sig", "utf-8", "cp1252", "latin-1")
_SUPPORTED = {".json", ".jsonl", ".csv", ".tsv", ".txt"}

# Same cap as detection and the sanitizer. Deeper trees are quarantined
# instead of parsed, so json.loads cannot raise RecursionError and an
# unscanned leaf cannot be written out.
_MAX_DEPTH = 128

# These top-level lists are one record per element (/visits/0, /results/3).
# A FHIR Bundle, a lab panel, and a ward list stay one document ("doc").
_SPLIT_KEYS = ("visits", "results", "patients")


def read_file(path: Path) -> dict:
    """Read one JSON, JSONL, CSV, TSV, or text file.

    Returns a dictionary:
      records      list of record dictionaries (empty when quarantined)
      shape        object, list, records, split, jsonl, csv, tsv, or text.
                   Empty when quarantined
      locs         one locator per record: row:N, a JSON pointer, or doc
      shell        for shape "split", the object around the record list
      split_key    list key those records are written back under
      delimiter    "," or "\\t" for tables
      sha256       hex digest of the raw file, or None if it could not be read
      encoding     codec name, or None when decoding did not happen
      quarantined  True when the file is missing, unreadable, or not valid
      reason       short token when quarantined, otherwise ""
      path         the path that was requested

    Parser errors are not copied into ``reason``. Those messages can quote
    the file, and a hospital file may contain patient data.
    """
    source = Path(path)
    result = _blank(source)

    try:
        raw = source.read_bytes()
    except FileNotFoundError:
        return _quarantine(result, "file_not_found")
    except OSError:
        return _quarantine(result, "could_not_read")

    result["sha256"] = hashlib.sha256(raw).hexdigest()

    suffix = source.suffix.lower()
    if suffix not in _SUPPORTED:
        return _quarantine(result, "unsupported_format")

    if not raw.strip():
        return _quarantine(result, "empty_file")

    try:
        text, encoding = _decode(raw)
    except UnicodeError:
        return _quarantine(result, "could_not_decode")

    result["encoding"] = encoding
    if not text.strip():
        return _quarantine(result, "empty_file")

    try:
        if suffix == ".json":
            records, shape, locs, shell, split_key = _parse_json(text)
        elif suffix == ".jsonl":
            records = _parse_jsonl(text)
            shape, locs = "jsonl", [f"/{index}" for index in range(len(records))]
            shell, split_key = None, None
        elif suffix == ".txt":
            records = [{"text": text}]
            shape, locs = "text", ["doc"]
            shell, split_key = None, None
        else:
            delimiter = "\t" if suffix == ".tsv" else ","
            if _json_document(text):
                raise ValueError("table is not a table")
            records = _parse_table(text, delimiter)
            shape = "tsv" if suffix == ".tsv" else "csv"
            locs = [f"row:{index}" for index in range(len(records))]
            shell, split_key = None, None
            result["delimiter"] = delimiter
    except RecursionError:
        return _quarantine(result, "nesting_too_deep")
    except (ValueError, csv.Error, MemoryError):
        kind = {".json": "invalid_json", ".jsonl": "invalid_jsonl"}.get(suffix, "invalid_table")
        if suffix == ".csv":
            kind = "invalid_csv"
        elif suffix == ".tsv":
            kind = "invalid_tsv"
        elif suffix == ".txt":
            kind = "invalid_text"
        return _quarantine(result, kind)

    result["records"] = records
    result["shape"] = shape
    result["locs"] = locs
    result["shell"] = shell
    result["split_key"] = split_key
    return result


def _blank(source: Path) -> dict:
    return {
        "path": str(source),
        "sha256": None,
        "encoding": None,
        "shape": "",
        "records": [],
        "locs": [],
        "shell": None,
        "split_key": None,
        "delimiter": ",",
        "quarantined": False,
        "reason": "",
    }


def _decode(raw: bytes) -> tuple[str, str]:
    """Decode raw bytes as UTF-16 (BOM), UTF-8, cp1252, then latin-1."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16"), "utf-16"
    last_error: UnicodeError | None = None
    for codec in _ENCODINGS:
        try:
            text = raw.decode(codec)
        except UnicodeError as exc:
            last_error = exc
            continue
        name = "utf-8" if codec == "utf-8-sig" else codec
        return text, name
    if last_error is not None:
        raise last_error
    raise UnicodeError("could not decode file")


def _parse_json(text: str) -> tuple[list[dict], str, list[str], dict | None, str | None]:
    """Accept one object, a list of objects, or {\"records\": [...]}."""
    if _nesting_depth(text) > _MAX_DEPTH:
        raise RecursionError
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("JSON is not valid") from exc
    except RecursionError:
        raise
    if isinstance(data, list):
        records = _as_records(data)
        return records, "list", [f"/{index}" for index in range(len(records))], None, None
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        records = _as_records(data["records"])
        return records, "records", [f"/records/{index}" for index in range(len(records))], None, None
    if isinstance(data, dict):
        return _parse_object(data)
    raise ValueError("JSON must be an object or a list of objects")


def _parse_object(data: dict) -> tuple[list[dict], str, list[str], dict | None, str | None]:
    """One document, unless visits, results, or patients is a list of rows."""
    if data.get("resourceType") == "Bundle":
        return [data], "object", ["doc"], None, None
    for key in _SPLIT_KEYS:
        rows = data.get(key)
        if not isinstance(rows, list) or not rows:
            continue
        if not all(isinstance(row, dict) for row in rows):
            raise ValueError("JSON record list must contain objects")
        shell: dict = {}
        for name, value in data.items():
            shell[name] = [] if name == key else value
        pointer = "/" + key.replace("~", "~0").replace("/", "~1")
        locs = [f"{pointer}/{index}" for index in range(len(rows))]
        return list(rows), "split", locs, shell, key
    return [data], "object", ["doc"], None, None


def _parse_jsonl(text: str) -> list[dict]:
    """One JSON object per line. Blank lines are skipped."""
    records: list[dict] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if _nesting_depth(line) > _MAX_DEPTH:
            raise RecursionError
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSONL line {line_number} is not valid JSON") from exc
        except RecursionError:
            raise
        if not isinstance(item, dict):
            raise ValueError(f"JSONL line {line_number} is not an object")
        records.append(item)
    return records


def _parse_table(text: str, delimiter: str) -> list[dict]:
    """Read a header row, then one dictionary per data row."""
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if reader.fieldnames is None:
        return []
    records: list[dict] = []
    for row_number, row in enumerate(reader, start=2):
        if None in row:
            raise ValueError(f"row {row_number} has more columns than the header")
        records.append({key: value for key, value in row.items() if key is not None})
    return records


def _json_document(text: str) -> bool:
    """True when a .csv or .tsv file is really one JSON document."""
    stripped = text.lstrip("\ufeff").strip()
    if not stripped.startswith(("{", "[")):
        return False
    if _nesting_depth(stripped) > _MAX_DEPTH:
        return True
    try:
        data = json.loads(stripped)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return False
    return isinstance(data, (dict, list))


def _nesting_depth(text: str) -> int:
    """Deepest ``{`` or ``[`` outside of strings. Iterative, so it cannot recurse."""
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > deepest:
                deepest = depth
        elif char in "}]" and depth:
            depth -= 1
    return deepest


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
    result["locs"] = []
    result["shape"] = ""
    result["shell"] = None
    result["split_key"] = None
    result["quarantined"] = True
    result["reason"] = reason
    return result
