"""Read and write local record files. No network access."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path


def read_records(path: Path) -> list[dict]:
    """Load a local JSON, JSONL, or CSV file of synthetic records."""
    source = path.resolve()
    if not source.is_file():
        raise FileNotFoundError(f"input not found: {source}")

    suffix = source.suffix.lower()
    if suffix == ".json":
        return _read_json(source)
    if suffix == ".jsonl":
        return _read_jsonl(source)
    if suffix == ".csv":
        return _read_csv(source)
    raise ValueError(f"unsupported input format '{suffix}'. Use .json, .jsonl, or .csv")


def write_records(records: list[dict], path: Path) -> None:
    """Write sanitized records next to the chosen local path."""
    target = path.resolve()
    suffix = target.suffix.lower()
    if suffix not in {".json", ".jsonl", ".csv"}:
        raise ValueError(f"unsupported output format '{suffix}'. Use .json, .jsonl, or .csv")

    shape = {".json": "list", ".jsonl": "jsonl", ".csv": "csv"}[suffix]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_render(records, suffix, shape))


def write_shaped(records: list[dict], path: Path, shape: str) -> str:
    """Write records in the container the reader saw.

    ``shape`` is object, list, records, jsonl, or csv. Returns the SHA-256
    hex digest of the bytes written.
    """
    target = path.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    data = _render(records, target.suffix.lower(), shape)
    target.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _render(records: list[dict], suffix: str, shape: str) -> bytes:
    """Serialize records. A single JSON object stays an object."""
    if shape == "object" and len(records) == 1:
        return _json_bytes(records[0])
    if shape == "records":
        return _json_bytes({"records": records})
    if shape == "csv" or suffix == ".csv":
        return _csv_bytes(records)
    if shape == "jsonl" or suffix == ".jsonl":
        return _jsonl_bytes(records)
    return _json_bytes(records)


def _json_bytes(payload: object) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _jsonl_bytes(records: list[dict]) -> bytes:
    lines = [json.dumps(record, ensure_ascii=False) for record in records]
    text = "\n".join(lines)
    if lines:
        text += "\n"
    return text.encode("utf-8")


def _csv_bytes(records: list[dict]) -> bytes:
    fieldnames: list[str] = []
    seen: set[str] = set()
    for record in records:
        for key in record:
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for record in records:
        writer.writerow({key: _csv_cell(record.get(key, "")) for key in fieldnames})
    return buffer.getvalue().encode("utf-8")


def _read_json(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, list):
        return _as_records(data)
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        return _as_records(data["records"])
    if isinstance(data, dict):
        return [data]
    raise ValueError("JSON input must be a record, a list of records, or {\"records\": [...]}")


def _read_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError(f"JSONL line {line_number} is not an object")
        records.append(item)
    return records


def _read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            return []
        return [dict(row) for row in reader]


def _csv_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _as_records(rows: list) -> list[dict]:
    records: list[dict] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"record {index} is not an object")
        records.append(row)
    return records
