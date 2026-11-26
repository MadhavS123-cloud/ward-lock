#!/usr/bin/env python3
"""WARD-LOCK: offline privacy firewall for hospital records.

Local files only. No language models and no network calls.

    python main.py --input input_folder --output output_folder
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detection.engine import find_personal_info
from ingestion.reader import read_file
from linkage.cluster import assign_patients
from privacy.assess import assess
from privacy.generalize import generalize
from sanitizer import sanitize
from utils.config import load_policy
from utils.io import write_records, write_shaped

POLICY_PATH = ROOT / "config" / "policy.yaml"
_SUPPORTED = {".json", ".jsonl", ".csv"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ward-lock",
        description=(
            "Offline hospital privacy firewall. "
            "Reads and writes local files. Does not call language models."
        ),
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Folder of local records (.json, .jsonl, or .csv).",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Folder for sanitized/, report.json, and records.jsonl.",
    )
    return parser


def run_pipeline(input_path: Path, output_path: Path) -> None:
    started = datetime.now(timezone.utc)
    clock = time.perf_counter()

    root = input_path.resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"input folder not found: {root}")
    output = output_path.resolve()
    if output.exists() and not output.is_dir():
        raise ValueError(f"output must be a folder: {output}")

    sources = _input_files(root, output)
    loaded: list[dict] = []
    combined: list[dict] = []
    spans: list[tuple[int, int]] = []
    for path, relative in sources:
        item = read_file(path)
        item["relative"] = relative
        start = len(combined)
        if not item["quarantined"]:
            combined.extend(item["records"])
        spans.append((start, len(combined)))
        loaded.append(item)
        if item["quarantined"]:
            print(f"[ingestion] quarantined {relative}: {item['reason']}")
        else:
            print(
                f"[ingestion] {relative}: {len(item['records'])} record(s) "
                f"encoding={item['encoding']} sha256={item['sha256']}"
            )

    # One list, so the same person in two files shares one patient id.
    found = find_personal_info(combined)
    _report_findings(found)

    if combined:
        combined = assign_patients(combined, found)
        linked = sum(1 for record in combined if isinstance(record, dict) and record.get("patient"))
        print(f"[linkage] {linked} patient id(s), {len(combined) - linked} left unset")
        combined = generalize(combined)
        print("[privacy] shifted dates by patient and banded ages")
        policy = load_policy(POLICY_PATH)
        combined = assess(combined, policy)
        combined = sanitize(combined, found, policy)
        print(f"[sanitizer] removed {len(found)} personal item(s)")
    else:
        load_policy(POLICY_PATH)
        print("[linkage] 0 patient id(s), 0 left unset")
        print("[sanitizer] removed 0 personal item(s)")

    _write_output(output, loaded, spans, combined, found, started, clock)
    print(f"[ward-lock] wrote {output}")


def _input_files(root: Path, output: Path) -> list[tuple[Path, str]]:
    """Supported files under the input folder, in a stable order."""
    found: list[tuple[Path, str]] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SUPPORTED:
            continue
        resolved = path.resolve()
        # A previous output folder sitting inside the input is not a source.
        if resolved == output or output in resolved.parents:
            continue
        found.append((path, path.relative_to(root).as_posix()))
    found.sort(key=lambda item: item[1])
    return found


def _write_output(
    output: Path,
    loaded: list[dict],
    spans: list[tuple[int, int]],
    combined: list[dict],
    found: list[dict],
    started: datetime,
    clock: float,
) -> None:
    """Write sanitized/, records.jsonl, and report.json."""
    sanitized_root = output / "sanitized"
    if sanitized_root.exists():
        shutil.rmtree(sanitized_root)
    sanitized_root.mkdir(parents=True, exist_ok=True)

    hits = _hits_by_file(spans, found)
    flat: list[dict] = []
    file_reports: list[dict] = []
    for index, item in enumerate(loaded):
        start, end = spans[index]
        records = [] if item["quarantined"] else combined[start:end]
        flat.extend(records)
        entry = {
            "path": item["relative"],
            "sha256": item["sha256"],
            "records": len(records),
            "personal_items": hits[index],
            "quarantined": bool(item["quarantined"]),
        }
        if item["quarantined"]:
            entry["reason"] = item["reason"]
        else:
            dest = sanitized_root / item["relative"]
            entry["sanitized"] = "sanitized/" + item["relative"]
            entry["sanitized_sha256"] = write_shaped(records, dest, item.get("shape") or "")
        file_reports.append(entry)

    write_records(flat, output / "records.jsonl")

    linked = sum(1 for record in flat if isinstance(record, dict) and record.get("patient"))
    finished = datetime.now(timezone.utc)
    report = {
        "timing": {
            "started": started.isoformat(),
            "finished": finished.isoformat(),
            "elapsed_seconds": round(time.perf_counter() - clock, 3),
        },
        "counts": {
            "files": len(loaded),
            "records": len(flat),
            "quarantined": sum(1 for item in loaded if item["quarantined"]),
            "personal_items": len(found),
            "linked": linked,
            "unlinked": len(flat) - linked,
        },
        "files": file_reports,
    }
    report_path = output / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _hits_by_file(spans: list[tuple[int, int]], found: list[dict]) -> list[int]:
    counts = [0] * len(spans)
    for item in found:
        record_index = int(item.get("record", -1))
        for file_index, (start, end) in enumerate(spans):
            if start <= record_index < end:
                counts[file_index] += 1
                break
    return counts


def _report_findings(found: list[dict]) -> None:
    print(f"[detection] {len(found)} personal item(s)")
    for item in found:
        parts = [f"{item['type']}:"]
        if item.get("cue"):
            parts.append(item["cue"])
        parts.append(item["text"])
        if item.get("latin"):
            parts.append(f"[{item['latin']}]")
        if item.get("field"):
            parts.append(f"({item['field']})")
        _emit("[detection] " + " ".join(parts))


def _emit(message: str) -> None:
    """Print text that may contain Hindi on a console that is not UTF-8."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    safe = message.encode(encoding, errors="replace").decode(encoding, errors="replace")
    print(safe)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run_pipeline(args.input, args.output)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
