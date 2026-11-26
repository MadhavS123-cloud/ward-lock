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
from utils.io import write_shaped

POLICY_PATH = ROOT / "config" / "policy.yaml"


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
        help="Folder of local records. Unsupported types are quarantined.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Folder for sanitized/, report.json, and records.jsonl.",
    )
    return parser


def run_pipeline(input_path: Path, output_path: Path) -> None:
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
    quarantined_files = 0
    for path, relative in sources:
        try:
            item = read_file(path)
        except RecursionError:
            item = {
                "sha256": None,
                "encoding": None,
                "shape": "",
                "records": [],
                "quarantined": True,
                "reason": "JSON nesting is too deep",
            }
        item["relative"] = relative
        start = len(combined)
        if not item["quarantined"]:
            combined.extend(item["records"])
        else:
            quarantined_files += 1
        spans.append((start, len(combined)))
        loaded.append(item)

    # One list, so the same person in two files shares one patient id.
    # Counts only. Record text is personal information and stays off stdout.
    found = find_personal_info(combined)
    print(f"[ingestion] {len(loaded)} file(s), {quarantined_files} quarantined")
    print(f"[detection] {len(found)} personal item(s)")

    if combined:
        combined = assign_patients(combined, found)
        linked = sum(1 for record in combined if isinstance(record, dict) and record.get("patient"))
        print(f"[linkage] {linked} patient id(s), {len(combined) - linked} left unset")
        combined = generalize(combined)
        policy = load_policy(POLICY_PATH)
        combined = assess(combined, policy)
        combined = sanitize(combined, found, policy)
        print(f"[sanitizer] removed {len(found)} personal item(s)")
    else:
        load_policy(POLICY_PATH)
        print("[linkage] 0 patient id(s), 0 left unset")
        print("[sanitizer] removed 0 personal item(s)")

    _write_output(output, loaded, spans, combined, found, clock)
    print("[ward-lock] finished")


def _input_files(root: Path, output: Path) -> list[tuple[Path, str]]:
    """Every file under the input folder, in a stable order.

    JSON, JSONL, and CSV are sanitized. Anything else is still listed so the
    reader can quarantine it and the report can name it.
    """
    found: list[tuple[Path, str]] = []
    for path in root.rglob("*"):
        if not path.is_file():
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
    clock: float,
) -> None:
    """Write sanitized/, records.jsonl, and report.json."""
    sanitized_root = output / "sanitized"
    if sanitized_root.exists():
        shutil.rmtree(sanitized_root)
    sanitized_root.mkdir(parents=True, exist_ok=True)

    index_rows: list[dict] = []
    file_reports: list[dict] = []
    sanitized_count = 0
    for index, item in enumerate(loaded):
        start, end = spans[index]
        quarantined = bool(item["quarantined"])
        records = [] if quarantined else combined[start:end]
        entry = {
            "path": item["relative"],
            "input_sha256": item["sha256"],
            "output": None,
            "status": "quarantined" if quarantined else "sanitized",
            "records": len(records),
        }
        if quarantined:
            entry["reason"] = item["reason"]
        else:
            dest_rel = "sanitized/" + item["relative"]
            entry["output"] = dest_rel
            try:
                entry["output_sha256"] = write_shaped(
                    records, sanitized_root / item["relative"], item.get("shape") or ""
                )
            except RecursionError:
                entry["status"] = "quarantined"
                entry["output"] = None
                entry["records"] = 0
                entry["reason"] = "JSON nesting is too deep"
                records = []
            else:
                sanitized_count += 1
                for offset, record in enumerate(records):
                    index_rows.append(
                        {
                            "file": item["relative"],
                            "loc": str(offset),
                            "patient": _patient_id(record),
                        }
                    )
        file_reports.append(entry)

    _write_index(index_rows, output / "records.jsonl")

    linked = sum(1 for row in index_rows if row["patient"])
    quarantined_count = len(loaded) - sanitized_count
    report = {
        "timing": {"seconds": round(time.perf_counter() - clock, 3)},
        "resources": {"peak_rss_mb": _peak_rss_mb()},
        "counts": {
            "files_total": len(loaded),
            "files_sanitized": sanitized_count,
            "files_quarantined": quarantined_count,
            "records_processed": len(index_rows),
            "records_linked": linked,
            "records_unlinked": len(index_rows) - linked,
            "personal_items": len(found),
        },
        "files": file_reports,
    }
    report_path = output / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _patient_id(record: object) -> str | None:
    """Pseudonym only. Missing and blank ids are null in the index."""
    if not isinstance(record, dict):
        return None
    patient = record.get("patient")
    if isinstance(patient, str) and patient.strip():
        return patient.strip()
    return None


def _write_index(rows: list[dict], path: Path) -> None:
    """One index line per record: file, loc, and patient. Not the record body."""
    lines = [
        json.dumps(
            {"file": row["file"], "loc": row["loc"], "patient": row["patient"]},
            ensure_ascii=False,
        )
        for row in rows
    ]
    text = ("\n".join(lines) + "\n") if lines else ""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _peak_rss_mb() -> float:
    """Highest resident memory of this process, in megabytes."""
    try:
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # macOS reports bytes. Linux reports kilobytes.
        if sys.platform == "darwin":
            return round(peak / (1024 * 1024), 3)
        return round(peak / 1024, 3)
    except Exception:
        pass
    if sys.platform != "win32":
        return 0.0
    try:
        import ctypes
        from ctypes import wintypes

        class _Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = _Counters()
        counters.cb = ctypes.sizeof(_Counters)
        # argtypes are required. Without them the 64-bit call fails and the
        # peak stays zero.
        kernel = ctypes.windll.kernel32
        process = kernel.GetCurrentProcess()
        info = ctypes.windll.psapi.GetProcessMemoryInfo
        info.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Counters), wintypes.DWORD]
        info.restype = wintypes.BOOL
        if info(process, ctypes.byref(counters), counters.cb):
            return round(counters.PeakWorkingSetSize / (1024 * 1024), 3)
    except Exception:
        pass
    return 0.0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run_pipeline(args.input, args.output)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except RecursionError:
        print("error: input nesting is too deep", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
