#!/usr/bin/env python3
"""WARD-LOCK: offline privacy firewall for hospital records.

Local files only. No language models and no network calls.

    python main.py --input input_folder --output output_folder
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detection.engine import find_personal_info, mask_personal_text
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
    if not os.environ.get("RAKSHA_SECRET", "").strip():
        raise ValueError("RAKSHA_SECRET is not set")

    sources = _input_files(root, output)
    loaded: list[dict] = []
    combined: list[dict] = []
    spans: list[tuple[int, int]] = []
    quarantined_files = 0
    for path, relative in sources:
        item = _load_one(path, relative)
        start = len(combined)
        if not item["quarantined"]:
            combined.extend(item["records"])
        else:
            quarantined_files += 1
        spans.append((start, len(combined)))
        loaded.append(item)

    # One list, so the same person in two files shares one patient id.
    # Counts only. Record text is personal information and stays off stdout.
    policy = load_policy(POLICY_PATH)
    loaded, spans, combined, found, generalized = _transform(loaded, spans, combined, policy)
    _sanitize_shells(loaded, policy)
    quarantined_files = sum(1 for item in loaded if item["quarantined"])
    shell_hits = sum(int(item.get("shell_hits") or 0) for item in loaded)
    detected = len(found) + shell_hits
    linked = sum(1 for record in combined if isinstance(record, dict) and record.get("patient"))
    print(f"[ingestion] {len(loaded)} file(s), {quarantined_files} quarantined")
    print(f"[detection] {detected} personal item(s)")
    print(f"[linkage] {linked} patient id(s), {len(combined) - linked} left unset")
    print(f"[sanitizer] removed {detected} personal item(s)")

    _write_output(output, loaded, spans, combined, detected, generalized, clock)
    print("[ward-lock] finished")


def _load_one(path: Path, relative: str) -> dict:
    """Read one file. A crash becomes a quarantine, and the name stays off stdout."""
    try:
        item = read_file(path)
    except RecursionError:
        item = _unreadable(path, "nesting_too_deep")
    except (OSError, ValueError, MemoryError):
        item = _unreadable(path, "could_not_read")
    except Exception:
        item = _unreadable(path, "could_not_read")
    item["relative"] = relative
    item["shell_hits"] = 0
    return item


def _unreadable(path: Path, reason: str) -> dict:
    """Quarantine a file that the reader could not finish, and still hash it."""
    digest = None
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        pass
    return {
        "sha256": digest,
        "encoding": None,
        "shape": "",
        "records": [],
        "locs": [],
        "shell": None,
        "split_key": None,
        "delimiter": ",",
        "quarantined": True,
        "reason": reason,
    }


def _transform(
    loaded: list[dict],
    spans: list[tuple[int, int]],
    combined: list[dict],
    policy: dict,
) -> tuple[list[dict], list[tuple[int, int]], list[dict], list[dict], int]:
    """Detect, link, generalize, and redact. One bad file is quarantined."""
    try:
        done, found, generalized = _stages(combined, policy)
        return loaded, spans, done, found, generalized
    except RecursionError:
        pass
    except Exception:
        pass

    rebuilt: list[dict] = []
    new_loaded: list[dict] = []
    new_spans: list[tuple[int, int]] = []
    found_all: list[dict] = []
    generalized = 0
    for item, (start, end) in zip(loaded, spans):
        if item["quarantined"]:
            new_spans.append((len(rebuilt), len(rebuilt)))
            new_loaded.append(item)
            continue
        try:
            done, found, gen = _stages(combined[start:end], policy)
        except Exception:
            failed = dict(item)
            failed["quarantined"] = True
            failed["reason"] = "could_not_process"
            failed["records"] = []
            failed["locs"] = []
            new_spans.append((len(rebuilt), len(rebuilt)))
            new_loaded.append(failed)
            continue
        new_spans.append((len(rebuilt), len(rebuilt) + len(done)))
        rebuilt.extend(done)
        found_all.extend(found)
        generalized += gen
        new_loaded.append(item)
    return new_loaded, new_spans, rebuilt, found_all, generalized


def _stages(records: list[dict], policy: dict) -> tuple[list[dict], list[dict], int]:
    """Run the middle of the pipeline on one list of records."""
    found = find_personal_info(records)
    generalized = 0
    if records:
        records = assign_patients(records, found)
        before = records
        records = generalize(records)
        generalized = sum(1 for old, new in zip(before, records) if old != new)
        records = assess(records, policy)
        records = sanitize(records, found, policy)
    return records, found, generalized


def _sanitize_shells(loaded: list[dict], policy: dict) -> None:
    """Redact names that sit beside a record list, such as an export path."""
    for item in loaded:
        shell = item.get("shell")
        if item.get("quarantined") or not isinstance(shell, dict):
            continue
        try:
            found = find_personal_info([shell])
            cleaned = sanitize([shell], found, policy)
            item["shell"] = cleaned[0] if cleaned else shell
            item["shell_hits"] = len(found)
        except Exception:
            item["quarantined"] = True
            item["reason"] = "could_not_process"
            item["records"] = []
            item["locs"] = []


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
    detected: int,
    generalized: int,
    clock: float,
) -> None:
    """Write sanitized/, records.jsonl, and report.json.

    The report names files by SHA-256 only. A path can be a patient's name,
    so it is not stored here and is not printed.
    """
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
            "input_sha256": item["sha256"],
            "output": None,
            "status": "quarantined" if quarantined else "sanitized",
        }
        if quarantined:
            entry["reason"] = item.get("reason") or "could_not_process"
        else:
            relative = _safe_relative(item["relative"])
            dest_rel = "sanitized/" + relative
            dest = sanitized_root / relative
            entry["output"] = dest_rel
            try:
                entry["output_sha256"] = write_shaped(
                    records,
                    dest,
                    item.get("shape") or "",
                    shell=item.get("shell"),
                    split_key=item.get("split_key"),
                    delimiter=item.get("delimiter") or ",",
                )
            except RecursionError:
                _drop_partial(dest)
                entry["status"] = "quarantined"
                entry["output"] = None
                entry["reason"] = "nesting_too_deep"
                records = []
            except (OSError, ValueError, TypeError, MemoryError):
                _drop_partial(dest)
                entry["status"] = "quarantined"
                entry["output"] = None
                entry["reason"] = "could_not_process"
                records = []
            else:
                sanitized_count += 1
                locs = item.get("locs") or []
                for offset, record in enumerate(records):
                    loc = locs[offset] if offset < len(locs) else "doc"
                    index_rows.append(
                        {
                            "file": dest_rel,
                            "loc": loc,
                            "patient": _patient_id(record),
                        }
                    )
        file_reports.append(entry)

    _write_index(index_rows, output / "records.jsonl")

    linked = sum(1 for row in index_rows if row["patient"])
    quarantined_count = len(loaded) - sanitized_count
    report = {
        "schema": "raksha-report/1",
        "files": file_reports,
        "counts": {
            "files_total": len(loaded),
            "files_sanitized": sanitized_count,
            "files_quarantined": quarantined_count,
            "records_processed": len(index_rows),
            "identifiers_detected": detected,
            "records_linked": linked,
            "records_generalized": generalized,
            "records_suppressed": 0,
            "records_quarantined": 0,
        },
        "timing": {"seconds": round(time.perf_counter() - clock, 3)},
        "resources": {"peak_rss_mb": _peak_rss_mb()},
    }
    report_path = output / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _safe_relative(relative: str) -> str:
    """Rename a file whose name contains a person or an id.

    The directory stays. A short hash keeps two renamed files from colliding
    and does not copy the original name.
    """
    path = Path(relative)
    masked = mask_personal_text(path.name)
    if masked == path.name:
        return relative
    suffix = path.suffix
    stem = masked[: -len(suffix)] if suffix and masked.endswith(suffix) else masked
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._") or "record"
    digest = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:8]
    name = f"{stem}_{digest}{suffix}"
    parent = path.parent.as_posix()
    if parent in {"", "."}:
        return name
    return f"{parent}/{name}"


def _drop_partial(path: Path) -> None:
    """Remove a file that failed mid-write so it is not part of the release."""
    try:
        if path.is_file():
            path.unlink()
    except OSError:
        pass


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
            sort_keys=True,
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
