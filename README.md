# WARD-LOCK

WARD-LOCK is an offline privacy firewall for synthetic Indian hospital records. It runs locally on CPU with no network calls, no external APIs, and no language models.

The tool takes a folder of hospital exports, detects personal information across English and Hindi (Devanagari) text, links records belonging to the same patient under a keyed pseudonym, generalizes dates and ages, redacts direct identifiers, and writes the cleaned files along with a run report.

## Tech Stack

- **Python 3** (standard library: `csv`, `json`, `re`, `hmac`, `hashlib`, `datetime`, `tomllib`, `pathlib`)
- **PyYAML** (`config/policy.yaml` loading and policy validation)
- **indic-transliteration** (Devanagari-to-IAST transliteration for matching Hindi names against Latin records)
- **rapidfuzz** (`fuzz.ratio` token similarity for cross-record patient clustering)

## Setup and Usage

Install dependencies and set the per-release secret in your environment:

```bash
pip install -r requirements.txt
```

On Linux / macOS:

```bash
export RAKSHA_SECRET="your-secret-here"
python main.py --input input_folder --output output_folder
```

On PowerShell (Windows):

```powershell
$env:RAKSHA_SECRET = "your-secret-here"
python main.py --input input_folder --output output_folder
```

The output folder contains:
- `sanitized/`: cleaned files keeping the input folder layout and container formats
- `records.jsonl`: processed records with their assigned `patient` pseudonym
- `report.json`: file hashes, record counts, quarantine status, and elapsed time

## Architecture

```
input files (.json, .jsonl, .csv)
   │
   ▼
[1. Ingestion]        decode (utf-8-sig / latin-1), SHA-256 hash, quarantine broken files
   │
   ▼
[2. Detection]        regex + field-key scan, doctor/medicine span protection, Hindi romanization
   │
   ▼
[3. Linkage & HMAC]   name normalization + rapidfuzz token matching + Union-Find -> PSN-<hex>
   │
   ▼
[4. Privacy]          HMAC-keyed per-patient date shifting, 10-year age banding
   │
   ▼
[5. Sanitizer]        span + policy-column redaction ([REDACTED]), preserve clinical fields
   │
   ▼
output/ (sanitized/, records.jsonl, report.json)
```

## How Each Stage Works

1. **Ingestion (`ingestion/reader.py`)**:
   Reads `.json` (single object, list, or `{"records": [...]}`), `.jsonl`, and `.csv` files. Raw bytes are hashed with SHA-256 before decoding. Decoding tries `utf-8-sig` first and falls back to `latin-1`. Broken JSON/CSV files or unsupported formats passed directly to the reader are marked `quarantined` without copying parser exception text into the reason field.

2. **Detection (`detection/engine.py`)**:
   Recursively walks each record to scan leaf strings and field names.
   - **Rule and regex matching**: detects email addresses, 10–12 digit Indian mobile and STD landline numbers, 12-digit Aadhaar numbers, 14-digit ABHA IDs, UHID/MRN tokens, and names in English and Devanagari.
   - **Context rules**: identifies prefixed names (`Mr`, `Mrs`, `Shri`, `Smt`, `Pt`, `C/O`, `S/o`, `D/o`, `W/o`), skips clinical/stop words, and protects spans matching doctors (`Dr.`, `डॉ.`) and medicines/doses (`Dolo 650`, `Ramipril 5 mg`, `1-0-1`) as well as doctor/medicine column names.
   - **Transliteration**: Devanagari names are romanized to IAST using `indic-transliteration` (falls back gracefully if absent).

3. **Linkage and Pseudonymization (`linkage/cluster.py`, `pseudonym/hmac.py`)**:
   - Picks the patient name per record while ignoring relative cues (`C/O`, `S/O`, `D/O`, `W/O`), doctor columns, and medicine columns.
   - Normalizes names by romanizing Hindi, lowercasing, stripping punctuation, and removing honorifics (`ji`, `sahab`, `sahib`, `sahaba`, `didi`).
   - Compares name pairs using word-level `rapidfuzz.fuzz.ratio` (supporting single-letter initials like `Ramesh K.` matching `Ramesh Kumar`).
   - Clusters records scoring `>= 80` via Union-Find. Records with weak best matches (`70–80`) or conflicting strong matches are left unlinked (`patient: null`).
   - Generates deterministic `PSN-<6-hex>` IDs via `HMAC-SHA256` keyed with `RAKSHA_SECRET`.

4. **Privacy / Generalization (`privacy/generalize.py`, `privacy/assess.py`)**:
   - Shifts `YYYY-MM-DD` and `DD/MM/YYYY` dates by a deterministic non-zero offset in `[-365, +365]` days derived from `HMAC-SHA256(RAKSHA_SECRET, "date-shift:<key>")` per patient so admission/discharge gaps and stay durations stay unchanged.
   - Converts exact ages in age fields and phrases (`age 47`, `47 years old`) into 10-year bands (`40-49`).
   - Skips clinical fields (`medicine`, `dose`, `vital`, `diagnosis`, `bp`, `pulse`, `spo2`, `temperature`, `heart_rate`).

5. **Sanitization and Export (`sanitizer/sanitize.py`, `utils/io.py`)**:
   Replaces detected PII spans (longest match first with boundary checks) and policy-defined `direct_identifiers` columns (`config/policy.yaml`) with `[REDACTED]`, leaving clinical fields untouched. Outputs are written in UTF-8 preserving original container shapes.

## Security Design

- **Offline and local-only**: `utils/config.py` validates `config/policy.yaml` at runtime to enforce `offline: true`, `cpu_only: true`, and `llm: false`.
- **Key handling**: `RAKSHA_SECRET` is read solely from the environment variable for HMAC pseudonyms and date shifts and is never written to output files.
- **Quarantine safety**: Failed reads drop all partial records and omit raw exception strings from `report.json`.

## Known Limitations

- **Supported file types**: `main.py` currently discovers `.json`, `.jsonl`, and `.csv` only; `.txt`, `.tsv`, `.xml`, `.pdf`, and `.jpg` files are not processed or listed in `report.json`.
- **Deeply nested JSON**: `_walk()` in `detection/engine.py` uses Python recursion and hits `RecursionError` on very deep JSON trees (e.g., 1,500+ levels).
- **Incomplete PII & channel coverage**: `PAN`, `INSURANCE_ID`, `PIN`, `VILLAGE`, and hidden channels (filenames, CSV headers, JSON keys, base64 attachments, and path metadata) are not yet detected/renamed.
- **Over-redaction & FHIR structure**: Capitalized clinical/facility phrases (such as lab test names, hospital names, districts, and `C/O` complaints) can be matched by the generic capitalized-name regex, and a root `patient` key is added to JSON objects including FHIR Bundles.
- **Contract & logging gaps**: `main.py` prints detected items to stdout during runs, `report.json` and `records.jsonl` schemas are not yet aligned with the `raksha-report/1` evaluation contract, and `privacy/assess.py` (k-anonymity assessment) is still a stub.
