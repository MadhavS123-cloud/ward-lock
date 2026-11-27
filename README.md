# WARD-LOCK

WARD-LOCK is an offline privacy firewall for synthetic Indian hospital records. It runs on the local CPU. It does not call a network service and it does not call a language model. Point it at a folder of hospital exports and it finds personal information in English and Hindi, links records that belong to the same patient, replaces that identity with a keyed pseudonym, generalizes dates and ages, redacts direct identifiers, and writes the cleaned files plus a run report.

The release is built for a privacy evaluation. Medicines, doses, vitals, and diagnoses stay in the chart so a later reader can still use the clinical content. Names, phone numbers, government ids, addresses, and exact dates of birth are removed or generalized.

## Setup and how to run

Python 3.11 or later is enough. The third-party packages are PyYAML, which loads `config/policy.yaml`, and rapidfuzz, which scores name pairs. Hindi romanization lives in `utils/translit.py` and needs no extra package.

```bash
pip install -r requirements.txt
```

Set the per-release secret before the run. The pipeline reads it from the environment and does not write it into any output file.

PowerShell:

```powershell
$env:RAKSHA_SECRET = "your-secret-here"
python main.py --input input_folder --output output_folder
```

bash:

```bash
export RAKSHA_SECRET="your-secret-here"
python main.py --input input_folder --output output_folder
```

`raksha.toml` names the same entry point for an evaluator: install from `requirements.txt`, then `python main.py --input {input} --output {output}`.

The output folder contains three artifacts.

- `sanitized/` holds the cleaned files. Folder layout and container format are preserved. JSON objects, JSON lists, `{"records": [...]}` wrappers, JSONL, CSV, TSV, and plain text are written back in the shape they arrived in.
- `records.jsonl` has one line per processed record. Each line is only `file`, `loc`, and `patient`. `file` is a path under `sanitized/`. `loc` is `row:N` for a table, an RFC 6901 JSON pointer, or `doc` for a single document. `patient` is a `PSN-` id, or `null` when the linker will not assign one.
- `report.json` follows the `raksha-report/1` schema. Each input is identified by `input_sha256` of the raw bytes. The report stores `status` (`sanitized` or `quarantined`), a fixed reason token when the file was quarantined, the count block, `timing.seconds`, and `resources.peak_rss_mb`.

Stdout prints stage counts only. Record text, file paths, and quarantine reasons stay off the console.

A missing input folder, an output path that is not a directory, or a missing `RAKSHA_SECRET` exits with status 1. A bad file inside a valid folder is quarantined, the rest of the batch still finishes, and the process exits 0 after the report is written.

## Architecture

`main.py` runs one fixed sequence.

1. **Ingestion** (`ingestion/reader.py`). Every file under the input folder is listed in a stable order. Raw bytes are hashed with SHA-256 before any decoding. Decoding tries a UTF-16 BOM, then UTF-8 (including a BOM), Windows cp1252, and latin-1. Supported containers are `.json`, `.jsonl`, `.csv`, `.tsv`, and `.txt`. A JSON document deeper than 128 levels is quarantined before `json.loads`. Lists named `visits`, `results`, or `patients` become one record per element, and the surrounding object is kept as a shell. A FHIR Bundle stays one document. Other suffixes, including `.pdf`, `.jpg`, and `.xml`, are quarantined with `unsupported_format` and still appear in the report. Parser failures become fixed tokens such as `invalid_json`, `invalid_jsonl`, `invalid_csv`, `invalid_tsv`, `empty_file`, or `nesting_too_deep`. Exception text is dropped, because a parser message can quote the file.

2. **Detection** (`detection/engine.py`). Each record is walked to a depth of 128. Leaf strings are scanned with regular expressions and field-name rules. File names, JSON keys, and CSV headers go through the same mask.

3. **Linkage** (`linkage/cluster.py`). Names and chart identifiers are compared across the whole input, so the same person in two files can share one id.

4. **Pseudonym** (`pseudonym/hmac.py`). The shared identity becomes `PSN-` plus six hexadecimal characters from HMAC-SHA256.

5. **Privacy** (`privacy/generalize.py`). Dates move by a per-patient offset. Exact ages become 10-year bands. `privacy/assess.py` is reserved for k-anonymity and currently returns records unchanged.

6. **Sanitizer** (`sanitizer/sanitize.py`). Detected spans and policy columns are replaced with `[REDACTED]`. Place columns and address lines are wiped. Clinical fields are copied through.

A failure in the middle of the pipeline quarantines that file with `could_not_process`. The other files still finish. Shell objects that sit beside a split record list are scanned and redacted as well, so a label next to the rows is covered. Linkage runs on the raw values. Redaction happens after the pseudonym is assigned.

## How personal data is detected and removed

Detection is rule based. It looks for email addresses, Indian mobile numbers (an optional `+91` or leading `0`, spaces and hyphens allowed, Devanagari digits included), STD landlines, 12-digit Aadhaar numbers, 14-digit ABHA ids, PAN numbers of the form `ABCDE1234F`, labelled PIN codes, insurance tokens such as PM-JAY and CGHS, and hospital numbers (UHID, MRN, and unlabelled patterns such as `JJH-0077112`). A column whose leaf name is a known identifier is tagged when the value still has the right shape.

Names are detected in English and in Devanagari. Titles such as Mr, Mrs, Shri, Smt, and Patient mark a following name. Relative cues (`C/O`, `S/o`, `D/o`, `W/o`) mark a name that must be removed and must not be used as the patient's own name. Hinglish honorifics (`ji`, `sahab`, `didi`) and a name written before a relation (`Asha, W/o Kamal`) are included. Path fragments such as `Anita_Sharma` or `Shahid_NA_010607` are scanned too. Devanagari is romanized with `utils/translit.to_latin`, so `रमेश कुमार` and `Ramesh Kumar` become the same string, `ramesh kumar`. Long vowels fold short, a word-final inherent schwa is dropped, and `सिंह` becomes `singh`.

Some spans are protected so the chart stays useful. Text after `Dr.` or `डॉ.` is treated as a clinician and is not returned as a patient name. Medicine and dose patterns (`Dolo 650`, `Ramipril 5 mg`, `1-0-1`) are protected. `utils/medical.py` is an offline list of diseases, symptoms, and medicines, including Parkinson's, bukhar, Dolo, Ramipril, sugar, and bp, plus the Hindi romanizations of those terms. If every real word in a tagged span is on that list, the tag is cancelled before overlap resolution. Doses and units do not count as words. Inside a mixed span, the sanitizer keeps the medical word and replaces the name.

Base64 blobs of sufficient length are decoded as UTF-8. When the decoded text itself contains personal data, the blob is marked as an attachment and removed. JSON keys, CSV headers, and file names pass through the same mask. A file whose name contains a person or an id is renamed to a cleaned stem plus an 8-character hash of the original relative path. The original name is not stored in the report.

Removal is applied after linking. Direct-identifier columns from `config/policy.yaml`, together with a built-in set of name, id, phone, email, address, and date-of-birth columns, are replaced entirely with `[REDACTED]`. Place columns — village, gaon, gram, city, street, pata, mohalla, locality, landmark, house, and address — are wiped the same way. A hospital `ward` column is left alone. Free text loses lines that start with `Address` or `पता`, house-number cues, `Vill` / `Gram` / `ग्राम` cues, a given name before `'s attendant`, a given name before `ka BP`, and `Mohd.` or `Md.` plus a name. A line such as `Ward: 4 (Medicine)` stays. Clinical fields (`medicine`, `dose`, `vital`, `diagnosis`, `bp`, `pulse`, `spo2`, `temperature`, heart rate) are copied unchanged. Keys remain, so the file shape remains. A `doctor_name` column is cleared. A doctor named in prose after `Dr.` stays, because that span was protected at detection time.

## Patient linking and HMAC pseudonyms

Linkage sees the combined record list. For each record it picks one patient name. It ignores relative cues, guardian and attendant fields, doctor and medicine fields, and paths that belong to an organization, a practitioner, or a hospital. A facility string that contains words such as hospital or clinic is dropped. A one-letter stub is dropped. If one record names two people who do not fuzzy-match each other, the linker refuses to choose.

Names are normalized before comparison: Devanagari to ASCII, lower case, punctuation removed, and honorifics stripped (`ji`, `sahab`, `sahib`, `shri`, `shree`, `sri`, `smt`, `shrimati`, `kumari`, `mr`, `mrs`, `ms`, `miss`, `master`, and a few others). Word order does not matter. Each word is scored with `rapidfuzz.fuzz.ratio` against the best unused word on the other side. A single letter is an initial, so `Ramesh K.` matches `Ramesh Kumar`. The name score is the lowest paired word score. An extra unmatched word holds the score under the link threshold, so a shared surname cannot hide `Suresh` versus `Ramesh`.

A score of 80 or higher is a link. A lower score does not link. Records also carry chart keys: a 10-digit mobile, a 12-digit Aadhaar, a 14-digit ABHA, an email, or a hospital number (UHID, MRN, IPD, OPD). The same chart key joins rows even when the name is missing or spelled differently. Disagreeing chart keys keep two people apart, including two patients who share a spelling such as Harish Pandey. A row with no chart number is attached only when exactly one existing cluster fits. Union-Find holds the clusters.

Each cluster receives one pseudonym from `pseudonym/hmac.py`. `patient_id` computes HMAC-SHA256 over the normalized name, with `RAKSHA_SECRET` as the key, and keeps the first 6 hex characters:

```text
PSN- + HMAC-SHA256(RAKSHA_SECRET, normalized_name)[:6]
```

The same normalized name always yields the same id. The id cannot be turned back into the name without the secret. When one spelling belongs to more than one person, the HMAC input is the name plus a chart key, so the ids differ. A cluster that has only a chart key and no name is hashed as `id:` plus that key. A record the linker will not assign stays `patient: null` in `records.jsonl`. Hindi and English forms of the same name share an id only when `to_latin` produces the same ASCII string.

## Privacy techniques

Dates and ages are quasi-identifiers. `privacy/generalize.py` edits them after the pseudonym exists and before redaction.

Every `YYYY-MM-DD` and `DD/MM/YYYY` date on a record moves by the same number of days. The offset is

```text
HMAC-SHA256(RAKSHA_SECRET, "date-shift:" + key)
```

reduced into the closed range −365 to +365 and forced off zero. For a linked patient the key is the `PSN-` id, so every visit for that patient shifts together and the length of a stay stays the same. An unlinked row uses its own date texts as the key. Impossible dates and dose patterns such as `1-0-1` are left as written. The original separator style is kept.

Exact ages in age fields, and phrases such as `age 47` or `47 years old`, become 10-year bands. 47 becomes `40-49`. A value that is already a band is left alone. A bare phrase such as `5 years` can be a disease duration, so that shape is not banded. Ages outside 0–130 stay as written.

Sex, district, and department are listed as quasi-identifiers in `config/policy.yaml`. The current generalizer does not rewrite them. PIN codes are removed as identifiers. The policy asks for k-anonymity of 5 with suppression below that threshold. `privacy/assess.py` is still a stub, so small equivalence classes are not suppressed, and `records_suppressed` in the report is 0.

## Security design

`config/policy.yaml` is loaded on every run. `utils/config.py` refuses to continue unless `offline` is true, `cpu_only` is true, `llm` is false, the scope is `synthetic_indian_hospital_records`, the pseudonym method is `hmac-sha256` with `reversible: false`, and both sanitizer actions are `redact`. `requirements.txt` pins PyYAML and rapidfuzz only. The tree has no HTTP client and no model runtime.

`RAKSHA_SECRET` is required. It keys both the patient id and the date shift. It is read from the environment and is not copied into `sanitized/`, `records.jsonl`, or `report.json`. Anyone who holds the secret can recompute an id from a guessed name and can recover a date offset from a patient id. Use a secret that is unique to the release and store it outside the repository.

The report names inputs by the SHA-256 of the raw bytes. Paths can contain a patient name, so paths are omitted from the report and from stdout. Quarantine reasons are a fixed vocabulary. A partial write that fails is deleted so a broken file is not part of the release. Per-file exceptions are caught. One unreadable export does not abort the batch.

Walkers in detection, generalization, and the sanitizer stop at depth 128. The reader quarantines a deeper JSON file before parsing, so a buried leaf is not copied out unscanned. On Windows, peak resident memory is read through `GetProcessMemoryInfo` with explicit argument types and stored as `resources.peak_rss_mb`.

## Practice-set performance

The latest scored run used the 200-file practice set with `RAKSHA_SECRET=practice-secret`.

| Check | Result |
| --- | --- |
| Leak rate | 0.0% (0 / 3,230). Contract check: **CONTRACT OK**. |
| Channel leaks | Village 0/150, house 0/136, locality 0/103, landmark 0/64, patient name 0/962. Remaining channels 0%. Canaries 0/4. |
| Linking | Precision 1.00, recall 0.77, **F0.5 0.94**, 0 false merges. |
| Clinical retention | 4,550 / 4,855 medical values kept (93.7%). |
| Pipeline | 7 files quarantined, 3,669 detections, 701 records linked, 116 left unset. |

An earlier linker, before the chart-key rules, scored precision 0.85, recall 0.49, and F0.5 0.74, with 6 false merges, at a leak rate of 5.8%. The table above is the current practice-set result.

## Known limitations

k-anonymity is specified in the policy and is not enforced. Small groups that share a sex, a district, and a department can remain. `records_suppressed` does not yet reflect a real suppression pass.

Linking prefers a missed match over a wrong merge. Recall of 0.77 on the practice set means some true pairs stay unlinked and receive a separate id or `null`. A fuzzy score under 80, two equally plausible clusters, or disagreeing chart numbers all produce that outcome.

The pseudonym is 24 bits of the HMAC. That is stable on a ward-sized corpus. A much larger population can collide. The id is a pure function of the normalized name and the secret, so the same name links across releases that share the secret, and a leaked secret makes the id guessable from the name.

The medical protect-list is a fixed vocabulary. Practice retention was 93.7%, so some clinical phrases that look like names are still redacted. A drug or a diagnosis outside the list can be removed when a name pattern matches it. Doctor names written after `Dr.` or `डॉ.` in free text are kept.

Place scrubbing covers the columns and cues listed above. A place written in an unusual sentence, or in a language other than English or Hindi, can remain. Images, PDF, and XML are quarantined rather than parsed, so text inside those formats is not rewritten and is not released as a sanitized body. The quarantine entry is the hash and the status only.

JSON deeper than 128 levels is quarantined as `nesting_too_deep`. The sanitizer does not attempt a partial rewrite of that file.

Date shifting hides the calendar day and keeps intervals. It does not hide the fact that two events were a known number of days apart. Age banding hides the year of age inside a decade. A reader who already knows a rare diagnosis plus a coarse age can still narrow a cohort. This tool reduces direct identifiers in synthetic hospital exports. It is not a formal anonymity proof.

## License

MIT. See [LICENSE](LICENSE).
