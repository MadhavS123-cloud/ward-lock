# WARD-LOCK

Offline privacy firewall for hospital records.

The pipeline reads and writes local files only. It does not call the network or any language model.

```text
pip install -r requirements.txt
python main.py --input input_folder --output output_folder
```

The output folder holds `sanitized/` (cleaned files, same layout), `report.json` (file hashes, counts, and timing), and `records.jsonl` (one line per record, with the patient id).

`config/policy.yaml` lists direct identifiers, quasi-identifiers, and the k-anonymity bar.

Stages, in order: ingestion, detection, linkage, pseudonym, privacy, sanitizer.
