# Security Operations Lake + Warehouse

A reproducible, local-first security analytics platform. It correlates synthetic authentication and privilege events by **event time**, quarantines invalid records, stores clean events as Parquet, loads a dimensional DuckDB warehouse, and renders an offline detection dashboard. This is a data-engineering and detection-rule demonstration, not a production SIEM.

## Run

Requires Python 3.13 and DuckDB. From this repository:

```powershell
python -m pip install -r requirements.txt
python -m pytest tests -q
python pipeline.py fixtures/raw run-output
```

`run-output` must **not** exist; the CLI never overwrites a previous run. Open `run-output/dashboard.html` in a browser. The checked-in [dashboard](examples/dashboard.html) and [metrics](examples/metrics.json) were generated from the small synthetic fixture. To create a larger, repeatable dataset:

```powershell
python generate_data.py synthetic-input --seed 42 --rows 10000
python pipeline.py synthetic-input synthetic-output
```

The generator refuses to replace an existing directory. It creates only fictional accounts and [documentation-range](https://www.rfc-editor.org/rfc/rfc5737) IP addresses; no real identities, secrets, or network calls are needed.

## Data flow

```text
auth.jsonl + privilege.jsonl + hosts.csv
  → bronze/  original bytes + SHA-256 lineage
  → validation + event-time correlation + quarantine.csv
  → silver/  date-partitioned events and alerts (Parquet)
  → warehouse.duckdb  star schema + warehouse queries
  → metrics.json + standalone dashboard.html
```

| Layer | Contents | Check |
|---|---|---|
| Bronze | Byte-for-byte copies of the three input files | `manifest.json.inputs_sha256` |
| Silver | Normalized events and alerts partitioned by `event_date` | Query with DuckDB or any Parquet reader |
| Quarantine | Malformed, blank, invalid-encoding, duplicate-ID, and unknown-host event rows with reasons | Raw = accepted + rejected |
| Warehouse | `fact_event`, `fact_alert`, `dim_actor`, `dim_host`, `dim_date` | Primary/foreign keys and reconciliation tests |
| Report | Alert counts, affected hosts, rule mix, timeline | SQL-derived metrics; no CDN or server |

Each JSONL auth row needs `event_id`, timezone-aware `occurred_at`, `account`, `host`, `outcome` (`failure`/`success`), and `source_ip`. Each privilege row needs `event_id`, `occurred_at`, `account`, `host`, `action` (`grant`/`revoke`), and `privilege`. `hosts.csv` gives `host_id,criticality,team`; `criticality` is `standard` or `sensitive`. Missing required files or an invalid inventory header stop the run. Invalid individual event rows are quarantined so valid rows still flow through.

The brute-force rule creates one alert when an account has **five failures on one host within ten minutes**, followed by a success within ten minutes of the final failure. A success clears that account/host window. A grant of `admin` privilege on a `sensitive` host creates a separate alert. Events are sorted by parsed UTC instants before rule evaluation, so file arrival order does not change results. This simple rule may produce false positives and does not replace investigation.

## Reproducibility and limits

`manifest.json` records SHA-256 inputs and reconciliation counts. The pipeline snapshots the three source files into bronze before parsing them, so the hashes, facts, and quarantine all describe the same run. Every output directory is assembled beside its final path before being published. Empty event streams still get schema-bearing Parquet files. The fixture generates 13 accepted events, two quarantined rows, and two alerts. Tests cover corrected event ordering, exact rule boundaries, account/host isolation, invalid records, warehouse integrity, protected output paths, and generator repeatability.

This demonstration loads one run into memory and creates one local DuckDB database per output directory. It does not provide continuous ingestion, distributed writes, real-time notifications, geolocation, or a calibrated false-positive model. The synthetic `dim_actor` is an analytical dimension, not an identity directory.
