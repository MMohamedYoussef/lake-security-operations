"""Persist validated security events as a local lake and dimensional warehouse."""

import csv
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

import duckdb

from .dashboard import render_dashboard
from .security import REQUIRED_FILES, _hosts, normalize


def _json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _quote(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _populate_database(path: Path, silver: Path, events: list[dict], alerts: list[dict], hosts: dict[str, dict[str, str]]) -> dict:
    con = duckdb.connect(str(path))
    try:
        con.execute("CREATE TABLE dim_actor(actor_key INTEGER PRIMARY KEY, account VARCHAR UNIQUE NOT NULL)")
        con.execute("CREATE TABLE dim_host(host_key INTEGER PRIMARY KEY, host_id VARCHAR UNIQUE NOT NULL, criticality VARCHAR NOT NULL, team VARCHAR NOT NULL)")
        con.execute("CREATE TABLE dim_date(date_key INTEGER PRIMARY KEY, event_date DATE UNIQUE NOT NULL)")
        con.execute("CREATE TABLE fact_event(event_id VARCHAR PRIMARY KEY, occurred_at TIMESTAMPTZ NOT NULL, date_key INTEGER REFERENCES dim_date(date_key), actor_key INTEGER REFERENCES dim_actor(actor_key), host_key INTEGER REFERENCES dim_host(host_key), event_type VARCHAR NOT NULL, outcome VARCHAR, source_ip VARCHAR, action VARCHAR, privilege VARCHAR)")
        con.execute("CREATE TABLE fact_alert(alert_id VARCHAR PRIMARY KEY, event_id VARCHAR REFERENCES fact_event(event_id), occurred_at TIMESTAMPTZ NOT NULL, date_key INTEGER REFERENCES dim_date(date_key), actor_key INTEGER REFERENCES dim_actor(actor_key), host_key INTEGER REFERENCES dim_host(host_key), rule VARCHAR NOT NULL, severity VARCHAR NOT NULL)")
        actor_keys = {name: i + 1 for i, name in enumerate(sorted({e["account"] for e in events}))}
        host_keys = {name: i + 1 for i, name in enumerate(sorted(hosts))}
        date_keys = {day: int(day.replace("-", "")) for day in sorted({e["occurred_at"][:10] for e in events})}
        con.executemany("INSERT INTO dim_actor VALUES (?, ?)", [(key, account) for account, key in actor_keys.items()]) if actor_keys else None
        con.executemany("INSERT INTO dim_host VALUES (?, ?, ?, ?)", [
            (host_keys[name], name, hosts[name]["criticality"], hosts[name]["team"]) for name in sorted(hosts)
        ])
        con.executemany("INSERT INTO dim_date VALUES (?, ?)", [(key, day) for day, key in date_keys.items()]) if date_keys else None
        if events:
            con.executemany("INSERT INTO fact_event VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
                (
                    e["event_id"], e["occurred_at"], date_keys[e["occurred_at"][:10]],
                    actor_keys[e["account"]], host_keys[e["host"]], e["event_type"], e["outcome"],
                    e["source_ip"], e["action"], e["privilege"],
                ) for e in events
            ])
        if alerts:
            con.executemany("INSERT INTO fact_alert VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [
                (
                    a["alert_id"], a["event_id"], a["occurred_at"], date_keys[a["occurred_at"][:10]],
                    actor_keys[a["account"]], host_keys[a["host"]], a["rule"], a["severity"],
                ) for a in alerts
            ])
        con.execute("CREATE TABLE silver_event(event_date DATE, event_id VARCHAR, occurred_at TIMESTAMPTZ, account VARCHAR, host VARCHAR, event_type VARCHAR, outcome VARCHAR, source_ip VARCHAR, action VARCHAR, privilege VARCHAR)")
        con.execute("CREATE TABLE silver_alert(event_date DATE, alert_id VARCHAR, event_id VARCHAR, occurred_at TIMESTAMPTZ, account VARCHAR, host VARCHAR, rule VARCHAR, severity VARCHAR)")
        if events:
            con.executemany("INSERT INTO silver_event VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
                (
                    e["occurred_at"][:10], e["event_id"], e["occurred_at"], e["account"],
                    e["host"], e["event_type"], e["outcome"], e["source_ip"], e["action"], e["privilege"],
                ) for e in events
            ])
            con.execute(f"COPY (SELECT * FROM silver_event ORDER BY occurred_at, event_id) TO {_quote(silver / 'events')} (FORMAT PARQUET, PARTITION_BY (event_date))")
        else:
            (silver / "events").mkdir()
            con.execute(f"COPY silver_event TO {_quote(silver / 'events' / 'empty.parquet')} (FORMAT PARQUET)")
        if alerts:
            con.executemany("INSERT INTO silver_alert VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [
                (
                    a["occurred_at"][:10], a["alert_id"], a["event_id"], a["occurred_at"],
                    a["account"], a["host"], a["rule"], a["severity"],
                ) for a in alerts
            ])
            con.execute(f"COPY (SELECT * FROM silver_alert ORDER BY occurred_at, alert_id) TO {_quote(silver / 'alerts')} (FORMAT PARQUET, PARTITION_BY (event_date))")
        else:
            (silver / "alerts").mkdir()
            con.execute(f"COPY silver_alert TO {_quote(silver / 'alerts' / 'empty.parquet')} (FORMAT PARQUET)")
        severity = dict(con.execute("SELECT severity, count(*) FROM fact_alert GROUP BY severity ORDER BY severity").fetchall())
        affected = [row[0] for row in con.execute("SELECT DISTINCT h.host_id FROM fact_alert a JOIN dim_host h ON a.host_key=h.host_key ORDER BY h.host_id").fetchall()]
        daily = [{"date": str(day), "alerts": count} for day, count in con.execute(
            "SELECT d.event_date, count(*) FROM fact_alert a JOIN dim_date d ON a.date_key=d.date_key GROUP BY d.event_date ORDER BY d.event_date"
        ).fetchall()]
        rules = dict(con.execute("SELECT rule, count(*) FROM fact_alert GROUP BY rule ORDER BY rule").fetchall())
        return {
            "total_events": con.execute("SELECT count(*) FROM fact_event").fetchone()[0],
            "total_alerts": con.execute("SELECT count(*) FROM fact_alert").fetchone()[0],
            "severity_counts": severity,
            "affected_hosts": affected,
            "daily_alerts": daily,
            "brute_force_alerts": rules.get("brute_force_success", 0),
            "sensitive_privilege_alerts": rules.get("sensitive_privilege_grant", 0),
        }
    finally:
        con.close()


def build(input_dir: Path, output_dir: Path) -> dict:
    input_dir = input_dir.resolve()
    output_dir = output_dir.absolute()
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-stage-", dir=output_dir.parent))
    try:
        bronze = stage / "lake" / "bronze"
        silver = stage / "lake" / "silver"
        bronze.mkdir(parents=True)
        silver.mkdir(parents=True)
        hashes = {}
        for name in REQUIRED_FILES:
            source = input_dir / name
            data = source.read_bytes()
            (bronze / name).write_bytes(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        events, alerts, rejects, counts = normalize(bronze)
        hosts = _hosts(bronze)
        with (stage / "quarantine.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["source", "line", "reason", "raw"], lineterminator="\n")
            writer.writeheader()
            writer.writerows(rejects)
        metrics = _populate_database(stage / "warehouse.duckdb", silver, events, alerts, hosts)
        metrics["quarantined"] = len(rejects)
        _json(stage / "metrics.json", metrics)
        _json(stage / "manifest.json", {
            "inputs_sha256": hashes,
            "counts": {**counts, "fact_event": metrics["total_events"], "fact_alert": metrics["total_alerts"]},
        })
        (stage / "dashboard.html").write_text(render_dashboard(metrics), encoding="utf-8")
        if output_dir.exists():
            raise FileExistsError(output_dir)
        os.rename(stage, output_dir)
        return metrics
    finally:
        if stage.exists() and stage.parent.resolve() == output_dir.parent.resolve():
            shutil.rmtree(stage)
