import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.security import build, normalize  # noqa: E402


def write_input(root: Path, auth: list[dict], privilege: list[dict] | None = None) -> Path:
    root.mkdir(parents=True)
    (root / "hosts.csv").write_text(
        "host_id,criticality,team\nweb-1,standard,app\nvault-1,sensitive,security\n",
        encoding="utf-8",
    )
    for name, rows in (("auth.jsonl", auth), ("privilege.jsonl", privilege or [])):
        (root / name).write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
    return root


def auth(event_id: str, minute: int, account: str = "acct-a", host: str = "web-1", outcome: str = "failure") -> dict:
    return {
        "event_id": event_id,
        "occurred_at": f"2026-01-03T10:{minute:02d}:00Z",
        "account": account,
        "host": host,
        "outcome": outcome,
        "source_ip": "192.0.2.10",
    }


def test_five_failures_then_success_at_ten_minute_boundary_alerts_despite_file_order(tmp_path: Path) -> None:
    rows = [auth("success", 10, outcome="success")]
    rows += [auth(f"fail-{i}", i * 2) for i in range(5)]
    events, alerts, rejects, counts = normalize(write_input(tmp_path / "raw", rows))
    assert [event["event_id"] for event in events] == ["fail-0", "fail-1", "fail-2", "fail-3", "fail-4", "success"]
    assert [alert["rule"] for alert in alerts] == ["brute_force_success"]
    assert alerts[0]["event_id"] == "success"
    assert rejects == []
    assert counts["raw_events"] == counts["accepted_events"] == 6


def test_auth_failures_do_not_cross_hosts_or_accounts_and_duplicates_quarantine(tmp_path: Path) -> None:
    rows = [auth(f"a-{i}", i, account="acct-a") for i in range(3)]
    rows += [auth(f"b-{i}", i + 3, account="acct-b") for i in range(2)]
    rows += [auth("success", 7, outcome="success"), auth("a-0", 8), auth("unknown", 9, host="missing")]
    events, alerts, rejects, counts = normalize(write_input(tmp_path / "raw", rows))
    assert alerts == []
    assert len(events) == 6
    assert len(rejects) == 2
    assert {row["reason"] for row in rejects} == {"duplicate_event_id", "unknown_host"}
    assert counts["raw_events"] == counts["accepted_events"] + counts["rejected_events"]


def test_sensitive_privilege_grant_is_independent_alert(tmp_path: Path) -> None:
    privilege = [{
        "event_id": "p1", "occurred_at": "2026-01-03T11:00:00Z", "account": "acct-a",
        "host": "vault-1", "action": "grant", "privilege": "admin",
    }]
    events, alerts, rejects, _ = normalize(write_input(tmp_path / "raw", [], privilege))
    assert len(events) == 1 and not rejects
    assert [(a["rule"], a["severity"], a["event_id"]) for a in alerts] == [
        ("sensitive_privilege_grant", "high", "p1")
    ]


def test_success_within_ten_minutes_of_fifth_failure_still_alerts(tmp_path: Path) -> None:
    rows = [auth(f"f{i}", i) for i in range(5)] + [auth("s", 13, outcome="success")]
    _, alerts, _, _ = normalize(write_input(tmp_path / "raw", rows))
    assert [alert["event_id"] for alert in alerts] == ["s"]


def test_fractional_second_events_sort_by_time_not_iso_text(tmp_path: Path) -> None:
    rows = [auth("exact", 0), auth("fraction", 0, outcome="success")]
    rows[0]["occurred_at"] = "2026-01-03T10:00:00Z"
    rows[1]["occurred_at"] = "2026-01-03T10:00:00.500000Z"
    events, _, _, _ = normalize(write_input(tmp_path / "raw", rows))
    assert [event["event_id"] for event in events] == ["exact", "fraction"]


def test_unrepresentable_utc_timestamp_is_quarantined(tmp_path: Path) -> None:
    bad = auth("bad", 0)
    bad["occurred_at"] = "0001-01-01T00:00:00+01:00"
    events, _, rejects, counts = normalize(write_input(tmp_path / "raw", [auth("good", 1), bad]))
    assert [event["event_id"] for event in events] == ["good"]
    assert [row["reason"] for row in rejects] == ["invalid_timestamp"]
    assert counts["raw_events"] == counts["accepted_events"] + counts["rejected_events"]


def test_blank_and_invalid_utf8_lines_are_quarantined_without_losing_valid_events(tmp_path: Path) -> None:
    raw = write_input(tmp_path / "raw", [auth("good", 0)])
    with (raw / "auth.jsonl").open("ab") as handle:
        handle.write(b"\n\xff\n")
    events, _, rejects, counts = normalize(raw)
    assert [event["event_id"] for event in events] == ["good"]
    assert [(row["line"], row["reason"]) for row in rejects] == [(2, "empty_line"), (3, "invalid_encoding")]
    assert counts == {"raw_events": 3, "accepted_events": 1, "rejected_events": 2}


def test_bronze_is_the_same_snapshot_that_was_normalized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from src import storage

    raw = write_input(tmp_path / "raw", [auth("first", 0)])
    original = (raw / "auth.jsonl").read_bytes()
    real_normalize = storage.normalize

    def mutate_source_after_normalization(path: Path):
        result = real_normalize(path)
        with (raw / "auth.jsonl").open("ab") as handle:
            handle.write((json.dumps(auth("late", 1)) + "\n").encode("utf-8"))
        return result

    monkeypatch.setattr(storage, "normalize", mutate_source_after_normalization)
    output = tmp_path / "output"
    build(raw, output)
    assert (output / "lake" / "bronze" / "auth.jsonl").read_bytes() == original
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["raw_events"] == manifest["counts"]["fact_event"] == 1


def test_empty_event_files_still_write_discoverable_silver_schemas(tmp_path: Path) -> None:
    raw = write_input(tmp_path / "raw", [])
    output = tmp_path / "output"
    metrics = build(raw, output)
    assert metrics["total_events"] == metrics["total_alerts"] == 0
    con = duckdb.connect()
    for layer in ("events", "alerts"):
        files = list((output / "lake" / "silver" / layer).rglob("*.parquet"))
        assert files
        assert con.execute("SELECT count(*) FROM read_parquet(?)", [str(files[0])]).fetchone()[0] == 0
    con.close()


def test_build_creates_reconciled_lake_warehouse_dashboard_and_preserves_existing_output(tmp_path: Path) -> None:
    rows = [auth(f"f{i}", i) for i in range(5)] + [auth("s", 9, outcome="success")]
    rows += [auth("bad", 11, host="missing")]
    raw = write_input(tmp_path / "raw", rows)
    output = tmp_path / "output"
    metrics = build(raw, output)
    assert metrics["total_events"] == 6
    assert metrics["total_alerts"] == 1
    assert metrics["quarantined"] == 1
    assert hashlib.sha256((raw / "auth.jsonl").read_bytes()).digest() == hashlib.sha256(
        (output / "lake" / "bronze" / "auth.jsonl").read_bytes()
    ).digest()
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["counts"]["raw_events"] == 7
    assert manifest["counts"]["accepted_events"] + manifest["counts"]["rejected_events"] == 7
    assert list((output / "lake" / "silver").rglob("*.parquet"))
    con = duckdb.connect(str(output / "warehouse.duckdb"), read_only=True)
    assert con.sql("SELECT count(*) FROM fact_event").fetchone()[0] == 6
    assert con.sql("SELECT count(*) FROM fact_alert").fetchone()[0] == 1
    assert con.sql("SELECT count(*) FROM fact_event e LEFT JOIN dim_host h ON e.host_key=h.host_key WHERE h.host_key IS NULL").fetchone()[0] == 0
    con.close()
    html = (output / "dashboard.html").read_text(encoding="utf-8")
    assert "Brute-force" in html and "vault-1" not in html
    assert "http://" not in html and "https://" not in html
    with pytest.raises(FileExistsError):
        build(raw, output)
    assert json.loads((output / "metrics.json").read_text(encoding="utf-8")) == metrics


def test_cli_and_generator_are_deterministic(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    for dest in (a, b):
        run = subprocess.run(
            [sys.executable, str(ROOT / "generate_data.py"), str(dest), "--seed", "7", "--rows", "100"],
            capture_output=True, text=True,
        )
        assert run.returncode == 0, run.stderr
    assert (a / "auth.jsonl").read_bytes() == (b / "auth.jsonl").read_bytes()
    output = tmp_path / "cli-output"
    run = subprocess.run([sys.executable, str(ROOT / "pipeline.py"), str(a), str(output)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert (output / "warehouse.duckdb").exists()
