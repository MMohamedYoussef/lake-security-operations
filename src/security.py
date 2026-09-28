"""Normalize synthetic security logs and derive deterministic alerts."""

import csv
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path


REQUIRED_FILES = ("hosts.csv", "auth.jsonl", "privilege.jsonl")


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid_timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("timezone_required")
    try:
        return parsed.astimezone(timezone.utc)
    except OverflowError as exc:
        raise ValueError("invalid_timestamp") from exc


def _nonempty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid_{field}")
    return value.strip()


def _hosts(input_dir: Path) -> dict[str, dict[str, str]]:
    path = input_dir / "hosts.csv"
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["host_id", "criticality", "team"]:
            raise ValueError("hosts.csv requires host_id,criticality,team header")
        hosts: dict[str, dict[str, str]] = {}
        for row in reader:
            host = _nonempty(row.get("host_id"), "host_id")
            criticality = _nonempty(row.get("criticality"), "criticality")
            team = _nonempty(row.get("team"), "team")
            if host in hosts or criticality not in {"standard", "sensitive"}:
                raise ValueError("invalid or duplicate host inventory")
            hosts[host] = {"criticality": criticality, "team": team}
    if not hosts:
        raise ValueError("hosts.csv is empty")
    return hosts


def normalize(input_dir: Path):
    """Return accepted events, alerts, rejected rows, and reconciliation counts."""
    input_dir = Path(input_dir)
    for name in REQUIRED_FILES:
        if not (input_dir / name).is_file():
            raise FileNotFoundError(input_dir / name)
    hosts = _hosts(input_dir)
    events: list[dict] = []
    rejects: list[dict] = []
    seen_ids: set[str] = set()
    raw_count = 0
    for name, kind in (("auth.jsonl", "auth"), ("privilege.jsonl", "privilege")):
        with (input_dir / name).open("rb") as handle:
            for line_number, raw_line in enumerate(handle, 1):
                raw_count += 1
                try:
                    line = raw_line.decode("utf-8-sig" if line_number == 1 else "utf-8")
                except UnicodeDecodeError:
                    rejects.append({
                        "source": name, "line": line_number, "reason": "invalid_encoding",
                        "raw": raw_line.decode("utf-8", errors="replace").rstrip("\r\n"),
                    })
                    continue
                if not line.strip():
                    rejects.append({
                        "source": name, "line": line_number, "reason": "empty_line", "raw": "",
                    })
                    continue
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError("invalid_json_object")
                    event_id = _nonempty(row.get("event_id"), "event_id")
                    if event_id in seen_ids:
                        raise ValueError("duplicate_event_id")
                    instant = _timestamp(row.get("occurred_at"))
                    account = _nonempty(row.get("account"), "account")
                    host = _nonempty(row.get("host"), "host")
                    if host not in hosts:
                        raise ValueError("unknown_host")
                    event = {
                        "event_id": event_id,
                        "occurred_at": instant.isoformat().replace("+00:00", "Z"),
                        "account": account,
                        "host": host,
                        "event_type": kind,
                        "outcome": "",
                        "source_ip": "",
                        "action": "",
                        "privilege": "",
                    }
                    if kind == "auth":
                        outcome = _nonempty(row.get("outcome"), "outcome")
                        if outcome not in {"failure", "success"}:
                            raise ValueError("invalid_outcome")
                        event["outcome"] = outcome
                        event["source_ip"] = _nonempty(row.get("source_ip"), "source_ip")
                    else:
                        action = _nonempty(row.get("action"), "action")
                        if action not in {"grant", "revoke"}:
                            raise ValueError("invalid_action")
                        event["action"] = action
                        event["privilege"] = _nonempty(row.get("privilege"), "privilege")
                    seen_ids.add(event_id)
                    events.append(event)
                except (ValueError, TypeError, json.JSONDecodeError) as exc:
                    rejects.append({
                        "source": name,
                        "line": line_number,
                        "reason": str(exc) if isinstance(exc, ValueError) else "invalid_json",
                        "raw": line.rstrip("\r\n"),
                    })
    events.sort(key=lambda e: (_timestamp(e["occurred_at"]), e["event_id"]))
    alerts: list[dict] = []
    failures: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
    window = timedelta(minutes=10)
    for event in events:
        instant = _timestamp(event["occurred_at"])
        key = (event["account"], event["host"])
        if event["event_type"] == "auth":
            recent = failures[key]
            if event["outcome"] == "failure":
                while recent and instant - recent[0] > window:
                    recent.popleft()
                recent.append(instant)
            else:
                if len(recent) >= 5 and instant - recent[-1] <= window:
                    alerts.append({
                        "alert_id": f"brute:{event['event_id']}", "event_id": event["event_id"],
                        "occurred_at": event["occurred_at"], "account": event["account"],
                        "host": event["host"], "rule": "brute_force_success", "severity": "high",
                    })
                recent.clear()
        elif event["action"] == "grant" and event["privilege"] == "admin" and hosts[event["host"]]["criticality"] == "sensitive":
            alerts.append({
                "alert_id": f"priv:{event['event_id']}", "event_id": event["event_id"],
                "occurred_at": event["occurred_at"], "account": event["account"],
                "host": event["host"], "rule": "sensitive_privilege_grant", "severity": "high",
            })
    counts = {"raw_events": raw_count, "accepted_events": len(events), "rejected_events": len(rejects)}
    return events, alerts, rejects, counts


def build(input_dir: Path, output_dir: Path):
    from .storage import build as persist

    return persist(Path(input_dir), Path(output_dir))
