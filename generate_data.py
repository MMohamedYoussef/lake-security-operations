"""Create reproducible synthetic authentication and privilege logs."""

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate(output_dir: Path, seed: int, rows: int) -> None:
    if output_dir.exists():
        raise FileExistsError(output_dir)
    if not 1 <= rows <= 100_000:
        raise ValueError("rows must be between 1 and 100000")
    rng = random.Random(seed)
    output_dir.mkdir(parents=True)
    (output_dir / "hosts.csv").write_text(
        "host_id,criticality,team\nweb-1,standard,application\nweb-2,standard,application\nvault-1,sensitive,security\n",
        encoding="utf-8",
    )
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with (output_dir / "auth.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for i in range(rows):
            event_time = start + timedelta(seconds=i * 15)
            cycle = i % 50
            scripted = cycle < 6
            row = {
                "event_id": f"auth-{i:06d}",
                "occurred_at": event_time.isoformat().replace("+00:00", "Z"),
                "account": "demo-operator" if scripted else f"demo-user-{rng.randrange(1, 31):02d}",
                "host": "web-1" if scripted else rng.choice(["web-1", "web-2", "vault-1"]),
                "outcome": ("failure" if cycle < 5 else "success") if scripted else rng.choice(["success"] * 8 + ["failure"] * 2),
                "source_ip": f"192.0.2.{1 + rng.randrange(200)}",
            }
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    with (output_dir / "privilege.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for i in range(0, rows, 80):
            row = {
                "event_id": f"priv-{i:06d}",
                "occurred_at": (start + timedelta(seconds=i * 15 + 5)).isoformat().replace("+00:00", "Z"),
                "account": "demo-admin", "host": "vault-1", "action": "grant", "privilege": "admin",
            }
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic synthetic security logs")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--rows", type=int, default=10_000)
    args = parser.parse_args()
    try:
        generate(args.output_dir, args.seed, args.rows)
    except (ValueError, FileExistsError, OSError) as exc:
        print(f"Generator: {exc}", file=sys.stderr)
        return 2
    print(f"Generated {args.rows} synthetic auth rows in {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
