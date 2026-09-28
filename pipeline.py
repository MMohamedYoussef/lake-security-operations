"""Build the local security event lake, warehouse, and report."""

import argparse
import json
import sys
from pathlib import Path

from src.security import build


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a synthetic security operations data platform")
    parser.add_argument("input_dir", type=Path, help="Directory containing hosts.csv, auth.jsonl, privilege.jsonl")
    parser.add_argument("output_dir", type=Path, help="New directory for the lake, warehouse, and report")
    args = parser.parse_args()
    try:
        metrics = build(args.input_dir, args.output_dir)
    except (ValueError, FileNotFoundError, FileExistsError, OSError) as exc:
        print(f"Security pipeline: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"output": str(args.output_dir), "events": metrics["total_events"], "alerts": metrics["total_alerts"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
