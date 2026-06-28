#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

# How to run:
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly:
#      uv run vibesecurity.py scan --root /path/to/repo
# 3. Or with Python:
#      python vibesecurity.py scan --root /path/to/repo

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vibesecurity_report import report_payload
from vibesecurity_scan import JsonMap, diff_payload, inventory_payload, redact, scan_payload


def command_payload(args: argparse.Namespace) -> JsonMap:
    root = Path(args.root).resolve()
    match args.command:
        case "inventory":
            return inventory_payload(root)
        case "diff":
            return diff_payload(root)
        case "scan":
            return scan_payload(root)
        case "report":
            return report_payload(Path(args.input), Path(args.output) if args.output else None)
        case _:
            raise SystemExit(f"unknown command: {args.command}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vibesecurity.py")
    parser.add_argument("command", choices=["inventory", "diff", "scan", "report"])
    parser.add_argument("--root", default=".", help="Repository root to inspect.")
    parser.add_argument("--input", default=".vibesecurity/findings.json", help="Findings JSON for report rendering.")
    parser.add_argument("--output", default="", help="Optional Markdown report output path.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        payload = command_payload(args)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": redact(str(exc))}), file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
