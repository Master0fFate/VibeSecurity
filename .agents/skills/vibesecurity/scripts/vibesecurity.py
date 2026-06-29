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

from vibesecurity_common import JsonMap, redact
from vibesecurity_remediation import fix_plan_payload
from vibesecurity_report import report_payload
from vibesecurity_scan import diff_payload, inventory_payload, scan_payload


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
        case "fix-plan":
            return fix_plan_payload(Path(args.input), str(args.finding), bool(args.review_only))
        case _:
            raise SystemExit(f"unknown command: {args.command}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vibesecurity.py")
    parser.add_argument("command", choices=["inventory", "diff", "scan", "report", "fix-plan"])
    parser.add_argument("--root", default=".", help="Repository root to inspect.")
    parser.add_argument("--input", default=".vibesecurity/findings.json", help="Findings JSON for report rendering.")
    parser.add_argument("--output", default="", help="Optional Markdown report output path.")
    parser.add_argument("--finding", default="all", help="Finding id or matcher id to plan; defaults to all.")
    parser.add_argument("--review-only", action="store_true", help="Render remediation guidance without patch-ready output.")
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
