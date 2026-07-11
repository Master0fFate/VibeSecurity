from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vibesecurity_common import JsonMap, visible_text
from vibesecurity_remediation import fix_plan_payload
from vibesecurity_report import report_payload
from vibesecurity_scan import diff_payload, inventory_payload, scan_payload


def root_path(root: Path, value: str) -> Path:
    path = Path(value)
    resolved = (path if path.is_absolute() else root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path must stay within repository root: {value}") from exc
    return resolved


def command_payload(args: argparse.Namespace) -> JsonMap:
    root = Path(args.root).resolve()
    if not root.is_dir():
        raise ValueError(f"repository root is not a directory: {root}")
    match args.command:
        case "inventory":
            return inventory_payload(root)
        case "diff":
            return diff_payload(root)
        case "scan":
            return scan_payload(root)
        case "report":
            return report_payload(
                root_path(root, args.input),
                root_path(root, args.output) if args.output else None,
            )
        case "fix-plan":
            return fix_plan_payload(
                root_path(root, args.input), str(args.finding), bool(args.review_only)
            )
        case _:
            raise SystemExit(f"unknown command: {args.command}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vibesecurity.py")
    parser.add_argument(
        "command", choices=["inventory", "diff", "scan", "report", "fix-plan"]
    )
    parser.add_argument("--root", default=".", help="Repository root to inspect.")
    parser.add_argument(
        "--input",
        default=".vibesecurity/findings.json",
        help="Findings JSON for report rendering.",
    )
    parser.add_argument(
        "--output", default="", help="Optional Markdown report output path."
    )
    parser.add_argument(
        "--finding",
        default="all",
        help="Finding id or matcher id to plan; defaults to all.",
    )
    parser.add_argument(
        "--review-only",
        action="store_true",
        help="Render remediation guidance without patch-ready output.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        payload = command_payload(args)
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": visible_text(str(exc), 1_000)}), file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
