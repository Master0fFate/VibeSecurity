from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vibesecurity_common import (
    EXIT_CLEAN,
    EXIT_FINDINGS,
    EXIT_TOOL_ERROR,
    EXIT_USAGE,
    JsonMap,
    VIBESEC_VERSION,
    visible_text,
)
from vibesecurity_config import PolicyConfig, load_policy_config, merge_policy
from vibesecurity_remediation import fix_plan_payload
from vibesecurity_report import report_payload
from vibesecurity_scan import diff_payload, inventory_payload
from vibesecurity_sarif import sarif_from_items, validate_sarif_shape
from vibesecurity_verify import verify_payload

COMMANDS = (
    "inventory",
    "diff",
    "scan",
    "report",
    "fix-plan",
    "deps",
    "feed",
    "sca",
    "history",
    "verify",
    "baseline",
)


def root_path(root: Path, value: str) -> Path:
    path = Path(value)
    resolved = (path if path.is_absolute() else root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path must stay within repository root: {value}") from exc
    return resolved


def sarif_from_scan(payload: JsonMap) -> JsonMap:
    items = [
        item
        for item in (payload.get("candidates") or [])
        if isinstance(item, dict)
    ]
    return sarif_from_items(items, payload.get("project") if isinstance(payload.get("project"), dict) else None)


def command_payload(args: argparse.Namespace, config: PolicyConfig | None = None) -> JsonMap:
    root = Path(args.root).resolve()
    if not root.is_dir():
        raise ValueError(f"repository root is not a directory: {root}")
    if config is None:
        config = load_policy_config(root)
        config = merge_policy(config, network_enabled=False if args.offline else None, fail_on=args.fail_on)
    cache_override = Path(args.cache_dir).resolve() if args.cache_dir else None
    match args.command:
        case "inventory":
            return inventory_payload(root)
        case "diff":
            return diff_payload(root)
        case "scan":
            from vibesecurity_pipeline import enriched_scan_payload

            return enriched_scan_payload(
                root,
                config,
                advisory_source=Path(args.advisory_db).resolve() if args.advisory_db else None,
                analyzers=[name.strip() for name in (args.run_analyzers or "").split(",") if name.strip()],
                cache_dir=cache_override,
            )
        case "report":
            return report_payload(
                root_path(root, args.input),
                root_path(root, args.output) if args.output else None,
            )
        case "fix-plan":
            return fix_plan_payload(
                root_path(root, args.input), str(args.finding), bool(args.review_only)
            )
        case "deps":
            from vibesecurity_deps import deps_payload

            return deps_payload(root)
        case "feed":
            from vibesecurity_feed import (
                cache_dir as default_cache_dir,
                export_bundle,
                feed_refresh_payload,
                feed_status_payload,
                import_bundle,
            )

            directory = cache_override if cache_override is not None else default_cache_dir(root)
            match args.action:
                case "refresh":
                    return feed_refresh_payload(
                        root, directory, config.network_enabled, config.registry_lookups
                    )
                case "status":
                    return feed_status_payload(directory, config.max_cache_age_hours)
                case "export":
                    output = Path(args.bundle).resolve() if args.bundle else directory.parent / "advisory-bundle.json"
                    return export_bundle(directory, output)
                case "import":
                    if not args.bundle:
                        raise ValueError("feed import requires --bundle")
                    return import_bundle(Path(args.bundle).resolve(), directory)
                case _:
                    raise ValueError(f"unknown feed action: {args.action}")
        case "sca":
            from vibesecurity_deps import deps_payload
            from vibesecurity_feed import provenance_block
            from vibesecurity_pipeline import default_advisory_source, resolve_advisory_records
            from vibesecurity_sca import sca_candidates

            source = Path(args.advisory_db).resolve() if args.advisory_db else default_advisory_source(root, cache_override)
            records, warnings, bundle_provenance = resolve_advisory_records(source)
            deps = deps_payload(root)
            dependencies = deps.get("dependencies")
            if bundle_provenance is not None:
                provenance = bundle_provenance
                fresh = True
            else:
                provenance = (
                    provenance_block(source, config.max_cache_age_hours) if source else {}
                )
                fresh = bool(provenance.get("fresh"))
            candidates, sca_warnings = sca_candidates(
                dependencies if isinstance(dependencies, list) else [], records, fresh
            )
            return {
                "project": {},
                "scope": {"mode": "sca", "advisory_db": provenance},
                "advisory_db": provenance,
                "candidates": candidates,
                "warnings": [*warnings, *sca_warnings][:100],
            }
        case "history":
            from vibesecurity_history import history_payload

            return history_payload(root, config.history_window_months, bool(args.all_refs))
        case "verify":
            return verify_payload(
                root,
                root_path(root, args.input),
                str(args.finding),
                str(args.test_cmd or ""),
                cache_dir=cache_override,
                max_age_hours=config.max_cache_age_hours,
            )
        case "baseline":
            from vibesecurity_baseline import baseline_payload

            return baseline_payload(root, config.baseline_max_age_days)
        case _:
            raise ValueError(f"unknown command: {args.command}")


def build_parser() -> argparse.ArgumentParser:
    parser = UsageParser(prog="vibesecurity.py")
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("action", nargs="?", default="", help="feed subaction")
    parser.add_argument("--root", default=".", help="Repository root to inspect.")
    parser.add_argument(
        "--input",
        default=".vibesecurity/findings.json",
        help="Findings JSON for report, fix-plan, and verify.",
    )
    parser.add_argument(
        "--output", default="", help="Optional Markdown report output path."
    )
    parser.add_argument(
        "--finding",
        default="all",
        help="Finding id or matcher id for fix-plan and verify; defaults to all.",
    )
    parser.add_argument(
        "--review-only",
        action="store_true",
        help="Render remediation guidance without patch-ready output.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "confirmed", "confirmed-high", "critical"],
        default=None,
        help="Exit 1 when findings meet the threshold (scan/report/verify). Default: config or none.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "sarif"],
        default="json",
        help="Output format for scan and report.",
    )
    parser.add_argument(
        "--advisory-db",
        default="",
        help="Advisory cache directory or exported bundle file for scan/sca/verify (default: .vibesecurity/cache when present).",
    )
    parser.add_argument(
        "--cache-dir",
        default="",
        help="Override the advisory cache directory (default .vibesecurity/cache).",
    )
    parser.add_argument(
        "--run-analyzers",
        default="",
        help="Comma-separated analyzers to execute (npm-audit, pip-audit, semgrep, gitleaks, cargo-audit, govulncheck).",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Disable network access for feed refresh regardless of config.",
    )
    parser.add_argument(
        "--bundle",
        default="",
        help="Bundle path for feed export/import.",
    )
    parser.add_argument(
        "--all-refs",
        action="store_true",
        help="Scan all refs in history mode.",
    )
    parser.add_argument(
        "--test-cmd",
        default="",
        help="Test command run by verify after confirming findings are gone.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"VibeSecurity {VIBESEC_VERSION}",
    )
    return parser


class UsageParser(argparse.ArgumentParser):
    """Usage errors exit 3, distinct from tool errors (2) and findings (1)."""

    def error(self, message: str):  # type: ignore[override]
        print(json.dumps({"error": f"usage: {message}"}), file=sys.stderr)
        raise SystemExit(EXIT_USAGE)


def _exit_code_for(args: argparse.Namespace, payload: JsonMap, fail_on: str) -> int:
    if args.command == "scan":
        gate = payload.get("gate")
        if isinstance(gate, dict) and fail_on != "none":
            return int(gate.get("exit_code", EXIT_CLEAN))
        return EXIT_CLEAN
    if args.command == "verify":
        summary = payload.get("summary")
        if isinstance(summary, dict):
            still = summary.get("still-present", 0)
            failed = summary.get("test-failed", 0)
            if fail_on != "none" and (still or failed):
                return EXIT_FINDINGS
        return EXIT_CLEAN
    if args.command == "report" and fail_on != "none":
        from vibesecurity_pipeline import gate_summary
        from vibesecurity_report import report_sections_from_json
        from vibesecurity_common import load_json_file

        try:
            sections = report_sections_from_json(load_json_file(Path(args.input)))
            gate = gate_summary([*sections.confirmed, *sections.candidates], fail_on)
            payload["gate"] = gate
            return int(gate.get("exit_code", EXIT_CLEAN))
        except (OSError, ValueError):
            return EXIT_CLEAN
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        root = Path(args.root).resolve()
        config = load_policy_config(root)
        config = merge_policy(
            config,
            network_enabled=False if args.offline else None,
            fail_on=args.fail_on,
        )
        payload = command_payload(args, config)
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": visible_text(str(exc), 1_000)}), file=sys.stderr)
        return EXIT_TOOL_ERROR
    if args.format == "sarif" and args.command in {"scan", "report"}:
        if args.command == "scan":
            rendered = sarif_from_scan(payload)
        else:
            from vibesecurity_sarif import sarif_payload

            rendered = sarif_payload(root_path(root, args.input))
        problems = validate_sarif_shape(rendered)
        if problems:
            print(
                json.dumps({"error": "sarif validation failed", "problems": problems}),
                file=sys.stderr,
            )
            return EXIT_TOOL_ERROR
        print(json.dumps(rendered, indent=2, sort_keys=True))
        return EXIT_CLEAN
    print(json.dumps(payload, indent=2, sort_keys=True))
    return _exit_code_for(args, payload, config.fail_on)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except argparse.ArgumentError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        raise SystemExit(EXIT_USAGE)
