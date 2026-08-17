from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, visible_text
from vibesecurity_remediation import findings_from_json
from vibesecurity_scan import scan_payload as _base_scan_payload

VERIFY_TEST_TIMEOUT_SECONDS: Final = 600


def _augmented_scan_payload(root: Path, cache_dir: Path | None, max_age_hours: int) -> JsonMap:
    """Rerun the matcher scan plus SCA over the current tree."""
    payload = _base_scan_payload(root)
    if cache_dir is not None:
        from vibesecurity_sca import sca_candidates
        from vibesecurity_deps import deps_payload
        from vibesecurity_feed import load_advisory_db, provenance_block

        deps = deps_payload(root)
        dependencies = deps.get("dependencies")
        records, warnings = load_advisory_db(cache, max_age_hours)
        provenance = provenance_block(cache, max_age_hours)
        fresh = bool(provenance.get("fresh"))
        sca_items, sca_warnings = sca_candidates(
            dependencies if isinstance(dependencies, list) else [], records, fresh
        )
        payload["candidates"] = [*payload.get("candidates", []), *sca_items]
        payload["warnings"] = [
            *payload.get("scope", {}).get("matcher_warnings", []),
            *warnings,
            *sca_warnings,
        ]
        payload["advisory_db"] = provenance
    return payload


def run_test_command(command: str, root: Path) -> tuple[str, int, str]:
    """Run the user's test command from the repository root."""
    if not command.strip():
        return "skipped", 0, "no test command provided"
    argv = shlex.split(command)
    if not argv:
        return "skipped", 0, "empty test command"
    try:
        result = subprocess.run(
            argv,
            cwd=root,
            capture_output=True,
            timeout=VERIFY_TEST_TIMEOUT_SECONDS,
            text=True,
            errors="replace",
        )
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        return ("passed" if result.returncode == 0 else "failed"), result.returncode, (
            detail[0][:300] if detail else f"exit {result.returncode}"
        )
    except FileNotFoundError:
        return "error", 127, f"command not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return "error", 124, f"test command timed out after {VERIFY_TEST_TIMEOUT_SECONDS}s"


def verify_payload(
    root: Path,
    input_path: Path,
    finding_id: str,
    test_command: str,
    cache_dir: Path | None = None,
    max_age_hours: int = 72,
) -> JsonMap:
    """C3: prove each finding is gone, never claim more than measured."""
    root = root.resolve()
    from vibesecurity_common import load_json_file

    data = load_json_file(input_path)
    findings = findings_from_json(data)
    from vibesecurity_remediation import selected_findings

    selected = selected_findings(findings, finding_id)
    if not selected:
        return {
            "project": {},
            "scope": {"mode": "verify"},
            "verdicts": [],
            "warnings": [f"no finding matched '{visible_text(finding_id, 200)}'"],
            "candidates": [],
        }
    scan = _augmented_scan_payload(root, cache_dir, max_age_hours)
    candidates = scan.get("candidates")
    current_prints = {
        item.get("fingerprint")
        for item in (candidates if isinstance(candidates, list) else [])
        if isinstance(item, dict) and isinstance(item.get("fingerprint"), str)
    }
    unknown_ids = not current_prints
    verdicts: list[JsonMap] = []
    for item in selected:
        fingerprint = item.get("fingerprint")
        item_id = visible_text(
            str(item.get("id", item.get("matcher_id", "unknown"))), 200
        )
        status = visible_text(str(item.get("status", "needs-review")), 50)
        verdict: JsonMap = {"id": item_id, "status": status}
        if not isinstance(fingerprint, str) or not fingerprint:
            verdict["verdict"] = "inconclusive"
            verdict["reason"] = "finding has no fingerprint; rerun the scan that produced it with fingerprinting enabled"
            verdicts.append(verdict)
            continue
        if fingerprint in current_prints:
            verdict["verdict"] = "still-present"
            verdict["reason"] = "fingerprint still appears in the current scan"
            verdicts.append(verdict)
            continue
        if unknown_ids:
            verdict["verdict"] = "inconclusive"
            verdict["reason"] = "current scan produced no fingerprints; scan may have failed"
            verdicts.append(verdict)
            continue
        if test_command.strip():
            outcome, code, detail = run_test_command(test_command, root)
            verdict["test_command"] = visible_text(test_command, 300)
            verdict["test_outcome"] = outcome
            verdict["test_exit_code"] = code
            verdict["test_detail"] = detail
            if outcome == "failed":
                verdict["verdict"] = "test-failed"
                verdict["reason"] = "finding is absent but the test command failed"
            elif outcome == "error":
                verdict["verdict"] = "inconclusive"
                verdict["reason"] = f"test command error: {detail}"
            else:
                verdict["verdict"] = "verified"
                verdict["reason"] = "fingerprint absent and test command passed"
        else:
            verdict["verdict"] = "verified"
            verdict["reason"] = "fingerprint absent from the current scan (no test command supplied)"
        verdicts.append(verdict)
    summary = {
        "verified": sum(1 for item in verdicts if item.get("verdict") == "verified"),
        "still-present": sum(1 for item in verdicts if item.get("verdict") == "still-present"),
        "test-failed": sum(1 for item in verdicts if item.get("verdict") == "test-failed"),
        "inconclusive": sum(1 for item in verdicts if item.get("verdict") == "inconclusive"),
    }
    return {
        "project": {},
        "scope": {"mode": "verify", "finding": finding_id},
        "verdicts": verdicts,
        "summary": summary,
        "warnings": [],
        "candidates": [],
    }
