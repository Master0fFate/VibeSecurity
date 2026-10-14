from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, JsonValue, fingerprint, visible_text
from vibesecurity_standards import standards_block

ANALYZER_COMMANDS: Final[dict[str, tuple[str, ...]]] = {
    "npm-audit": ("npm", "audit", "--json"),
    "pip-audit": ("pip-audit", "--format", "json"),
    "semgrep": ("semgrep", "--json", "."),
    "gitleaks": ("gitleaks", "detect", "--report-format", "json", "--no-banner"),
    "cargo-audit": ("cargo-audit",),
    "govulncheck": ("govulncheck", "./..."),
}
ANALYZER_VERSION_ARGS: Final[dict[str, tuple[str, ...]]] = {
    "npm-audit": ("npm", "--version"),
    "pip-audit": ("pip-audit", "--version"),
    "semgrep": ("semgrep", "--version"),
    "gitleaks": ("gitleaks", "version"),
}
ANALYZER_TIMEOUTS: Final[dict[str, int]] = {
    "npm-audit": 180,
    "pip-audit": 180,
    "semgrep": 300,
    "gitleaks": 180,
    "cargo-audit": 120,
    "govulncheck": 300,
}
SUMMARY_ONLY_ANALYZERS: Final = {"cargo-audit", "govulncheck"}
VERSION_TIMEOUT_SECONDS: Final = 10
MAX_BRIDGE_CANDIDATES: Final = 1_000
CWE_IN_TEXT: Final = re.compile(r"CWE-\d{1,5}")
SEVERITY_MAP: Final = {
    "crit": "critical",
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "info": "info",
    "note": "info",
    "error": "high",
    "warning": "medium",
}


def _normalize_severity(value: str) -> str:
    return SEVERITY_MAP.get(value.strip().lower(), "medium")


def _cwe_from(value: JsonValue) -> str:
    if isinstance(value, str):
        found = CWE_IN_TEXT.findall(value)
        return ", ".join(dict.fromkeys(found[:4]))
    if isinstance(value, list):
        return ", ".join(dict.fromkeys(cwe for item in value for cwe in CWE_IN_TEXT.findall(str(item)))[:4])
    return ""


def _tool_version(name: str) -> str:
    args = ANALYZER_VERSION_ARGS.get(name)
    if not args:
        return ""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=VERSION_TIMEOUT_SECONDS, errors="replace"
        )
        first = (result.stdout or "").strip().splitlines()
        return first[0][:100] if first else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _run(argv: tuple[str, ...], root: Path, timeout: int) -> tuple[int, str, str, bool]:
    try:
        result = subprocess.run(
            argv,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return result.returncode, result.stdout or "", result.stderr or "", False
    except FileNotFoundError:
        return 127, "", f"executable not found: {argv[0]}", True
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s", True


def _bridge_candidate(
    tool: str,
    matcher_id: str,
    path: str,
    line: int,
    snippet: str,
    reason: str,
    prompt: str,
    category: str,
    severity: str,
    confidence: str,
    cwe: str,
    print_parts: tuple[str, ...],
) -> JsonMap:
    return {
        "matcher_id": matcher_id.lower()[:80],
        "rule_pack": "bridge",
        "path": visible_text(path, 500),
        "line": line,
        "snippet_redacted": visible_text(snippet, 300),
        "reason": visible_text(reason, 500),
        "review_prompt": prompt,
        "category": category,
        "severity_hint": severity,
        "confidence_hint": confidence,
        "status": "needs-review",
        "source": "bridge",
        "tool": tool,
        "cwe": cwe,
        "standards": standards_block(cwe, "", "", category),
        "fingerprint": fingerprint("bridge", tool, *print_parts),
    }


def _npm_audit_candidates(stdout: str) -> tuple[list[JsonMap], str]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return [], "npm audit output was not valid JSON"
    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulnerabilities, dict):
        return [], "npm audit JSON had no vulnerabilities object"
    candidates: list[JsonMap] = []
    for name, info in vulnerabilities.items():
        if not isinstance(info, dict):
            continue
        severity = _normalize_severity(str(info.get("severity", "medium")))
        advisory_urls: list[str] = []
        cwe = ""
        via = info.get("via")
        if isinstance(via, list):
            for entry in via:
                if isinstance(entry, dict):
                    url = entry.get("url")
                    if isinstance(url, str) and url:
                        advisory_urls.append(url)
                    if not cwe:
                        cwe = _cwe_from(entry.get("cwe"))
        candidate = _bridge_candidate(
            "npm-audit",
            f"bridge-npm-audit-{name}",
            "package.json",
            0,
            f"npm audit flags {name}",
            f"npm audit reports {severity} severity for {name}",
            "Review the advisory and upgrade per the fixed version it names.",
            "supply-chain",
            severity,
            "medium",
            cwe,
            (name, severity),
        )
        candidate["advisory_urls"] = advisory_urls[:8]
        candidates.append(candidate)
    metadata = data.get("metadata")
    summary = ""
    if isinstance(metadata, dict):
        totals = metadata.get("vulnerabilities")
        if isinstance(totals, dict):
            summary = ", ".join(f"{key}: {value}" for key, value in sorted(totals.items()))
    return candidates, summary


def _pip_audit_candidates(stdout: str) -> tuple[list[JsonMap], str]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return [], "pip-audit output was not valid JSON"
    if not isinstance(data, list):
        return [], "pip-audit JSON was not an array"
    candidates: list[JsonMap] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        version = item.get("version")
        vulns = item.get("vulns")
        if not isinstance(name, str) or not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("id", "unknown"))
            fix_versions = vuln.get("fix_versions")
            candidate = _bridge_candidate(
                "pip-audit",
                f"bridge-pip-audit-{name}",
                "environment",
                0,
                f"{name} {version or '?'} flagged by pip-audit ({vuln_id})",
                f"pip-audit reports {vuln_id} for {name}",
                "Review the advisory and upgrade to a fixed version.",
                "supply-chain",
                "high",
                "medium",
                "",
                (name, vuln_id),
            )
            candidate["advisory_ids"] = [vuln_id]
            candidate["fixed_versions"] = (
                [str(fix) for fix in fix_versions if isinstance(fix, str)]
                if isinstance(fix_versions, list)
                else []
            )
            candidates.append(candidate)
    return candidates, f"{len(candidates)} advisory findings"


def _semgrep_candidates(stdout: str) -> tuple[list[JsonMap], str]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return [], "semgrep output was not valid JSON"
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return [], "semgrep JSON had no results array"
    candidates: list[JsonMap] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("check_id", "unknown"))
        path = str(item.get("path", "unknown"))
        start = item.get("start")
        line = start.get("line", 0) if isinstance(start, dict) else 0
        extra = item.get("extra")
        severity = "medium"
        message = check_id
        cwe = ""
        if isinstance(extra, dict):
            severity = _normalize_severity(str(extra.get("severity", "warning")))
            message = str(extra.get("message", check_id))
            metadata = extra.get("metadata")
            if isinstance(metadata, dict):
                cwe = _cwe_from(metadata.get("cwe"))
        candidates.append(
            _bridge_candidate(
                "semgrep",
                f"bridge-semgrep-{check_id}",
                path,
                line if isinstance(line, int) else 0,
                "semgrep finding (snippet withheld)",
                message,
                "Validate the semgrep finding in context before acting.",
                "other",
                severity,
                "low",
                cwe,
                (check_id, path, str(line)),
            )
        )
    return candidates, f"{len(candidates)} semgrep findings"


def _gitleaks_candidates(stdout: str) -> tuple[list[JsonMap], str]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return [], "gitleaks output was not valid JSON"
    if not isinstance(data, list):
        return [], "gitleaks JSON was not an array"
    candidates: list[JsonMap] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("RuleID", "unknown"))
        path = str(item.get("File", "unknown"))
        start = item.get("StartLine", 0)
        description = str(item.get("Description", "secret detected"))
        candidates.append(
            _bridge_candidate(
                "gitleaks",
                f"bridge-gitleaks-{rule_id}",
                path,
                start if isinstance(start, int) else 0,
                f"{rule_id} match (value withheld)",
                description,
                "Confirm the secret is real without printing it; rotate if exposed.",
                "secrets",
                "high",
                "medium",
                "CWE-798",
                (rule_id, path, str(start)),
            )
        )
    return candidates, f"{len(candidates)} secret findings"


PARSERS = {
    "npm-audit": _npm_audit_candidates,
    "pip-audit": _pip_audit_candidates,
    "semgrep": _semgrep_candidates,
    "gitleaks": _gitleaks_candidates,
}


def run_analyzer(name: str, root: Path) -> JsonMap:
    root = root.resolve()
    command = ANALYZER_COMMANDS.get(name)
    if command is None:
        return {"tool": name, "ran": False, "warning": f"unknown analyzer: {name}"}
    if shutil.which(command[0]) is None:
        return {"tool": name, "ran": False, "warning": f"{command[0]} not found on PATH"}
    if name in SUMMARY_ONLY_ANALYZERS:
        code, _, stderr, failed = _run(command, root, ANALYZER_TIMEOUTS[name])
        return {
            "tool": name,
            "ran": not failed,
            "exit_code": code,
            "summary": "summary-only bridge: exit code recorded; parse output manually for detail",
            "candidates": [],
            "warnings": [visible_text(stderr.strip()[:300], 300)] if failed or code not in (0, 1) else [],
        }
    argv = command
    report_path: Path | None = None
    if name == "gitleaks":
        handle = tempfile.NamedTemporaryFile(
            prefix="vibesec-gitleaks-", suffix=".json", delete=False
        )
        handle.close()
        report_path = Path(handle.name)
        argv = (*command, "--report-path", str(report_path))
    try:
        code, stdout, stderr, failed = _run(argv, root, ANALYZER_TIMEOUTS[name])
        if failed:
            return {
                "tool": name,
                "ran": False,
                "exit_code": code,
                "warning": visible_text(stderr.strip()[:300], 300),
                "candidates": [],
            }
        if report_path is not None:
            try:
                stdout = report_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                stdout = ""
        candidates, summary = PARSERS[name](stdout)
        record: JsonMap = {
            "tool": name,
            "ran": True,
            "tool_version": _tool_version(name) or None,
            "exit_code": code,
            "summary": visible_text(summary, 500),
            "candidates": candidates[:500],
        }
        if code not in (0, 1):
            output = (stderr or stdout).strip()
            record["warning"] = visible_text(
                output.splitlines()[0][:300] if output else f"exit {code}", 300
            )
        return record
    finally:
        if report_path is not None:
            try:
                report_path.unlink()
            except OSError:
                pass


def bridge_payload(root: Path, analyzers: list[str], allowed: tuple[str, ...]) -> JsonMap:
    warnings: list[str] = []
    results: list[JsonMap] = []
    candidates: list[JsonMap] = []
    for name in analyzers:
        if allowed and name not in allowed:
            warnings.append(f"analyzer '{name}' not allowed by policy; skipped")
            continue
        record = run_analyzer(name, root)
        results.append({key: value for key, value in record.items() if key != "candidates"})
        tool_candidates = record.get("candidates")
        if isinstance(tool_candidates, list):
            candidates.extend(item for item in tool_candidates if isinstance(item, dict))
        warning = record.get("warning")
        if isinstance(warning, str):
            warnings.append(f"{name}: {warning}")
    return {
        "project": {},
        "scope": {"mode": "bridge", "analyzers": analyzers},
        "tool_results": results,
        "candidates": candidates[:MAX_BRIDGE_CANDIDATES],
        "warnings": warnings[:100],
    }
