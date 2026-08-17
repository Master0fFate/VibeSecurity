from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from support import SCRIPTS, TestFunc, write

CLI = SCRIPTS / "vibesecurity.py"


def _run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, "-B", str(CLI), *args),
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
        timeout=120,
    )


def test_usage_error_exits_three() -> None:
    result = _run_cli("not-a-command")
    assert result.returncode == 3
    assert json.loads(result.stderr)["error"].startswith("usage:")


def test_missing_root_exits_two() -> None:
    result = _run_cli("scan", "--root", "definitely-not-a-directory-xyz")
    assert result.returncode == 2
    assert "error" in json.loads(result.stderr)


def test_clean_scan_exits_zero_and_reports_gate() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "README.md", "plain project with no findings\n")
        result = _run_cli("scan", "--root", str(root))
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["gate"]["fail_on"] == "none"
    assert payload["gate"]["exit_code"] == 0
    assert payload["baseline"]["loaded"] is False


def test_fail_on_none_never_fails_on_candidates() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "config.py", "aws_key = 'AKIAIOSFODNN7EXAMPLE'\n")
        result = _run_cli("scan", "--root", str(root), "--fail-on", "confirmed")
    assert result.returncode == 0, "candidates alone must not fail the build"
    payload = json.loads(result.stdout)
    assert payload["candidates"], "expected the secret-engine candidate"


def test_verify_missing_findings_exits_two() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "README.md", "x\n")
        result = _run_cli("verify", "--root", str(root), "--input", "missing.json")
    assert result.returncode == 2


def test_scan_sarif_format_is_valid() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "config.py", "aws_key = 'AKIAIOSFODNN7EXAMPLE'\n")
        result = _run_cli("scan", "--root", str(root), "--format", "sarif")
    assert result.returncode == 0
    sarif = json.loads(result.stdout)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "VibeSecurity"
    assert sarif["runs"][0]["results"], "expected sarif results for the planted secret"


TESTS = [
    test_usage_error_exits_three,
    test_missing_root_exits_two,
    test_clean_scan_exits_zero_and_reports_gate,
    test_fail_on_none_never_fails_on_candidates,
    test_verify_missing_findings_exits_two,
    test_scan_sarif_format_is_valid,
]
