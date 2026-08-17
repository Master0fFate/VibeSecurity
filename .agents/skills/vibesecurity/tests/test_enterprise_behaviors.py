from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from datetime import date, timedelta
from pathlib import Path

from support import TestFunc, write
from vibesecurity_baseline import apply_baseline, load_baseline
from vibesecurity_config import load_policy_config, merge_policy
from vibesecurity_pipeline import gate_summary
from vibesecurity_sarif import sarif_from_items, validate_sarif_shape
from vibesecurity_verify import verify_payload
from vibesecurity_scan import scan_payload

GIT = shutil.which("git")


def test_baseline_suppresses_active_and_refires_expired() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        future = (date.today() + timedelta(days=30)).isoformat()
        past = (date.today() - timedelta(days=1)).isoformat()
        write(
            root / ".vibesecurity" / "baseline.json",
            json.dumps(
                {
                    "schema": "vibesecurity-baseline/1",
                    "entries": [
                        {"fingerprint": "active-1", "reason": "tracked risk", "approved_by": "sec-team", "expires_on": future},
                        {"fingerprint": "expired-1", "reason": "old", "approved_by": "sec-team", "expires_on": past},
                    ],
                }
            ),
        )
        baseline = load_baseline(root)
    assert baseline.loaded
    assert "active-1" in baseline.active
    items = [{"fingerprint": "active-1", "status": "confirmed"}, {"fingerprint": "expired-1", "status": "confirmed"}, {"fingerprint": "other", "status": "needs-review"}]
    visible, suppressed, re_fired = apply_baseline(items, baseline)
    assert len(suppressed) == 1 and suppressed[0]["suppressed"] is True
    assert len(re_fired) == 1 and re_fired[0]["suppression_expired"] is True
    assert len(visible) == 2


def test_baseline_failures_never_silence_findings() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / ".vibesecurity" / "baseline.json", "{ not json")
        baseline = load_baseline(root)
    assert not baseline.loaded
    assert baseline.warnings
    visible, suppressed, _ = apply_baseline([{"fingerprint": "x", "status": "confirmed"}], baseline)
    assert len(visible) == 1 and suppressed == []


def test_config_precedence_and_unknown_keys() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(
            root / ".vibesecurity" / "config.json",
            json.dumps(
                {
                    "schema_version": "1",
                    "fail_on": "confirmed-high",
                    "max_cache_age_hours": 24,
                    "unknown_key": True,
                }
            ),
        )
        config = load_policy_config(root)
    assert config.fail_on == "confirmed-high"
    assert config.max_cache_age_hours == 24
    assert any("unknown key" in warning for warning in config.warnings)
    merged = merge_policy(config, fail_on="critical")
    assert merged.fail_on == "critical"
    defaults = load_policy_config(Path(tempfile.mkdtemp()))
    assert defaults.fail_on == "none" and defaults.max_cache_age_hours == 72


def test_gate_summary_exit_codes() -> None:
    critical = [{"status": "confirmed", "severity": "critical"}]
    high = [{"status": "confirmed", "severity": "high"}]
    candidate = [{"status": "needs-review", "severity": "critical"}]
    assert gate_summary(critical, "critical")["exit_code"] == 1
    assert gate_summary(high, "critical")["exit_code"] == 0
    assert gate_summary(high, "confirmed-high")["exit_code"] == 1
    assert gate_summary(candidate, "confirmed")["exit_code"] == 0, "candidates never fail a build"
    assert gate_summary(critical, "none")["exit_code"] == 0


def test_sarif_output_validates() -> None:
    items = [
        {
            "matcher_id": "secret-aws-access-key-id",
            "rule_pack": "secrets",
            "path": "src/config.py",
            "line": 3,
            "severity_hint": "high",
            "status": "confirmed",
            "reason": "aws access key id format",
            "fingerprint": "abc123",
            "source": "secret-engine",
        },
        {
            "matcher_id": "sca-npm-express",
            "rule_pack": "sca",
            "path": "package-lock.json",
            "line": 0,
            "severity_hint": "critical",
            "status": "confirmed",
            "reason": "advisory OSV-TEST-0001",
            "advisory_ids": ["OSV-TEST-0001", "CVE-2024-99999"],
            "kev": True,
            "fingerprint": "def456",
            "source": "advisory",
        },
    ]
    sarif = sarif_from_items(items, {"languages": ["python"]})
    problems = validate_sarif_shape(sarif)
    assert problems == [], problems
    results = sarif["runs"][0]["results"]
    assert results[0]["level"] == "error"
    assert results[0]["partialFingerprints"]["vibesecurityLocator/v1"] == "abc123"
    assert results[1]["properties"]["vibesecurityKev"] is True


def test_verify_harness_verdicts() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "config.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        scan = scan_payload(root)
        candidates = scan["candidates"]
        assert candidates
        live_print = candidates[0]["fingerprint"]
        findings = {
            "findings": [
                {"id": "VSEC-0001", "status": "confirmed", "fingerprint": live_print, "sources": [{"type": "documented-pattern", "id": "aws-access-key-format"}]},
                {"id": "VSEC-0002", "status": "confirmed", "fingerprint": "gone-fingerprint-xyz", "sources": [{"type": "documented-pattern", "id": "aws-access-key-format"}]},
            ]
        }
        findings_path = root / "findings.json"
        write(findings_path, json.dumps(findings))
        still = verify_payload(root, findings_path, "VSEC-0001", "")
        assert still["verdicts"][0]["verdict"] == "still-present"
        gone = verify_payload(root, findings_path, "VSEC-0002", "")
        assert gone["verdicts"][0]["verdict"] == "verified"
        tested = verify_payload(root, findings_path, "VSEC-0002", "python -c pass")
        assert tested["verdicts"][0]["verdict"] == "verified"
        failed = verify_payload(root, findings_path, "VSEC-0002", 'python -c "import sys; sys.exit(1)"')
        assert failed["verdicts"][0]["verdict"] == "test-failed"


def test_git_history_scan_finds_deleted_secret() -> None:
    if GIT is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        env_args = ("-c", "user.email=test@example.invalid", "-c", "user.name=Test")

        def git(*args: str) -> None:
            subprocess.run((GIT, *env_args, *args), cwd=root, check=True, capture_output=True)

        git("init", "-q")
        write(root / "settings.py", "aws_key = 'AKIAIOSFODNN7EXAMPLE'\n")
        git("add", "-A")
        git("commit", "-q", "-m", "add settings")
        (root / "settings.py").unlink()
        git("add", "-A")
        git("commit", "-q", "-m", "remove settings")
        from vibesecurity_history import history_payload

        payload = history_payload(root, window_months=12)
    assert payload["history_hits_count"] >= 1
    hit = payload["history_hits"][0]
    assert hit["only_in_history"] is True
    assert hit["matcher_id"].startswith("secret-")
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(payload)


TESTS = [
    test_baseline_suppresses_active_and_refires_expired,
    test_baseline_failures_never_silence_findings,
    test_config_precedence_and_unknown_keys,
    test_gate_summary_exit_codes,
    test_sarif_output_validates,
    test_verify_harness_verdicts,
    test_git_history_scan_finds_deleted_secret,
]
