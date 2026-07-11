from __future__ import annotations

import json
import tempfile
from pathlib import Path

from support import TestFunc, write
from vibesecurity_report import report_payload, report_sections_from_json, render_report


def test_report_separates_candidates_and_creates_parent_dirs() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        input_path = root / "candidates.json"
        output_path = root / "nested" / "report.md"
        write(
            input_path,
            json.dumps(
                {
                    "candidates": [
                        {
                            "matcher_id": "missing-auth-route-candidate",
                            "path": "src/route.ts",
                            "line": 1,
                            "category": "authz",
                            "snippet_redacted": "export async function GET()",
                            "reason": "Sensitive route.",
                            "review_prompt": "Check auth.",
                        }
                    ]
                }
            ),
        )
        payload = report_payload(input_path, output_path)
        report_exists = output_path.exists()
    report = payload["report_markdown"]
    assert isinstance(report, str)
    assert "## Scope" in report
    assert "## Executive Summary" in report
    assert "## Candidate Findings Requiring Review" in report
    assert "**Attack scenario**" in report
    assert "**Impact**" in report
    assert "## Coverage Notes" in report
    assert "## Follow-Up Recommendations" in report
    assert "## Findings" not in report
    assert report_exists


def test_report_only_confirmed_status_becomes_confirmed_finding() -> None:
    sections = report_sections_from_json(
        {
            "findings": [
                {"status": "confirmed", "title": "Real issue"},
                {"status": "needs-review", "validated": True, "title": "Candidate"},
                {"status": "fixed", "title": "Fixed issue"},
                {"status": "malformed", "title": "Unknown status"},
            ]
        }
    )
    report = render_report(sections)
    assert len(sections.confirmed) == 1
    assert len(sections.resolved) == 1
    assert len(sections.candidates) == 2
    assert "## Confirmed Findings" in report
    assert "Real issue" in report
    assert "## Resolved or Closed Findings" in report
    assert "Fixed issue" in report
    assert "## Candidate Findings Requiring Review" in report
    assert "Candidate" in report
    assert "Unknown status" in report


def test_report_merges_findings_and_top_level_candidates() -> None:
    sections = report_sections_from_json(
        {
            "findings": [{"status": "confirmed", "title": "Confirmed"}],
            "candidates": [
                {"matcher_id": "candidate-signal", "path": "src/route.ts", "line": 3}
            ],
        }
    )
    assert len(sections.confirmed) == 1
    assert len(sections.candidates) == 1
    report = render_report(sections)
    assert "Confirmed" in report
    assert "candidate-signal" in report


def test_report_preserves_scan_coverage_metadata() -> None:
    report = render_report(
        report_sections_from_json(
            {
                "project": {
                    "languages": ["java", "kotlin"],
                    "frameworks": ["spring"],
                    "workflows": ["gitlab-ci"],
                    "package_managers": ["maven"],
                },
                "scope": {
                    "mode": "scan",
                    "files_considered_count": 10,
                    "candidate_files": ["src/AdminController.java"],
                    "files_skipped": [{"path": "dist", "reason": "skipped-directory"}],
                    "rule_packs": ["high-signal", "supply-chain"],
                    "analyzers_run": ["semgrep"],
                    "manual_checks": ["authorization data flow"],
                    "residual_risk": "Runtime-only policy was not available.",
                    "coverage": {
                        "unsupported_or_profile_only": ["kotlin:profile-only"],
                        "optional_adapters": [
                            {
                                "adapter": "ast-grep",
                                "executable": "sg",
                                "available": False,
                            }
                        ],
                    },
                },
                "candidates": [
                    {
                        "matcher_id": "controller-auth",
                        "path": "src/AdminController.java",
                        "line": 7,
                        "category": "authz",
                    }
                ],
            }
        )
    )
    assert (
        "Project profile: languages: java, kotlin; frameworks: spring; workflows: gitlab-ci; package managers: maven"
        in report
    )
    assert (
        "Files reviewed: 10 files considered; candidates in src/AdminController.java"
        in report
    )
    assert "Files skipped: 1 skipped; sample: dist (skipped-directory)" in report
    assert "Rule packs loaded: high-signal, supply-chain" in report
    assert "Unsupported/profile-only surfaces: kotlin:profile-only" in report
    assert "Optional local analyzers: ast-grep:missing" in report
    assert "Analyzers actually run: semgrep" in report
    assert "Manual review checks: authorization data flow" in report
    assert "Residual risk: Runtime-only policy was not available." in report


def test_report_redacts_common_secret_formats() -> None:
    database_url = "".join(
        ("postgres", "://", "user", ":", "rawpass", "@", "db.invalid/db")
    )
    redis_url = "".join(
        ("redis", "://", ":", "password", "@", "cache.invalid:6379/0")
    )
    report = render_report(
        report_sections_from_json(
            {
                "findings": [
                    {
                        "status": "confirmed",
                        "title": "Secret leak",
                        "category": "secrets",
                        "evidence": f"DATABASE_URL={database_url} signing_secret=raw-signing-secret",
                        "attack_scenario": f"Attacker gets {redis_url}",
                        "impact": "client_secret=raw-client-secret and sk-testsecretsecretsecret can be reused.",
                        "recommendation": "Rotate oauth_secret=raw-oauth-secret",
                        "verification": "Check signing_secret=raw-signing-secret",
                    }
                ],
            }
        )
    )
    assert "rawpass" not in report
    assert "raw-signing-secret" not in report
    assert "redis" + "://:" + "password" not in report
    assert "raw-client-secret" not in report
    assert "sk-testsecretsecretsecret" not in report
    assert "raw-oauth-secret" not in report


def test_report_redacts_metadata_fields() -> None:
    credential_path = "src/pathpass/" + "".join(
        ("postgres", "://", "user", ":", "pathpass", "@", "db.invalid/db")
    )
    report = render_report(
        report_sections_from_json(
            {
                "findings": [
                    {
                        "status": "confirmed",
                        "id": "sk-titlefieldsecret1234567890",
                        "title": "titlepass ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
                        "severity": "high sk-severitysecret123456",
                        "confidence": "medium sk-confidencesecret123456",
                        "category": "categorypass client_secret=raw-category-secret",
                        "standard_refs": ["signing_secret=raw-standard-secret"],
                        "affected_files": [
                            {
                                "path": credential_path,
                                "lines": [1],
                            }
                        ],
                    }
                ],
            }
        )
    )
    assert "sk-titlefieldsecret1234567890" not in report
    assert "titlepass" not in report
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in report
    assert "sk-severitysecret123456" not in report
    assert "sk-confidencesecret123456" not in report
    assert "categorypass" not in report
    assert "raw-category-secret" not in report
    assert "raw-standard-secret" not in report
    assert "pathpass" not in report


TESTS: list[TestFunc] = [
    test_report_separates_candidates_and_creates_parent_dirs,
    test_report_only_confirmed_status_becomes_confirmed_finding,
    test_report_merges_findings_and_top_level_candidates,
    test_report_preserves_scan_coverage_metadata,
    test_report_redacts_common_secret_formats,
    test_report_redacts_metadata_fields,
]
