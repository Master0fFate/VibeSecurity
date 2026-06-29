from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
FIXTURES = SKILL_ROOT / "tests" / "fixtures"
sys.path.insert(0, str(SCRIPTS))

from vibesecurity_report import report_payload, report_sections_from_json, render_report
from vibesecurity_remediation import fix_plan_payload
from vibesecurity_scan import diff_payload, glob_matches, inventory_payload, scan_payload


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_fixture_scan_emits_review_candidates() -> None:
    payload = scan_payload(FIXTURES)
    candidates = payload["candidates"]
    assert isinstance(candidates, list)
    pairs = {(item["matcher_id"], item["path"]) for item in candidates if isinstance(item, dict)}
    assert ("missing-auth-route-candidate", "nextjs-bad-route/src/app/api/admin/users/route.ts") in pairs
    assert ("missing-auth-route-candidate", "fastapi-bad-auth/main.py") in pairs
    assert ("ai-output-to-shell", "llm-tool-bad-shell/agent.py") in pairs
    assert ("github-actions-pr-target", "gha-bad-workflow/.github/workflows/pr.yml") in pairs
    assert all(isinstance(item, dict) and item.get("status") == "needs-review" for item in candidates)
    assert all(isinstance(item, dict) and item.get("review_prompt") for item in candidates)


def test_nearby_terms_use_line_window() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "far" / "route.ts", "export async function GET() {\n  return Response.json({ ok: true });\n}\n" + "\n" * 8 + "const users = [];\n")
        write(root / "near" / "route.ts", "export async function GET() {\n  const users = [];\n  return Response.json(users);\n}\n")

        candidates = scan_payload(root)["candidates"]
        paths = {item["path"] for item in candidates if isinstance(item, dict)}

    assert "near/route.ts" in paths
    assert "far/route.ts" not in paths


def test_scan_reports_skips_and_truncation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "image.bin", "\x00binary")
        for index in range(205):
            write(root / f"secrets-{index}.txt", f"api_key=sk-test-{index:024d}\n")

        payload = scan_payload(root)

    assert payload["truncated"] is True
    assert payload["candidate_limit"] == 200
    assert payload["candidates_returned"] == 200
    skipped = payload["scope"]["files_skipped"]
    assert isinstance(skipped, list)
    assert any(isinstance(item, dict) and item.get("reason") == "unsupported-file-type" for item in skipped)


def test_env_snippets_redact_values() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / ".env", "api_key=sk-test-secret-value-1234567890\n")

        candidates = scan_payload(root)["candidates"]

    assert isinstance(candidates, list)
    assert candidates
    first = candidates[0]
    assert isinstance(first, dict)
    assert first["snippet_redacted"] == "api_key=<redacted>"


def test_inventory_prefers_manifest_and_route_patterns() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "README.md", "This doc mentions fastapi but does not use it.\n")
        write(root / "package.json", json.dumps({"dependencies": {"next": "1.0.0", "react": "1.0.0"}}))
        write(root / "src" / "app" / "users" / "route.ts", "export async function GET() { return Response.json({}); }\n")

        payload = inventory_payload(root)

    project = payload["project"]
    assert isinstance(project, dict)
    assert project["frameworks"] == ["nextjs", "react"]
    assert project["route_files"] == ["src/app/users/route.ts"]


def test_diff_reports_git_warnings_outside_repo() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        payload = diff_payload(Path(tmp))

    warnings = payload["warnings"]
    assert isinstance(warnings, list)
    assert warnings
    assert all(isinstance(item, str) and "git " in item for item in warnings)


def test_report_separates_candidates_and_creates_parent_dirs() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        input_path = root / "candidates.json"
        output_path = root / "nested" / "report.md"
        write(input_path, json.dumps({"candidates": [{"matcher_id": "missing-auth-route-candidate", "path": "src/route.ts", "line": 1, "category": "authz", "snippet_redacted": "export async function GET()", "reason": "Sensitive route.", "review_prompt": "Check auth."}]}))

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
    sections = report_sections_from_json({"findings": [{"status": "confirmed", "title": "Real issue"}, {"status": "needs-review", "validated": True, "title": "Candidate"}, {"status": "fixed", "title": "Fixed issue"}]})
    report = render_report(sections)

    assert len(sections.confirmed) == 1
    assert len(sections.resolved) == 1
    assert len(sections.candidates) == 1
    assert "## Confirmed Findings" in report
    assert "Real issue" in report
    assert "## Resolved or Closed Findings" in report
    assert "Fixed issue" in report
    assert "## Candidate Findings Requiring Review" in report
    assert "Candidate" in report


def test_report_merges_findings_and_top_level_candidates() -> None:
    sections = report_sections_from_json({
        "findings": [{"status": "confirmed", "title": "Confirmed"}],
        "candidates": [{"matcher_id": "candidate-signal", "path": "src/route.ts", "line": 3}],
    })

    assert len(sections.confirmed) == 1
    assert len(sections.candidates) == 1
    report = render_report(sections)
    assert "Confirmed" in report
    assert "candidate-signal" in report


def test_report_redacts_common_secret_formats() -> None:
    report = render_report(report_sections_from_json({
        "findings": [{
            "status": "confirmed",
            "title": "Secret leak",
            "category": "secrets",
            "evidence": "DATABASE_URL=postgres://user:rawpass@example.invalid/db signing_secret=raw-signing-secret",
            "attack_scenario": "Attacker gets redis://:password@example.invalid:6379/0",
            "impact": "client_secret=raw-client-secret and sk-testsecretsecretsecret can be reused.",
            "recommendation": "Rotate oauth_secret=raw-oauth-secret",
            "verification": "Check signing_secret=raw-signing-secret",
        }],
    }))

    assert "rawpass" not in report
    assert "raw-signing-secret" not in report
    assert "redis://:password" not in report
    assert "raw-client-secret" not in report
    assert "sk-testsecretsecretsecret" not in report
    assert "raw-oauth-secret" not in report
    assert "raw-signing-secret" not in report


def test_report_redacts_metadata_fields() -> None:
    report = render_report(report_sections_from_json({
        "findings": [{
            "status": "confirmed",
            "id": "sk-titlefieldsecret1234567890",
            "title": "titlepass ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
            "severity": "high sk-severitysecret123456",
            "confidence": "medium sk-confidencesecret123456",
            "category": "categorypass client_secret=raw-category-secret",
            "standard_refs": ["signing_secret=raw-standard-secret"],
            "affected_files": [{"path": "src/pathpass/postgres://user:pathpass@example.invalid/db", "lines": [1]}],
        }],
    }))

    assert "sk-titlefieldsecret1234567890" not in report
    assert "titlepass" not in report
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in report
    assert "sk-severitysecret123456" not in report
    assert "sk-confidencesecret123456" not in report
    assert "categorypass" not in report
    assert "raw-category-secret" not in report
    assert "raw-standard-secret" not in report
    assert "pathpass" not in report


def test_fix_plan_requires_confirmed_findings() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "findings.json"
        write(input_path, json.dumps({
            "findings": [
                {"id": "VSEC-0001", "status": "confirmed", "category": "authz", "title": "Missing object authorization", "verification": "Denied user gets 403."},
                {"id": "VSEC-0002", "status": "needs-review", "category": "ssrf", "title": "Candidate fetch"},
            ],
            "candidates": [{"matcher_id": "possible-secret-literal", "status": "needs-review", "category": "secrets"}],
        }))

        payload = fix_plan_payload(input_path, "all", False)

    patch_ready = payload["patch_ready"]
    blocked = payload["blocked"]
    assert isinstance(patch_ready, list)
    assert isinstance(blocked, list)
    assert len(patch_ready) == 1
    assert len(blocked) == 2
    first = patch_ready[0]
    assert isinstance(first, dict)
    assert first["id"] == "VSEC-0001"
    assert first["patch_allowed"] is True
    assert "authorized" in str(first["security_invariant"]).lower()


def test_fix_plan_review_only_blocks_patch_ready_output() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "findings.json"
        write(input_path, json.dumps({"findings": [{"id": "VSEC-0001", "status": "confirmed", "category": "ai-agentic", "title": "Unsafe tool use"}]}))

        payload = fix_plan_payload(input_path, "VSEC-0001", True)

    assert payload["patch_ready"] == []
    review_items = payload["review_items"]
    assert isinstance(review_items, list)
    assert len(review_items) == 1
    first = review_items[0]
    assert isinstance(first, dict)
    assert first["patch_allowed"] is False


def test_symlinks_are_skipped_when_supported() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        root.mkdir()
        target = Path(tmp) / "outside-secret.txt"
        target.write_text("api_key=sk-outside-secret-1234567890\n", encoding="utf-8")
        link = root / "linked-secret.txt"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            return

        payload = scan_payload(root)

    assert payload["candidates_returned"] == 0
    skipped = payload["scope"]["files_skipped"]
    assert isinstance(skipped, list)
    assert any(isinstance(item, dict) and item.get("path") == "linked-secret.txt" and item.get("reason") in {"symlink", "outside-root"} for item in skipped)


def test_local_vibesecurity_state_is_skipped() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / ".vibesecurity" / "findings.json", "api_key=sk-local-state-secret-1234567890\n")
        write(root / "src" / "safe.txt", "hello\n")

        payload = scan_payload(root)

    assert payload["candidates_returned"] == 0
    skipped = payload["scope"]["files_skipped"]
    assert isinstance(skipped, list)
    assert any(isinstance(item, dict) and item.get("path") == ".vibesecurity" and item.get("reason") == "skipped-directory" for item in skipped)


def test_glob_matches_middle_double_star_without_directory() -> None:
    assert glob_matches("pages/api/users.ts", "**/pages/api/**/*.ts")
    assert glob_matches("src/pages/api/admin/users.ts", "**/pages/api/**/*.ts")
    assert not glob_matches("pages/app/users.ts", "**/pages/api/**/*.ts")


def main() -> int:
    tests = [
        test_fixture_scan_emits_review_candidates,
        test_nearby_terms_use_line_window,
        test_scan_reports_skips_and_truncation,
        test_env_snippets_redact_values,
        test_inventory_prefers_manifest_and_route_patterns,
        test_diff_reports_git_warnings_outside_repo,
        test_report_separates_candidates_and_creates_parent_dirs,
        test_report_only_confirmed_status_becomes_confirmed_finding,
        test_report_merges_findings_and_top_level_candidates,
        test_report_redacts_common_secret_formats,
        test_report_redacts_metadata_fields,
        test_fix_plan_requires_confirmed_findings,
        test_fix_plan_review_only_blocks_patch_ready_output,
        test_symlinks_are_skipped_when_supported,
        test_local_vibesecurity_state_is_skipped,
        test_glob_matches_middle_double_star_without_directory,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
