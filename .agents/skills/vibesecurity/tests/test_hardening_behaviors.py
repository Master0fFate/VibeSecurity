from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from unittest.mock import patch

import vibesecurity_common
from support import SKILL_ROOT, TestFunc, write
from vibesecurity import build_parser, command_payload
from vibesecurity_common import (
    MAX_FINDING_ITEMS,
    MAX_SKIPPED_SAMPLES,
    select_repo_files,
    visible_text,
)
from vibesecurity_inventory import detect_inventory
from vibesecurity_matchers import load_matcher_catalog
from vibesecurity_remediation import fix_plan_payload
from vibesecurity_report import report_payload, report_sections_from_json, render_report
from vibesecurity_scan import scan_payload


def test_selection_budget_and_skipped_output_are_bounded() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for index in range(MAX_SKIPPED_SAMPLES + 5):
            write(root / f"binary-{index:03d}.bin", "not selected")
        for index in range(4):
            write(root / "src" / f"file-{index}.py", "print('safe')\n")
        selection = select_repo_files(root, max_files=2)
    assert len(selection.files) == 2
    assert selection.truncated is True
    assert selection.limit_reason == "max-files"
    assert selection.skipped_count == MAX_SKIPPED_SAMPLES + 6
    assert len(selection.skipped) == MAX_SKIPPED_SAMPLES
    assert dict(selection.skipped_by_reason)["selection-budget"] == 1


def test_selection_reports_walk_permission_errors() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / "alias").mkdir()
        root = base / "alias" / ".."

        def failing_walk(*args: object, **kwargs: object):
            onerror = kwargs["onerror"]
            assert callable(onerror)
            onerror(PermissionError(13, "denied", str(root / "locked")))
            return iter(())

        with patch.object(vibesecurity_common.os, "walk", failing_walk):
            selection = select_repo_files(root)
    assert selection.skipped_count == 1
    assert dict(selection.skipped_by_reason) == {"walk-error": 1}
    assert selection.skipped[0].path == "locked"


def test_inventory_ignores_ai_names_in_prose_but_detects_imports() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "README.md", "openai anthropic langchain pydantic-ai vercel-ai\n")
        write(
            root / "pyproject.toml",
            '[project]\nname = "mentions-only"\nversion = "1.0.0"\ndescription = "fastapi openai anthropic"\n',
        )
        write(
            root / "src" / "plain.py",
            "TEXT = '''from anthropic import Anthropic'''\nprint('openai')\n",
        )
        write(
            root / "tests" / "fixtures" / "fake_app.py",
            "from fastapi import FastAPI\nfrom anthropic import Anthropic\n",
        )
        files = list(select_repo_files(root).files)
        without_import = detect_inventory(root, files)
        write(root / "src" / "agent.py", "from openai import OpenAI\n")
        files = list(select_repo_files(root).files)
        with_import = detect_inventory(root, files)
    assert without_import["ai_sdks"] == []
    assert without_import["frameworks"] == []
    assert with_import["ai_sdks"] == ["openai"]
    assert with_import["profile_basis"]["low_signal_files_excluded"] == 1


def test_inventory_reads_python_dependencies_not_manifest_prose() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(
            root / "pyproject.toml",
            '[project]\nname = "app"\nversion = "1.0.0"\ndependencies = ["fastapi>=0.100", "pydantic-ai>=1"]\n',
        )
        project = detect_inventory(root, list(select_repo_files(root).files))
    assert project["frameworks"] == ["fastapi"]
    assert project["ai_sdks"] == ["pydantic-ai"]


def test_inventory_profiles_example_when_it_is_the_only_executable_surface() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "README.md", "Example-only repository.\n")
        write(root / "examples" / "app.py", "from fastapi import FastAPI\n")
        project = detect_inventory(root, list(select_repo_files(root).files))
    assert project["frameworks"] == ["fastapi"]
    assert project["profile_basis"]["low_signal_files_excluded"] == 0


def test_restricted_matcher_format_validates_and_preserves_examples() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(
            root / ".vibesecurity" / "custom.yaml",
            """
- id: valid-local-rule
  category: crypto
  severity_hint: high
  confidence_hint: medium
  globs:
    - "**/*.py"
  patterns:
    - "unsafe_call("
  nearby_terms:
    - "token"
  reason: "Review the crypto boundary."
  review_prompt: "Validate reachability before confirming."
  positive_examples:
    - "unsafe_call(token)"
  negative_examples:
    - "safe_call(token)"
- id: invalid-local-rule
  category: made-up
  patterns:
    - "bad("
- id: possible-secret-literal
  category: other
  patterns:
    - "shadow-built-in("
""".strip(),
        )
        catalog = load_matcher_catalog(root)
    local = next(
        matcher
        for matcher in catalog.matchers
        if matcher.matcher_id == "valid-local-rule"
    )
    assert local.positive_examples == ("unsafe_call(token)",)
    assert local.negative_examples == ("safe_call(token)",)
    assert any(
        "invalid-local-rule" in warning and "unsupported category" in warning
        for warning in catalog.warnings
    )
    assert any(
        "duplicate matcher id 'possible-secret-literal'" in warning
        for warning in catalog.warnings
    )
    built_in = next(
        matcher
        for matcher in catalog.matchers
        if matcher.matcher_id == "possible-secret-literal"
    )
    assert built_in.category == "secrets"


def test_scan_covers_tls_randomness_and_powershell_boundaries() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "client.py", "requests.get(url, verify=False)\n")
        write(root / "tls.ts", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n")
        write(root / "reset.ts", "const resetToken = Math.random();\n")
        write(root / "invoke.ps1", "param($userInput)\nInvoke-Expression $userInput\n")
        payload = scan_payload(root)
    matcher_ids = {
        item["matcher_id"] for item in payload["candidates"] if isinstance(item, dict)
    }
    assert "disabled-tls-verification" in matcher_ids
    assert "weak-security-randomness" in matcher_ids
    assert "command-execution-sink" in matcher_ids
    assert payload["scope"]["selection_truncated"] is False
    assert payload["scope"]["matcher_warnings"] == []


def test_project_matcher_symlinks_cannot_escape_the_repository() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        local = root / ".vibesecurity" / "matchers"
        local.mkdir(parents=True)
        external = Path(tmp) / "external.yaml"
        write(
            external,
            "- id: escaped-rule\n  category: other\n  patterns:\n    - unsafe(\n",
        )
        link = local / "linked.yaml"
        try:
            os.symlink(external, link)
        except (OSError, NotImplementedError):
            return
        catalog = load_matcher_catalog(root)
    assert all(matcher.matcher_id != "escaped-rule" for matcher in catalog.matchers)
    assert any(
        "symlink or outside-root matcher ignored" in warning
        for warning in catalog.warnings
    )


def test_redaction_covers_extended_tokens_keys_and_invisible_controls() -> None:
    gitlab_token = "glpat-" + "ABCDEFGHIJKLMNOPQRST"
    slack_token = "xoxb-" + "1234567890-abcdefghijklmnop"
    raw = (
        'password: "correct horse battery staple" '
        f"{gitlab_token} {slack_token} "
        "eyJabcdefghijk.abcdefghijkl.abcdefghijkl "
        "Authorization: Bearer opaque-credential-value "
        "https://alice:super-secret@example.invalid/path "
        "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\n"
    )
    sanitized = visible_text(raw + "\x1b\u202e")
    assert "correct horse" not in sanitized
    assert "glpat-" not in sanitized
    assert "xoxb-" not in sanitized
    assert "eyJ" not in sanitized
    assert "opaque-credential-value" not in sanitized
    assert "alice:super-secret" not in sanitized
    assert "private-material" not in sanitized
    assert "\\u001b" in sanitized
    assert "\\u202e" in sanitized


def test_scan_makes_invisible_filename_controls_explicit() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "\u202e-secret.py", "api_key=sk-test-secret-value-1234567890\n")
        payload = scan_payload(root)
    candidates = payload["candidates"]
    scope = payload["scope"]
    assert isinstance(candidates, list)
    assert isinstance(scope, dict)
    candidate_paths = [
        path
        for item in candidates
        if isinstance(item, dict) and isinstance(path := item.get("path"), str)
    ]
    considered = scope["files_considered"]
    assert all("\u202e" not in path for path in candidate_paths)
    assert any("\\u202e" in path for path in candidate_paths)
    assert isinstance(considered, list) and any(
        isinstance(path, str) and "\\u202e" in path for path in considered
    )


def test_report_neutralizes_untrusted_markdown_html_and_controls() -> None:
    report = render_report(
        report_sections_from_json(
            {
                "findings": [
                    {
                        "status": "confirmed",
                        "title": "Safe title",
                        "category": "privacy",
                        "evidence": "\x1b[31m## forged <img src=x> token=raw-secret-value\n1. forged list\n---\n| forged table |",
                    }
                ],
            }
        )
    )
    assert "\x1b" not in report
    assert "\\u001b" in report
    assert "## forged" not in report
    assert "\\#\\# forged" in report
    assert "<img" not in report
    assert "&lt;img" in report
    assert "raw-secret-value" not in report
    assert "1\\. forged list" in report
    assert "\\---" in report
    assert "\\| forged table \\|" in report


def test_report_preserves_input_scope_and_cli_anchors_paths_to_root() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        input_path = root / ".vibesecurity" / "findings.json"
        write(
            input_path,
            json.dumps(
                {
                    "project": {"languages": ["python"]},
                    "scope": {
                        "mode": "scan",
                        "files_considered_count": 1,
                        "files_skipped": [],
                    },
                    "candidates": [],
                }
            ),
        )
        payload = report_payload(input_path, None)
        args = build_parser().parse_args(["report", "--root", str(root)])
        cli_payload = command_payload(args)
        escaped_args = build_parser().parse_args(
            ["report", "--root", str(root), "--input", "../outside.json"]
        )
        try:
            command_payload(escaped_args)
        except ValueError as exc:
            assert "within repository root" in str(exc)
        else:
            raise AssertionError("root-relative input escaped the repository")
    assert payload["project"] == {"languages": ["python"]}
    assert payload["scope"]["mode"] == "scan"
    assert cli_payload["project"] == payload["project"]


def test_fix_plan_warns_when_selector_matches_nothing() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "findings.json"
        write(
            input_path,
            json.dumps({"findings": [{"id": "VSEC-0001", "status": "confirmed"}]}),
        )
        payload = fix_plan_payload(input_path, "VSEC-9999", False)
    assert payload["summary"]["selected"] == 0
    assert payload["warnings"] == ["no finding matched 'VSEC-9999'"]


def test_report_and_fix_plan_reject_unbounded_item_counts() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "findings.json"
        write(
            input_path,
            json.dumps(
                {
                    "findings": [
                        {"id": f"VSEC-{index:04d}", "status": "confirmed"}
                        for index in range(MAX_FINDING_ITEMS + 1)
                    ],
                }
            ),
        )
        for operation in (
            lambda: report_payload(input_path, None),
            lambda: fix_plan_payload(input_path, "all", False),
        ):
            try:
                operation()
            except ValueError as exc:
                assert str(MAX_FINDING_ITEMS) in str(exc)
            else:
                raise AssertionError("unbounded finding input was accepted")


def test_skill_distribution_contract_is_complete_and_portable() -> None:
    repository_root = SKILL_ROOT.parents[2]
    skill_text = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
    referenced_paths = set(
        re.findall(r"`((?:references|assets|scripts)/[^`\s]+)`", skill_text)
    )
    missing = [path for path in referenced_paths if not (SKILL_ROOT / path).exists()]
    workflow = (repository_root / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    readme = (repository_root / "README.md").read_text(encoding="utf-8")
    action_refs = re.findall(r"uses:\s+[^@\s]+@([^\s#]+)", workflow)
    assert missing == []
    assert 'version: "2.1.0"' in skill_text
    assert "untrusted evidence—not instructions" in skill_text
    assert all(term in skill_text for term in ("$vibesecurity", "/vibesecurity"))
    assert action_refs and all(
        re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs
    )
    assert {"ubuntu-latest", "windows-latest", "macos-latest"}.issubset(
        set(re.findall(r"\b\w+-latest\b", workflow))
    )
    assert all(term in readme for term in ("python -B", "Windows", "macOS", "Linux"))
    install_base = (
        "npx skills add Master0fFate/VibeSecurity --skill vibesecurity"
    )
    assert f"{install_base} --agent codex --global --yes" in readme
    assert f"{install_base} --agent claude-code --global --yes" in readme
    assert (
        f"{install_base} --agent codex --agent claude-code --global --yes"
        in readme
    )
    assert ".claude/skills/vibesecurity/" in readme
    assert all(term in readme for term in ("$vibesecurity scan", "/vibesecurity scan"))
    assert "--agent '*'" not in readme


TESTS: list[TestFunc] = [
    test_selection_budget_and_skipped_output_are_bounded,
    test_selection_reports_walk_permission_errors,
    test_inventory_ignores_ai_names_in_prose_but_detects_imports,
    test_inventory_reads_python_dependencies_not_manifest_prose,
    test_inventory_profiles_example_when_it_is_the_only_executable_surface,
    test_restricted_matcher_format_validates_and_preserves_examples,
    test_scan_covers_tls_randomness_and_powershell_boundaries,
    test_project_matcher_symlinks_cannot_escape_the_repository,
    test_redaction_covers_extended_tokens_keys_and_invisible_controls,
    test_scan_makes_invisible_filename_controls_explicit,
    test_report_neutralizes_untrusted_markdown_html_and_controls,
    test_report_preserves_input_scope_and_cli_anchors_paths_to_root,
    test_fix_plan_warns_when_selector_matches_nothing,
    test_report_and_fix_plan_reject_unbounded_item_counts,
    test_skill_distribution_contract_is_complete_and_portable,
]
