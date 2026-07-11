from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from support import FIXTURES, TestFunc, write
from vibesecurity_scan import diff_payload, glob_matches, inventory_payload, scan_payload


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


def test_inventory_profiles_generic_worktree_surfaces() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / "pom.xml", "<project><dependency>org.springframework.boot:spring-boot-starter-web</dependency></project>\n")
        write(root / "src" / "main" / "java" / "AdminController.java", "class AdminController {}\n")
        write(root / "web.csproj", "<Project><PackageReference Include=\"Microsoft.AspNetCore.App\" /></Project>\n")
        write(root / "Controllers" / "BillingController.cs", "class BillingController {}\n")
        write(root / "composer.json", json.dumps({"require": {"laravel/framework": "^11.0"}}))
        write(root / "Gemfile", "gem 'rails'\n")
        write(root / "app" / "controllers" / "users_controller.rb", "class UsersController; end\n")
        write(root / "go.mod", "module example.com/app\nrequire github.com/gin-gonic/gin v1.10.0\n")
        write(root / "cmd" / "server" / "main.go", "package main\n")
        write(root / "Cargo.toml", "[dependencies]\nactix-web = \"4\"\n")
        write(root / ".gitlab-ci.yml", "deploy:\n  script: echo deploy\n")
        write(root / "Jenkinsfile", "pipeline { stages { stage('deploy') { steps { sh 'deploy' } } } }\n")
        write(root / "Dockerfile", "FROM ubuntu:latest\n")
        write(root / "infra" / "main.tf", "resource \"aws_security_group\" \"web\" {}\n")
        write(root / "k8s" / "deployment.yaml", "kind: Deployment\nspec: {}\n")
        project = inventory_payload(root)["project"]
    assert isinstance(project, dict)
    assert {"java", "csharp", "go", "ruby"}.issubset(set(project["languages"]))
    assert {"spring", "aspnetcore", "laravel", "rails", "gin", "actix-web"}.issubset(set(project["frameworks"]))
    assert {"gitlab-ci", "jenkins", "docker", "terraform", "kubernetes"}.issubset(set(project["workflows"]))


def test_scan_prioritizes_production_candidates_before_fixture_noise() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for index in range(205):
            write(root / "tests" / f"secrets-{index}.txt", f"api_key=sk-test-{index:024d}\n")
        write(root / "src" / "app" / "api" / "admin" / "users" / "route.ts", "export async function DELETE() {\n  return Response.json({ users: [] });\n}\n")
        payload = scan_payload(root)
    candidates = payload["candidates"]
    assert isinstance(candidates, list)
    paths = [item["path"] for item in candidates if isinstance(item, dict)]
    assert payload["truncated"] is True
    assert payload["candidates_total"] > payload["candidates_returned"]
    assert "src/app/api/admin/users/route.ts" in paths


def test_scan_finds_generic_workflow_candidates() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write(root / ".gitlab-ci.yml", "deploy:\n  script: curl https://example.invalid/install.sh | bash\n  environment: production\n  variables:\n    TOKEN: $TOKEN\n")
        write(root / "Jenkinsfile", "pipeline { stages { stage('deploy') { steps { withCredentials([]) { sh 'deploy' } } } } }\n")
        write(root / "Dockerfile", "FROM ubuntu:latest\nRUN curl https://example.invalid/install.sh | sh\n")
        write(root / "infra" / "main.tf", "cidr_blocks = [\"0.0.0.0/0\"]\n")
        write(root / "k8s" / "deployment.yaml", "kind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true\n")
        candidates = scan_payload(root)["candidates"]
    matcher_ids = {item["matcher_id"] for item in candidates if isinstance(item, dict)}
    assert "gitlab-ci-secret-boundary" in matcher_ids
    assert "jenkins-shell-or-secret-boundary" in matcher_ids
    assert "docker-unpinned-or-remote-script" in matcher_ids
    assert "terraform-public-or-wildcard-access" in matcher_ids
    assert "kubernetes-privileged-workload" in matcher_ids


def test_diff_reports_git_warnings_outside_repo() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        payload = diff_payload(Path(tmp))
    warnings = payload["warnings"]
    assert isinstance(warnings, list)
    assert warnings
    assert all(isinstance(item, str) and "git " in item for item in warnings)


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
    assert glob_matches(r"SRC\PAGES\API\USERS.TS", "**/pages/api/**/*.ts")
    assert not glob_matches("pages/app/users.ts", "**/pages/api/**/*.ts")


TESTS: list[TestFunc] = [
    test_fixture_scan_emits_review_candidates,
    test_nearby_terms_use_line_window,
    test_scan_reports_skips_and_truncation,
    test_env_snippets_redact_values,
    test_inventory_prefers_manifest_and_route_patterns,
    test_inventory_profiles_generic_worktree_surfaces,
    test_scan_prioritizes_production_candidates_before_fixture_noise,
    test_scan_finds_generic_workflow_candidates,
    test_diff_reports_git_warnings_outside_repo,
    test_symlinks_are_skipped_when_supported,
    test_local_vibesecurity_state_is_skipped,
    test_glob_matches_middle_double_star_without_directory,
]
