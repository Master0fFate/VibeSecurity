from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path
from typing import Final

from vibesecurity_common import (
    JsonMap,
    display_path,
    read_text,
    rel_path,
    select_repo_files,
)

PACKAGE_FRAMEWORKS: Final = {
    "next": "nextjs",
    "react": "react",
    "express": "express",
    "fastify": "fastify",
    "@hono/hono": "hono",
    "hono": "hono",
    "@nestjs/core": "nestjs",
    "@remix-run/node": "remix",
    "astro": "astro",
    "svelte": "svelte",
    "@sveltejs/kit": "sveltekit",
    "vue": "vue",
    "nuxt": "nuxt",
}
PYTHON_FRAMEWORK_MARKERS: Final = {
    "fastapi": "fastapi",
    "django": "django",
    "flask": "flask",
}
AI_PACKAGE_MARKERS: Final = {
    "openai": "openai",
    "@anthropic-ai/sdk": "anthropic",
    "anthropic": "anthropic",
    "langchain": "langchain",
    "@langchain/core": "langchain",
    "pydantic-ai": "pydantic-ai",
    "pydantic_ai": "pydantic-ai",
    "ai": "vercel-ai",
    "@ai-sdk/openai": "vercel-ai",
    "@ai-sdk/anthropic": "vercel-ai",
}
LOW_SIGNAL_PROFILE_PARTS: Final = {
    "test",
    "tests",
    "fixture",
    "fixtures",
    "example",
    "examples",
    "doc",
    "docs",
}
PROFILE_MANIFEST_NAMES: Final = {
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "Gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
}


def language_for(path: Path) -> str:
    suffix = path.suffix.lower()
    mapping = {
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".py": "python",
        ".go": "go",
        ".rb": "ruby",
        ".rs": "rust",
        ".java": "java",
        ".cs": "csharp",
        ".php": "php",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".swift": "swift",
        ".scala": "scala",
        ".ex": "elixir",
        ".exs": "elixir",
        ".clj": "clojure",
        ".cljs": "clojure",
        ".sql": "sql",
        ".ps1": "powershell",
        ".psm1": "powershell",
        ".bat": "batch",
        ".cmd": "batch",
        ".c": "c",
        ".h": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".hpp": "cpp",
        ".fs": "fsharp",
        ".fsx": "fsharp",
        ".vb": "visual-basic",
        ".dart": "dart",
        ".lua": "lua",
        ".r": "r",
        ".sol": "solidity",
        ".bicep": "bicep",
    }
    return mapping.get(suffix, "")


def dependency_names_from_package(path: Path) -> set[str]:
    try:
        payload = json.loads(read_text(path))
    except json.JSONDecodeError:
        return set()
    if not isinstance(payload, dict):
        return set()
    names: set[str] = set()
    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        deps = payload.get(section)
        if isinstance(deps, dict):
            names.update(name for name in deps if isinstance(name, str))
    return names


def normalized_dependency_name(value: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", value)
    return re.sub(r"[-_.]+", "-", match.group(1).casefold()) if match else ""


def add_requirement_values(names: set[str], values: object) -> None:
    if isinstance(values, list):
        for value in values:
            if isinstance(value, str) and (name := normalized_dependency_name(value)):
                names.add(name)


def add_dependency_mapping(names: set[str], value: object) -> None:
    if not isinstance(value, dict):
        return
    for raw_name, specification in value.items():
        if isinstance(specification, list):
            add_requirement_values(names, specification)
        elif isinstance(raw_name, str) and raw_name.casefold() != "python":
            if name := normalized_dependency_name(raw_name):
                names.add(name)


def python_dependency_names(files: list[Path]) -> set[str]:
    names: set[str] = set()
    for path in files:
        if path.name == "requirements.txt":
            for line in read_text(path).splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith(("#", "-")):
                    if name := normalized_dependency_name(stripped):
                        names.add(name)
            continue
        if path.name not in {"pyproject.toml", "Pipfile", "poetry.lock", "uv.lock"}:
            continue
        try:
            payload = tomllib.loads(read_text(path))
        except tomllib.TOMLDecodeError:
            continue
        project = payload.get("project")
        if isinstance(project, dict):
            add_requirement_values(names, project.get("dependencies"))
            optional = project.get("optional-dependencies")
            if isinstance(optional, dict):
                for group in optional.values():
                    add_requirement_values(names, group)
        dependency_groups = payload.get("dependency-groups")
        if isinstance(dependency_groups, dict):
            for group in dependency_groups.values():
                add_requirement_values(names, group)
        add_dependency_mapping(names, payload.get("packages"))
        add_dependency_mapping(names, payload.get("dev-packages"))
        tool = payload.get("tool")
        if isinstance(tool, dict):
            for manager_name in ("poetry", "pdm"):
                manager = tool.get(manager_name)
                if not isinstance(manager, dict):
                    continue
                add_dependency_mapping(names, manager.get("dependencies"))
                groups = manager.get("group")
                if isinstance(groups, dict):
                    for group in groups.values():
                        if isinstance(group, dict):
                            add_dependency_mapping(names, group.get("dependencies"))
            uv = tool.get("uv")
            if isinstance(uv, dict):
                add_requirement_values(names, uv.get("dev-dependencies"))
        packages = payload.get("package")
        if isinstance(packages, list):
            for package in packages:
                if isinstance(package, dict) and isinstance(package.get("name"), str):
                    if name := normalized_dependency_name(package["name"]):
                        names.add(name)
    return names


def manifest_text(files: list[Path], names: set[str]) -> str:
    return "\n".join(read_text(path).lower() for path in files if path.name in names)


def python_import_modules(files: list[Path]) -> set[str]:
    modules: set[str] = set()
    for path in files:
        if path.suffix.lower() != ".py":
            continue
        try:
            tree = ast.parse(read_text(path))
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(
                    alias.name.casefold().split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.casefold().split(".", 1)[0])
    return modules


def detect_ai_sdks(
    files: list[Path], python_modules: set[str], python_dependencies: set[str]
) -> set[str]:
    detected: set[str] = set()
    package_names: set[str] = set()
    for path in files:
        if path.name == "package.json":
            package_names.update(dependency_names_from_package(path))
    for marker, sdk in AI_PACKAGE_MARKERS.items():
        if marker in package_names:
            detected.add(sdk)
    for marker, sdk in AI_PACKAGE_MARKERS.items():
        if marker == "ai" or marker.startswith("@"):
            continue
        normalized = marker.replace("-", "_")
        if (
            normalized_dependency_name(marker) in python_dependencies
            or normalized in python_modules
        ):
            detected.add(sdk)
    return detected


def detect_frameworks(
    files: list[Path], python_modules: set[str], python_dependencies: set[str]
) -> set[str]:
    frameworks: set[str] = set()
    package_names: set[str] = set()
    for path in files:
        if path.name == "package.json":
            package_names.update(dependency_names_from_package(path))
    for package_name, framework in PACKAGE_FRAMEWORKS.items():
        if package_name in package_names:
            frameworks.add(framework)
    for marker, framework in PYTHON_FRAMEWORK_MARKERS.items():
        if (
            normalized_dependency_name(marker) in python_dependencies
            or marker in python_modules
        ):
            frameworks.add(framework)
    if any(path.name == "go.mod" for path in files):
        frameworks.add("go-http")
    if any(
        path.name == "Cargo.toml" and "axum" in read_text(path).lower()
        for path in files
    ):
        frameworks.add("axum")
    java_text = manifest_text(files, {"pom.xml", "build.gradle", "build.gradle.kts"})
    if "spring-boot" in java_text or "org.springframework" in java_text:
        frameworks.add("spring")
    dotnet_text = manifest_text(
        files, {path.name for path in files if path.suffix == ".csproj"}
    )
    if "microsoft.aspnetcore" in dotnet_text:
        frameworks.add("aspnetcore")
    composer_text = manifest_text(files, {"composer.json"})
    if "laravel/framework" in composer_text:
        frameworks.add("laravel")
    if "symfony/" in composer_text:
        frameworks.add("symfony")
    ruby_text = manifest_text(files, {"Gemfile"})
    if "rails" in ruby_text:
        frameworks.add("rails")
    go_text = manifest_text(files, {"go.mod"})
    for marker, framework in (
        ("gin-gonic/gin", "gin"),
        ("go-chi/chi", "chi"),
        ("labstack/echo", "echo"),
        ("gofiber/fiber", "fiber"),
    ):
        if marker in go_text:
            frameworks.add(framework)
    rust_text = manifest_text(files, {"Cargo.toml"})
    for marker, framework in (("actix-web", "actix-web"), ("rocket", "rocket")):
        if marker in rust_text:
            frameworks.add(framework)
    return frameworks


def detect_workflows(rels: list[str]) -> list[str]:
    workflows: set[str] = set()
    for rel in rels:
        lower = rel.lower()
        if ".github/workflows/" in lower:
            workflows.add("github-actions")
        if lower.endswith((".gitlab-ci.yml", ".gitlab-ci.yaml")):
            workflows.add("gitlab-ci")
        if ".circleci/" in lower:
            workflows.add("circleci")
        if lower.endswith("azure-pipelines.yml") or lower.endswith(
            "azure-pipelines.yaml"
        ):
            workflows.add("azure-pipelines")
        if lower.endswith("bitbucket-pipelines.yml") or lower.endswith(
            "bitbucket-pipelines.yaml"
        ):
            workflows.add("bitbucket-pipelines")
        if lower.endswith("jenkinsfile"):
            workflows.add("jenkins")
        if "dockerfile" in lower or "docker-compose" in lower:
            workflows.add("docker")
        if lower.endswith(".tf") or lower.endswith(".tfvars"):
            workflows.add("terraform")
        if lower.endswith(".bicep"):
            workflows.add("bicep")
        if lower.endswith((".yaml", ".yml")) and any(
            marker in lower for marker in ("k8s", "kubernetes", "helm", "charts")
        ):
            workflows.add("kubernetes")
    return sorted(workflows)


def detect_package_managers(files: list[Path]) -> list[str]:
    names = {path.name for path in files}
    managers = {
        "npm": {"package-lock.json"},
        "pnpm": {"pnpm-lock.yaml"},
        "yarn": {"yarn.lock"},
        "uv": {"uv.lock"},
        "pip": {"requirements.txt"},
        "pipenv": {"Pipfile", "Pipfile.lock"},
        "poetry": {"poetry.lock"},
        "cargo": {"Cargo.toml", "Cargo.lock"},
        "go-modules": {"go.mod", "go.sum"},
        "bundler": {"Gemfile", "Gemfile.lock"},
        "composer": {"composer.json", "composer.lock"},
        "maven": {"pom.xml"},
        "gradle": {"build.gradle", "build.gradle.kts", "settings.gradle"},
        "bun": {"bun.lock"},
    }
    return sorted(
        manager for manager, markers in managers.items() if names.intersection(markers)
    )


def route_like(rel: str) -> bool:
    lower = rel.lower()
    route_names = (
        "route.ts",
        "route.tsx",
        "route.js",
        "route.jsx",
        "+server.ts",
        "+server.js",
        "controller.java",
        "controller.cs",
        "controller.ts",
        "controller.js",
    )
    return (
        "/api/" in lower
        or "routes" in lower
        or "controllers" in lower
        or lower.endswith(("urls.py", "views.py", *route_names))
    )


def profile_files(root: Path, files: list[Path]) -> list[Path]:
    primary = [
        path
        for path in files
        if not {part.casefold() for part in path.relative_to(root).parts}.intersection(
            LOW_SIGNAL_PROFILE_PARTS
        )
    ]
    has_primary_evidence = any(
        language_for(path) or path.name in PROFILE_MANIFEST_NAMES for path in primary
    )
    return primary if has_primary_evidence else files


def detect_inventory(root: Path, files: list[Path] | None = None) -> JsonMap:
    resolved_root = root.resolve()
    selected = files if files is not None else list(select_repo_files(root).files)
    files = selected
    rels = [rel_path(resolved_root, path) for path in files]
    profiled_files = profile_files(resolved_root, files)
    profiled_rels = [rel_path(resolved_root, path) for path in profiled_files]
    languages = sorted({language for path in files if (language := language_for(path))})
    python_modules = python_import_modules(profiled_files)
    python_dependencies = python_dependency_names(profiled_files)
    workflows = detect_workflows(rels)
    return {
        "languages": languages,
        "frameworks": sorted(
            detect_frameworks(profiled_files, python_modules, python_dependencies)
        ),
        "ai_sdks": sorted(
            detect_ai_sdks(profiled_files, python_modules, python_dependencies)
        ),
        "ci": [
            item
            for item in workflows
            if item
            in {
                "github-actions",
                "gitlab-ci",
                "circleci",
                "jenkins",
                "azure-pipelines",
                "bitbucket-pipelines",
            }
        ],
        "workflows": workflows,
        "package_managers": detect_package_managers(files),
        "route_files": [
            display_path(item)
            for item in sorted(item for item in profiled_rels if route_like(item))[:50]
        ],
        "profile_basis": {
            "files_considered": len(profiled_files),
            "low_signal_files_excluded": len(files) - len(profiled_files),
        },
    }
