from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, read_text, rel_path, select_repo_files

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
    "svelte": "sveltekit",
    "vue": "vue",
    "nuxt": "nuxt",
}
PYTHON_FRAMEWORK_MARKERS: Final = {
    "fastapi": "fastapi",
    "django": "django",
    "flask": "flask",
}


def language_for(path: Path) -> str:
    suffix = path.suffix.lower()
    mapping = {
        ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript", ".py": "python",
        ".go": "go", ".rb": "ruby", ".rs": "rust", ".java": "java", ".cs": "csharp", ".php": "php",
        ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift", ".scala": "scala", ".ex": "elixir",
        ".exs": "elixir", ".clj": "clojure", ".cljs": "clojure", ".sql": "sql",
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
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = payload.get(section)
        if isinstance(deps, dict):
            names.update(name for name in deps if isinstance(name, str))
    return names


def python_manifest_text(path: Path) -> str:
    if path.name in {"requirements.txt", "pyproject.toml"}:
        return read_text(path).lower()
    return ""


def manifest_text(files: list[Path], names: set[str]) -> str:
    return "\n".join(read_text(path).lower() for path in files if path.name in names)


def import_mentions_framework(path: Path, framework: str) -> bool:
    prefix = f"import {framework}"
    from_prefix = f"from {framework}"
    return any(line.strip().lower().startswith((prefix, from_prefix)) for line in read_text(path).splitlines())


def detect_frameworks(files: list[Path]) -> set[str]:
    frameworks: set[str] = set()
    package_names: set[str] = set()
    python_manifest = ""
    for path in files:
        if path.name == "package.json":
            package_names.update(dependency_names_from_package(path))
        python_manifest += python_manifest_text(path)
    for package_name, framework in PACKAGE_FRAMEWORKS.items():
        if package_name in package_names:
            frameworks.add(framework)
    for marker, framework in PYTHON_FRAMEWORK_MARKERS.items():
        if marker in python_manifest or any(path.suffix == ".py" and import_mentions_framework(path, marker) for path in files):
            frameworks.add(framework)
    if any(path.name == "go.mod" for path in files):
        frameworks.add("go-http")
    if any(path.name == "Cargo.toml" and "axum" in read_text(path).lower() for path in files):
        frameworks.add("axum")
    java_text = manifest_text(files, {"pom.xml", "build.gradle", "build.gradle.kts"})
    if "spring-boot" in java_text or "org.springframework" in java_text:
        frameworks.add("spring")
    dotnet_text = manifest_text(files, {path.name for path in files if path.suffix == ".csproj"})
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
    for marker, framework in (("gin-gonic/gin", "gin"), ("go-chi/chi", "chi"), ("labstack/echo", "echo"), ("gofiber/fiber", "fiber")):
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
        if lower.endswith(".gitlab-ci.yml"):
            workflows.add("gitlab-ci")
        if ".circleci/" in lower:
            workflows.add("circleci")
        if lower.endswith("jenkinsfile"):
            workflows.add("jenkins")
        if "dockerfile" in lower or "docker-compose" in lower:
            workflows.add("docker")
        if lower.endswith(".tf") or lower.endswith(".tfvars"):
            workflows.add("terraform")
        if lower.endswith((".yaml", ".yml")) and any(marker in lower for marker in ("k8s", "kubernetes", "helm", "charts")):
            workflows.add("kubernetes")
    return sorted(workflows)


def detect_package_managers(files: list[Path]) -> list[str]:
    names = {path.name for path in files}
    managers = {
        "npm": "package-lock.json",
        "pnpm": "pnpm-lock.yaml",
        "yarn": "yarn.lock",
        "uv": "uv.lock",
        "pip": "requirements.txt",
        "cargo": "Cargo.lock",
        "go-modules": "go.sum",
        "bundler": "Gemfile",
        "composer": "composer.lock",
        "maven": "pom.xml",
        "gradle": "build.gradle",
    }
    return sorted(manager for manager, marker in managers.items() if marker in names)


def route_like(rel: str) -> bool:
    lower = rel.lower()
    route_names = (
        "route.ts", "route.tsx", "route.js", "route.jsx", "+server.ts", "+server.js",
        "controller.java", "controller.cs", "controller.ts", "controller.js",
    )
    return (
        "/api/" in lower
        or "routes" in lower
        or "controllers" in lower
        or lower.endswith(("urls.py", "views.py", *route_names))
    )


def detect_inventory(root: Path) -> JsonMap:
    files = list(select_repo_files(root).files)
    rels = [rel_path(root, path) for path in files]
    text_all = "\n".join(read_text(path).lower() for path in files)
    languages = sorted({language for path in files if (language := language_for(path))})
    ai_sdks = sorted(marker for marker in ("openai", "anthropic", "langchain", "pydantic-ai", "vercel-ai") if marker in text_all)
    return {
        "languages": languages,
        "frameworks": sorted(detect_frameworks(files)),
        "ai_sdks": ai_sdks,
        "ci": ["github-actions"] if any(".github/workflows/" in item for item in rels) else [],
        "workflows": detect_workflows(rels),
        "package_managers": detect_package_managers(files),
        "route_files": sorted(item for item in rels if route_like(item))[:50],
    }
