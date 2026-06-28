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
    return frameworks


def route_like(rel: str) -> bool:
    lower = rel.lower()
    route_names = ("route.ts", "route.tsx", "route.js", "route.jsx", "+server.ts", "+server.js")
    return (
        "/api/" in lower
        or "routes" in lower
        or lower.endswith(("urls.py", "views.py", *route_names))
    )


def detect_inventory(root: Path) -> JsonMap:
    files = list(select_repo_files(root).files)
    rels = [rel_path(root, path) for path in files]
    text_all = "\n".join(read_text(path).lower() for path in files)
    languages = sorted({language for path in files if (language := language_for(path))})
    ai_sdks = sorted(marker for marker in ("openai", "anthropic", "langchain", "pydantic-ai", "vercel-ai") if marker in text_all)
    ci = ["github-actions"] if any(".github/workflows/" in item for item in rels) else []
    return {
        "languages": languages,
        "frameworks": sorted(detect_frameworks(files)),
        "ai_sdks": ai_sdks,
        "ci": ci,
        "route_files": sorted(item for item in rels if route_like(item))[:50],
    }
