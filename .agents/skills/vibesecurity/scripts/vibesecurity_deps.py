from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, visible_text

MAX_LOCKFILE_BYTES: Final = 10_000_000
MAX_DEPS: Final = 20_000

OSV_ECOSYSTEMS: Final = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "crates.io": "crates.io",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
}

LOCKFILE_NAMES: Final = {
    "package-lock.json": "npm-package-lock",
    "yarn.lock": "npm-yarn-v1",
    "pnpm-lock.yaml": "npm-pnpm",
    "poetry.lock": "pypi-poetry",
    "requirements.txt": "pypi-requirements",
    "requirements-prod.txt": "pypi-requirements",
    "Pipfile.lock": "pypi-pipfile",
    "go.mod": "go-mod",
    "Cargo.lock": "cargo-lock",
    "Gemfile.lock": "gemfile-lock",
    "composer.lock": "composer-lock",
}

UNSUPPORTED_MANIFESTS: Final = {
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "gradle.lockfile": "gradle",
    "yarn.lock": "npm-yarn-berry",
    "pnpm-workspace.yaml": "npm-pnpm-workspace",
    "mix.lock": "elixir-hex",
    "packages.lock.json": "nuget",
    "packages.config": "nuget",
    "Package.resolved": "swift",
    "go.sum": "go-sum-hashes-only",
}

REQUIREMENT_PIN: Final = re.compile(r"^([A-Za-z0-9._-]+)\s*==\s*([^\\s#;]+)")
GO_REQUIRE_LINE: Final = re.compile(r"^\s*([A-Za-z0-9._/~+-]+/[A-Za-z0-9._/~+-]+(?:/[A-Za-z0-9._~+-]+)*)\s+(v[0-9][^\s]+)")
GEM_SPEC: Final = re.compile(r"^ {4}([A-Za-z0-9._-]+) \(([0-9][^)]*)\)")
PNPM_PACKAGE_KEY: Final = re.compile(r"^ {2}/?([^\s:]+@[^\s:]+):")
YARN_ENTRY: Final = re.compile(r'^"?([^\s"@]+@[^\s@"]+|[^\s@]+@[^\s@"]+|[^\s"]+)"?:$')


@dataclass(frozen=True, slots=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    source_file: str
    line: int

    def to_json(self) -> JsonMap:
        return {
            "ecosystem": self.ecosystem,
            "name": visible_text(self.name, 200),
            "version": visible_text(self.version, 200),
            "source_file": visible_text(self.source_file, 500),
            "line": self.line,
        }


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _bounded_lines(text: str) -> list[str]:
    return text.splitlines()[:200_000]


def parse_npm_package_lock(text: str, rel: str) -> tuple[list[Dependency], list[str]]:
    deps: list[Dependency] = []
    warnings: list[str] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], [f"{rel}: package-lock.json is not valid JSON; skipped"]
    if not isinstance(data, dict):
        return [], [f"{rel}: package-lock.json root must be an object; skipped"]
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, value in packages.items():
            if not key or not isinstance(value, dict):
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            version = value.get("version")
            if name and isinstance(version, str) and version:
                deps.append(Dependency("npm", name, version, rel, 0))
        return deps, warnings
    legacy = data.get("dependencies")
    if isinstance(legacy, dict):
        for name, value in legacy.items():
            version = value.get("version") if isinstance(value, dict) else None
            if isinstance(version, str) and version:
                deps.append(Dependency("npm", name, version, rel, 0))
        return deps, [f"{rel}: legacy lockfile v1 dependencies block parsed"]
    return deps, [f"{rel}: package-lock.json has no packages or dependencies block"]


def parse_yarn_v1(text: str, rel: str) -> tuple[list[Dependency], list[str]]:
    if "__metadata:" in text:
        return [], [f"{rel}: yarn berry lockfile is unsupported; reported as unsupported"]
    deps: list[Dependency] = []
    current_names: list[str] = []
    for number, line in enumerate(_bounded_lines(text), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(" ") and stripped.endswith(":") and "@" in stripped:
            entry = stripped[:-1].strip('"')
            for candidate in entry.split(", "):
                if "@" in candidate:
                    name_version = candidate.rsplit("@", 1)
                    if len(name_version) == 2 and name_version[0] and name_version[1]:
                        current_names.append(name_version[0])
            continue
        if line.startswith("  version ") and current_names:
            match = re.match(r'^\s*version\s+"?([^"\s]+)"?', stripped)
            if match:
                for name in current_names:
                    deps.append(Dependency("npm", name, match.group(1), rel, number))
            current_names = []
    return deps, []


def parse_pnpm(text: str, rel: str) -> tuple[list[Dependency], list[str]]:
    deps: list[Dependency] = []
    warnings: list[str] = []
    in_packages = False
    for number, line in enumerate(_bounded_lines(text), start=1):
        stripped = line.strip()
        if stripped == "packages:":
            in_packages = True
            continue
        if in_packages:
            if stripped and not line.startswith(" "):
                in_packages = False
                continue
            match = PNPM_PACKAGE_KEY.match(line)
            if match:
                name_version = match.group(1).rsplit("@", 1)
                if len(name_version) == 2 and name_version[0] and name_version[1]:
                    name = name_version[0].lstrip("/")
                    version = name_version[1].split("(", 1)[0]
                    if version.startswith("v"):
                        version = version[1:]
                    deps.append(Dependency("npm", name, version, rel, number))
    if not deps:
        warnings.append(f"{rel}: no packages parsed from pnpm lockfile")
    return deps, warnings


def parse_poetry_lock(text: str, rel: str) -> tuple[list[Dependency], list[str]]:
    deps: list[Dependency] = []
    name = ""
    for number, line in enumerate(_bounded_lines(text), start=1):
        stripped = line.strip()
        if stripped == "[[package]]":
            name = ""
            continue
        if stripped.startswith("name = "):
            name = stripped.split("=", 1)[1].strip().strip('"')
            continue
        if stripped.startswith("version = ") and name:
            version = stripped.split("=", 1)[1].strip().strip('"')
            if version:
                deps.append(Dependency("pypi", name, version, rel, number))
            name = ""
    return deps, []


def parse_requirements(text: str, rel: str) -> tuple[list[Dependency], list[str]]:
    deps: list[Dependency] = []
    unpinned = 0
    for number, line in enumerate(_bounded_lines(text), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-", " ")) or stripped.startswith("--"):
            continue
        if "==" in stripped:
            match = REQUIREMENT_PIN.match(stripped)
            if match:
                deps.append(Dependency("pypi", match.group(1).lower(), match.group(2), rel, number))
                continue
        if re.match(r"^[A-Za-z0-9._-]+\s*(?:>=|<=|~=|>|<|!=)", stripped):
            unpinned += 1
    warnings = [f"{rel}: {unpinned} ranged requirement(s) not exact-pinned; not matched"] if unpinned else []
    return deps, warnings


def parse_pipfile_lock(text: str, rel: str) -> tuple[list[Dependency], list[str]]:
    deps: list[Dependency] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], [f"{rel}: Pipfile.lock is not valid JSON; skipped"]
    if not isinstance(data, dict):
        return [], [f"{rel}: Pipfile.lock root must be an object; skipped"]
    for section in ("default", "develop"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, value in block.items():
            version = value.get("version", "") if isinstance(value, dict) else ""
            if isinstance(version, str) and version.startswith("=="):
                deps.append(Dependency("pypi", name.lower(), version[2:], rel, 0))
    return deps, []


def parse_go_mod(text: str, rel: str) -> tuple[list[Dependency], list[str]]:
    deps: list[Dependency] = []
    in_require = False
    for number, line in enumerate(_bounded_lines(text), start=1):
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        candidate = stripped
        if candidate.startswith("require "):
            candidate = candidate[len("require ") :]
        elif not in_require:
            continue
        match = GO_REQUIRE_LINE.match(candidate)
        if match:
            deps.append(Dependency("go", match.group(1), match.group(2), rel, number))
    return deps, []


def parse_cargo_lock(text: str, rel: str) -> tuple[list[Dependency], list[str]]:
    deps: list[Dependency] = []
    name = ""
    for number, line in enumerate(_bounded_lines(text), start=1):
        stripped = line.strip()
        if stripped == "[[package]]":
            name = ""
            continue
        if stripped.startswith("name = "):
            name = stripped.split("=", 1)[1].strip().strip('"')
            continue
        if stripped.startswith("version = ") and name:
            version = stripped.split("=", 1)[1].strip().strip('"')
            if version:
                deps.append(Dependency("crates.io", name, version, rel, number))
            name = ""
    return deps, []


def parse_gemfile_lock(text: str, rel: str) -> tuple[list[Dependency], list[str]]:
    deps: list[Dependency] = []
    warnings: list[str] = []
    section = ""
    for number, line in enumerate(_bounded_lines(text), start=1):
        if line and not line.startswith(" ") and not line.startswith("\t"):
            section = line.strip().rstrip(":").lower()
            continue
        if section in {"gem", "git", "path", "specs"}:
            match = GEM_SPEC.match(line)
            if match:
                deps.append(Dependency("rubygems", match.group(1), match.group(2), rel, number))
    return deps, warnings


def parse_composer_lock(text: str, rel: str) -> tuple[list[Dependency], list[str]]:
    deps: list[Dependency] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], [f"{rel}: composer.lock is not valid JSON; skipped"]
    if not isinstance(data, dict):
        return [], [f"{rel}: composer.lock root must be an object; skipped"]
    for section in ("packages", "packages-dev"):
        block = data.get(section)
        if not isinstance(block, list):
            continue
        for value in block:
            if isinstance(value, dict) and isinstance(value.get("name"), str):
                version = value.get("version")
                if isinstance(version, str) and version:
                    deps.append(Dependency("packagist", value["name"], version, rel, 0))
    return deps, []


PARSERS = {
    "npm-package-lock": parse_npm_package_lock,
    "npm-yarn-v1": parse_yarn_v1,
    "npm-pnpm": parse_pnpm,
    "pypi-poetry": parse_poetry_lock,
    "pypi-requirements": parse_requirements,
    "pypi-pipfile": parse_pipfile_lock,
    "go-mod": parse_go_mod,
    "cargo-lock": parse_cargo_lock,
    "gemfile-lock": parse_gemfile_lock,
    "composer-lock": parse_composer_lock,
}


def walk_skip_parts() -> set[str]:
    return {
        ".git", "node_modules", ".venv", "venv", "vendor", "target",
        "__pycache__", ".vibesecurity", "dist", "build", ".codegraph", ".omo",
    }


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    junction = getattr(os.path, "isjunction", None)
    return bool(junction and junction(str(path)))


def deps_payload(root: Path) -> JsonMap:
    root = root.resolve()
    dependencies: list[Dependency] = []
    warnings: list[str] = []
    unsupported: list[JsonMap] = []
    seen_files: set[str] = set()
    skip_parts = walk_skip_parts()
    for dirpath, dirnames, filenames in os.walk(root):
        kept: list[str] = []
        for dirname in dirnames:
            if dirname.lower() in skip_parts or _is_link(Path(dirpath) / dirname):
                continue
            kept.append(dirname)
        dirnames[:] = kept
        for filename in sorted(filenames):
            full_path = Path(dirpath) / filename
            if _is_link(full_path):
                continue
            try:
                rel = str(full_path.resolve().relative_to(root)).replace("\\", "/")
            except ValueError:
                warnings.append(f"path outside repository root skipped: {visible_text(filename, 200)}")
                continue
            if filename in LOCKFILE_NAMES:
                if rel in seen_files:
                    continue
                seen_files.add(rel)
                path = full_path
                try:
                    if path.stat().st_size > MAX_LOCKFILE_BYTES:
                        warnings.append(f"{rel}: exceeds {MAX_LOCKFILE_BYTES} bytes; skipped")
                        continue
                    text = _read(path)
                except OSError as exc:
                    warnings.append(f"{rel}: unreadable ({type(exc).__name__})")
                    continue
                parser = PARSERS[LOCKFILE_NAMES[filename]]
                file_deps, file_warnings = parser(text, rel)
                dependencies.extend(file_deps)
                warnings.extend(file_warnings)
            elif filename in UNSUPPORTED_MANIFESTS:
                unsupported.append(
                    {"path": visible_text(rel, 500), "ecosystem": UNSUPPORTED_MANIFESTS[filename]}
                )
    if len(dependencies) > MAX_DEPS:
        warnings.append(f"dependency count exceeds {MAX_DEPS}; truncated")
        dependencies = dependencies[:MAX_DEPS]
    unique: dict[tuple[str, str, str], Dependency] = {}
    for dep in dependencies:
        unique.setdefault((dep.ecosystem, dep.name, dep.version), dep)
    ordered = sorted(unique.values(), key=lambda item: (item.ecosystem, item.name, item.version))
    return {
        "project": {},
        "scope": {
            "mode": "deps",
            "files_considered": sorted(seen_files)[:100],
            "files_considered_count": len(seen_files),
            "unsupported": unsupported[:200],
        },
        "dependencies": [dep.to_json() for dep in ordered],
        "dependencies_count": len(ordered),
        "warnings": warnings[:100],
        "candidates": [],
    }


def osv_query_packages(dependencies: list[JsonMap]) -> list[tuple[str, str]]:
    """Distinct (osv_ecosystem, name) pairs, bounded."""
    pairs: set[tuple[str, str]] = set()
    for dep in dependencies:
        ecosystem = dep.get("ecosystem")
        name = dep.get("name")
        if isinstance(ecosystem, str) and isinstance(name, str):
            mapped = OSV_ECOSYSTEMS.get(ecosystem)
            if mapped:
                pairs.add((mapped, name))
        if len(pairs) >= 2_000:
            break
    return sorted(pairs)
