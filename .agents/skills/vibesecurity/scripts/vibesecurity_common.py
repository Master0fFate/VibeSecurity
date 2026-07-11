from __future__ import annotations

import json
import os
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypeAlias

JsonValue: TypeAlias = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonMap: TypeAlias = dict[str, JsonValue]

TEXT_SUFFIXES: Final = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".py",
    ".go",
    ".rb",
    ".php",
    ".java",
    ".cs",
    ".rs",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".env",
    ".md",
    ".txt",
    ".dockerfile",
    ".sh",
    ".kt",
    ".kts",
    ".swift",
    ".scala",
    ".ex",
    ".exs",
    ".clj",
    ".cljs",
    ".sql",
    ".xml",
    ".gradle",
    ".tf",
    ".tfvars",
    ".hcl",
    ".lock",
    ".sln",
    ".csproj",
    ".props",
    ".targets",
    ".vue",
    ".svelte",
    ".astro",
    ".html",
    ".conf",
    ".ini",
    ".properties",
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".m",
    ".mm",
    ".fs",
    ".fsx",
    ".vb",
    ".dart",
    ".lua",
    ".r",
    ".sol",
    ".proto",
    ".graphql",
    ".gql",
    ".bicep",
}
TEXT_NAMES: Final = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Jenkinsfile",
    "Makefile",
    "Gemfile",
    "Rakefile",
    "Procfile",
    "package.json",
    "requirements.txt",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pyproject.toml",
    "Pipfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "settings.gradle",
    "mix.exs",
    ".gitignore",
    ".dockerignore",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    ".pypirc",
    "gradle.properties",
}
TEXT_NAMES_CASEFOLD: Final = {name.casefold() for name in TEXT_NAMES}
SKIP_PARTS: Final = {
    ".git",
    ".hg",
    ".svn",
    ".codegraph",
    ".omo",
    ".venv",
    ".vibesec",
    ".vibesecurity",
    ".tox",
    ".nox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".terraform",
    ".gradle",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    "venv",
    "vendor",
    "target",
    "pods",
    "deriveddata",
}
MAX_FILE_BYTES: Final = 1_000_000
MAX_CANDIDATES: Final = 200
MAX_FILES: Final = 25_000
MAX_TOTAL_BYTES: Final = 250_000_000
MAX_SKIPPED_SAMPLES: Final = 100
MAX_JSON_INPUT_BYTES: Final = 5_000_000
MAX_FINDING_ITEMS: Final = 1_000
MAX_DISPLAY_CHARS: Final = 8_000
SECRET_KEY: Final = (
    r"api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|passwd|private[_-]?key|"
    r"client[_-]?secret|jwt[_-]?secret|aws_secret_access_key|database_url|session[_-]?secret|"
    r"signing[_-]?secret|oauth[_-]?secret|webhook[_-]?secret"
)
QUOTED_SECRET_ASSIGNMENT: Final = re.compile(
    rf"(?i)\b({SECRET_KEY})\b(\s*[:=]\s*)(['\"])[^\r\n]*?\3",
)
SECRET_ASSIGNMENT: Final = re.compile(
    rf"(?i)\b({SECRET_KEY})\b(\s*[:=]\s*)[^\s,;]+",
)
SECRET_TOKEN: Final = re.compile(
    r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{16,}|AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{30,}|sk_live_[0-9A-Za-z]{16,})\b",
)
JWT_TOKEN: Final = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
AUTHORIZATION_HEADER: Final = re.compile(
    r"(?i)\b(authorization)(\s*[:=]\s*)(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+"
)
DATABASE_URL: Final = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s'\"<>]+",
    re.IGNORECASE,
)
CREDENTIAL_URL: Final = re.compile(
    r"\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^@\s/]+@",
    re.IGNORECASE,
)
PRIVATE_KEY: Final = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


@dataclass(frozen=True, slots=True)
class SkippedFile:
    path: str
    reason: str

    def to_json(self) -> JsonMap:
        return {"path": display_path(self.path), "reason": self.reason}


@dataclass(frozen=True, slots=True)
class FileSelection:
    files: tuple[Path, ...]
    skipped: tuple[SkippedFile, ...]
    skipped_count: int
    skipped_by_reason: tuple[tuple[str, int], ...]
    files_seen: int
    bytes_selected: int
    truncated: bool
    limit_reason: str
    max_files: int
    max_total_bytes: int

    def skipped_json(self) -> list[JsonMap]:
        return [item.to_json() for item in self.skipped]


def redact(text: str) -> str:
    keys = PRIVATE_KEY.sub("<redacted-private-key>", text)
    authorization = AUTHORIZATION_HEADER.sub(
        lambda item: f"{item.group(1)}{item.group(2)}<redacted>", keys
    )
    quoted = QUOTED_SECRET_ASSIGNMENT.sub(
        lambda item: f"{item.group(1)}{item.group(2)}<redacted>", authorization
    )
    assigned = SECRET_ASSIGNMENT.sub(
        lambda item: f"{item.group(1)}{item.group(2)}<redacted>", quoted
    )
    urls = DATABASE_URL.sub("<redacted-database-url>", assigned)
    credentials = CREDENTIAL_URL.sub(
        lambda item: f"{item.group(1)}<redacted-userinfo>@", urls
    )
    tokens = SECRET_TOKEN.sub("<redacted-token>", credentials)
    return JWT_TOKEN.sub("<redacted-token>", tokens)


def visible_text(text: str, limit: int = MAX_DISPLAY_CHARS) -> str:
    rendered: list[str] = []
    for character in redact(text)[:limit]:
        category = unicodedata.category(character)
        if character in {"\n", "\t"} or category not in {"Cc", "Cf", "Cs"}:
            rendered.append(character)
        else:
            codepoint = ord(character)
            rendered.append(
                f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"
            )
    if len(text) > limit:
        rendered.append("…<truncated>")
    return "".join(rendered)


def display_path(value: str) -> str:
    return visible_text(value, 1_000)


def redacted_snippet(path: Path, line: str) -> str:
    stripped = line.strip()
    if path.name.casefold().startswith(".env") and ("=" in stripped or ":" in stripped):
        separator = "=" if "=" in stripped else ":"
        key = stripped.split(separator, 1)[0].strip()
        return visible_text(f"{key}{separator}<redacted>", 180)
    return visible_text(stripped, 180)


def rel_path(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def load_json_file(path: Path) -> JsonValue:
    size = path.stat().st_size
    if size > MAX_JSON_INPUT_BYTES:
        raise ValueError(f"JSON input exceeds {MAX_JSON_INPUT_BYTES} bytes: {path}")
    value: JsonValue = json.loads(path.read_text(encoding="utf-8"))
    return value


def text_candidate_skip_reason(path: Path) -> str:
    if path.is_symlink():
        return "symlink"
    try:
        size = path.stat().st_size
    except OSError:
        return "stat-error"
    if size > MAX_FILE_BYTES:
        return "oversized-file"
    if (
        path.name.casefold() in TEXT_NAMES_CASEFOLD
        or path.name.casefold().startswith(".env")
        or path.suffix.lower() in TEXT_SUFFIXES
        or ".github" in {part.casefold() for part in path.parts}
    ):
        return ""
    return "unsupported-file-type"


def stays_within_root(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def selection_scope_fields(selection: FileSelection) -> JsonMap:
    return {
        "files_skipped": selection.skipped_json(),
        "files_skipped_count": selection.skipped_count,
        "files_skipped_by_reason": {
            reason: count for reason, count in selection.skipped_by_reason
        },
        "selection_truncated": selection.truncated,
        "selection_limit_reason": selection.limit_reason,
        "files_seen": selection.files_seen,
        "bytes_selected": selection.bytes_selected,
        "selection_limits": {
            "max_files": selection.max_files,
            "max_total_bytes": selection.max_total_bytes,
            "max_file_bytes": MAX_FILE_BYTES,
        },
    }


def select_repo_files(
    root: Path,
    *,
    max_files: int = MAX_FILES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> FileSelection:
    resolved_root = root.resolve()
    files: list[Path] = []
    skipped: list[SkippedFile] = []
    skipped_reasons: Counter[str] = Counter()
    files_seen = 0
    bytes_selected = 0
    truncated = False
    limit_reason = ""

    def skip(path: Path, reason: str) -> None:
        skipped_reasons[reason] += 1
        if len(skipped) < MAX_SKIPPED_SAMPLES:
            try:
                label = rel_path(resolved_root, path)
            except ValueError:
                label = "<outside-root>"
            skipped.append(SkippedFile(path=label, reason=reason))

    def walk_error(error: OSError) -> None:
        path = (
            Path(error.filename) if isinstance(error.filename, str) else resolved_root
        )
        skip(path, "walk-error")

    for dirpath, dirnames, filenames in os.walk(
        resolved_root, topdown=True, onerror=walk_error, followlinks=False
    ):
        current = Path(dirpath)
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
            child = current / dirname
            if dirname.lower() in SKIP_PARTS:
                skip(child, "skipped-directory")
                continue
            if child.is_symlink():
                skip(child, "symlink")
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for filename in sorted(filenames):
            path = current / filename
            files_seen += 1
            if not path.is_file() and not path.is_symlink():
                continue
            if {
                part.lower() for part in path.relative_to(resolved_root).parts
            }.intersection(SKIP_PARTS):
                continue
            if not stays_within_root(resolved_root, path):
                skip(path, "outside-root")
                continue
            reason = text_candidate_skip_reason(path)
            if reason:
                skip(path, reason)
                continue
            try:
                size = path.stat().st_size
            except OSError:
                skip(path, "stat-error")
                continue
            if len(files) >= max_files:
                skip(path, "selection-budget")
                truncated = True
                limit_reason = "max-files"
                dirnames.clear()
                break
            if bytes_selected + size > max_total_bytes:
                skip(path, "selection-budget")
                truncated = True
                limit_reason = "max-total-bytes"
                dirnames.clear()
                break
            files.append(path)
            bytes_selected += size
        if truncated:
            break
    return FileSelection(
        files=tuple(files),
        skipped=tuple(skipped),
        skipped_count=sum(skipped_reasons.values()),
        skipped_by_reason=tuple(sorted(skipped_reasons.items())),
        files_seen=files_seen,
        bytes_selected=bytes_selected,
        truncated=truncated,
        limit_reason=limit_reason,
        max_files=max_files,
        max_total_bytes=max_total_bytes,
    )
