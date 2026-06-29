from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypeAlias

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonMap: TypeAlias = dict[str, JsonValue]

TEXT_SUFFIXES: Final = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".php", ".java",
    ".cs", ".rs", ".yml", ".yaml", ".json", ".toml", ".env", ".md", ".txt", ".dockerfile", ".sh",
    ".kt", ".kts", ".swift", ".scala", ".ex", ".exs", ".clj", ".cljs", ".sql", ".xml",
    ".gradle", ".tf", ".tfvars", ".hcl", ".lock", ".sln", ".csproj", ".props", ".targets",
    ".vue", ".svelte", ".astro", ".html", ".conf", ".ini", ".properties",
}
TEXT_NAMES: Final = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Jenkinsfile", "Makefile",
    "Gemfile", "Rakefile", "Procfile", "package.json", "requirements.txt", "go.mod",
    "go.sum", "Cargo.toml", "Cargo.lock", "pyproject.toml", "Pipfile", "composer.json",
    "pom.xml", "build.gradle", "settings.gradle", "mix.exs",
}
SKIP_PARTS: Final = {
    ".git", ".codegraph", ".omo", ".venv", ".vibesec", ".vibesecurity",
    "__pycache__", "build", "dist", "node_modules", "venv",
}
MAX_FILE_BYTES: Final = 1_000_000
MAX_CANDIDATES: Final = 200
SECRET_ASSIGNMENT: Final = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|private[_-]?key|client[_-]?secret|jwt[_-]?secret|aws_secret_access_key|database_url|session[_-]?secret|signing[_-]?secret|oauth[_-]?secret)\b\s*[:=]\s*['\"]?[^'\"\s,;]+",
)
SECRET_TOKEN: Final = re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b")
DATABASE_URL: Final = re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s'\"<>]+", re.IGNORECASE)
AWS_SECRET_ACCESS_KEY: Final = re.compile(r"\b[A-Za-z0-9/+=]{40}\b")


@dataclass(frozen=True, slots=True)
class SkippedFile:
    path: str
    reason: str

    def to_json(self) -> JsonMap:
        return {"path": self.path, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class FileSelection:
    files: tuple[Path, ...]
    skipped: tuple[SkippedFile, ...]

    def skipped_json(self) -> list[JsonMap]:
        return [item.to_json() for item in self.skipped]


def redact(text: str) -> str:
    assigned = SECRET_ASSIGNMENT.sub(lambda item: f"{item.group(1)}=<redacted>", text)
    urls = DATABASE_URL.sub("<redacted-database-url>", assigned)
    tokens = SECRET_TOKEN.sub("<redacted-token>", urls)
    return AWS_SECRET_ACCESS_KEY.sub("<redacted-aws-secret>", tokens)


def redacted_snippet(path: Path, line: str) -> str:
    stripped = line.strip()
    if path.name.startswith(".env") and ("=" in stripped or ":" in stripped):
        separator = "=" if "=" in stripped else ":"
        key = stripped.split(separator, 1)[0].strip()
        return f"{key}{separator}<redacted>"[:180]
    return redact(stripped)[:180]


def rel_path(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def text_candidate_skip_reason(path: Path) -> str:
    if path.is_symlink():
        return "symlink"
    try:
        size = path.stat().st_size
    except OSError:
        return "stat-error"
    if size > MAX_FILE_BYTES:
        return "oversized-file"
    if path.name in TEXT_NAMES or path.name.startswith(".env") or path.suffix.lower() in TEXT_SUFFIXES or ".github" in path.parts:
        return ""
    return "unsupported-file-type"


def stays_within_root(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def select_repo_files(root: Path) -> FileSelection:
    resolved_root = root.resolve()
    files: list[Path] = []
    skipped: list[SkippedFile] = []
    for dirpath, dirnames, filenames in os.walk(resolved_root, topdown=True, followlinks=False):
        current = Path(dirpath)
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
            child = current / dirname
            if dirname in SKIP_PARTS:
                skipped.append(SkippedFile(path=rel_path(resolved_root, child), reason="skipped-directory"))
                continue
            if child.is_symlink():
                skipped.append(SkippedFile(path=rel_path(resolved_root, child), reason="symlink"))
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for filename in sorted(filenames):
            path = current / filename
            if not path.is_file() and not path.is_symlink():
                continue
            if set(path.relative_to(resolved_root).parts).intersection(SKIP_PARTS):
                continue
            if not stays_within_root(resolved_root, path):
                skipped.append(SkippedFile(path=rel_path(resolved_root, path), reason="outside-root"))
                continue
            reason = text_candidate_skip_reason(path)
            if reason:
                skipped.append(SkippedFile(path=rel_path(resolved_root, path), reason=reason))
                continue
            files.append(path)
    return FileSelection(files=tuple(files), skipped=tuple(skipped))
