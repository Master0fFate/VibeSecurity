from __future__ import annotations

import fnmatch
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypeAlias

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonMap: TypeAlias = dict[str, JsonValue]

TEXT_SUFFIXES: Final = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".php", ".java",
    ".cs", ".rs", ".yml", ".yaml", ".json", ".toml", ".env", ".md", ".txt", ".dockerfile", ".sh",
}
TEXT_NAMES: Final = {"Dockerfile", "package.json", "requirements.txt", "go.mod", "Cargo.toml", "pyproject.toml"}
SKIP_PARTS: Final = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
MAX_FILE_BYTES: Final = 1_000_000
MAX_CANDIDATES: Final = 200
SECRET_ASSIGNMENT: Final = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|private[_-]?key|client[_-]?secret|jwt[_-]?secret)\b\s*[:=]\s*['\"]?[^'\"\s,;]+",
)
SECRET_TOKEN: Final = re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b")


@dataclass(frozen=True, slots=True)
class Matcher:
    matcher_id: str
    category: str
    severity_hint: str
    confidence_hint: str
    globs: tuple[str, ...]
    patterns: tuple[str, ...]
    nearby_terms: tuple[str, ...]
    reason: str


def redact(text: str) -> str:
    assigned = SECRET_ASSIGNMENT.sub(lambda item: f"{item.group(1)}=<redacted>", text)
    return SECRET_TOKEN.sub("<redacted-token>", assigned)


def rel_path(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def is_text_candidate(path: Path) -> bool:
    try:
        is_small = path.stat().st_size <= MAX_FILE_BYTES
    except OSError:
        return False
    return is_small and (path.name in TEXT_NAMES or path.suffix.lower() in TEXT_SUFFIXES or ".github" in path.parts)


def iter_repo_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        parts = set(path.relative_to(root).parts)
        if path.is_file() and not parts.intersection(SKIP_PARTS) and is_text_candidate(path):
            files.append(path)
    return files


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def language_for(path: Path) -> str:
    suffix = path.suffix.lower()
    mapping = {
        ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript", ".py": "python",
        ".go": "go", ".rb": "ruby", ".rs": "rust", ".java": "java", ".cs": "csharp", ".php": "php",
    }
    return mapping.get(suffix, "")


def detect_frameworks(text_all: str, files: list[Path]) -> set[str]:
    frameworks: set[str] = set()
    for marker, framework in (
        ("next", "nextjs"), ("react", "react"), ("express", "express"), ("fastify", "fastify"),
        ("@hono", "hono"), ("@nestjs", "nestjs"), ("fastapi", "fastapi"), ("django", "django"),
        ("flask", "flask"), ("rails", "rails"),
    ):
        if marker in text_all:
            frameworks.add(framework)
    if any(path.name == "go.mod" for path in files):
        frameworks.add("go-http")
    return frameworks


def route_like(rel: str) -> bool:
    lower = rel.lower()
    return "/api/" in lower or "routes" in lower or lower.endswith("urls.py") or lower.endswith("views.py")


def detect_inventory(root: Path) -> JsonMap:
    files = iter_repo_files(root)
    rels = [rel_path(root, path) for path in files]
    text_all = "\n".join(read_text(path).lower() for path in files)
    languages = sorted({language for path in files if (language := language_for(path))})
    ai_sdks = sorted(marker for marker in ("openai", "anthropic", "langchain", "pydantic-ai", "vercel-ai") if marker in text_all)
    ci = ["github-actions"] if any(".github/workflows/" in item for item in rels) else []
    return {
        "languages": languages,
        "frameworks": sorted(detect_frameworks(text_all, files)),
        "ai_sdks": ai_sdks,
        "ci": ci,
        "route_files": sorted(item for item in rels if route_like(item))[:50],
    }


def risk_categories_for_path(rel: str) -> list[str]:
    lower = rel.lower()
    categories: set[str] = set()
    for marker, category in (
        ("auth", "auth"), ("login", "auth"), ("admin", "authz"), ("permission", "authz"),
        ("api", "web-api"), ("route", "web-api"), ("workflow", "ci-cd"), (".github", "ci-cd"),
        ("package.json", "supply-chain"), ("lock", "supply-chain"), (".env", "secrets"),
        ("secret", "secrets"), ("agent", "ai-agentic"), ("openai", "ai-agentic"), ("llm", "ai-agentic"),
    ):
        if marker in lower:
            categories.add(category)
    return sorted(categories) or ["general"]


def run_git(root: Path, args: tuple[str, ...]) -> list[str]:
    try:
        result = subprocess.run(("git", *args), cwd=root, check=True, capture_output=True, text=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def changed_files(root: Path) -> list[str]:
    names: list[str] = []
    for args in (("diff", "--name-only"), ("diff", "--cached", "--name-only"), ("ls-files", "--others", "--exclude-standard")):
        names.extend(run_git(root, args))
    return sorted(set(names))


def load_matchers(root: Path) -> list[Matcher]:
    matchers: list[Matcher] = []
    for matcher_root in (Path(__file__).resolve().parents[1] / "references" / "matchers", root / ".vibesecurity"):
        if matcher_root.exists():
            for path in sorted(matcher_root.glob("*.yaml")):
                matchers.extend(parse_matcher_file(path))
    return dedupe_matchers(matchers or fallback_matchers())


def dedupe_matchers(matchers: list[Matcher]) -> list[Matcher]:
    seen: set[str] = set()
    unique: list[Matcher] = []
    for matcher in matchers:
        if matcher.matcher_id not in seen:
            unique.append(matcher)
            seen.add(matcher.matcher_id)
    return unique


def parse_matcher_file(path: Path) -> list[Matcher]:
    matchers: list[Matcher] = []
    draft: dict[str, str] = {}
    lists: dict[str, list[str]] = {"globs": [], "patterns": [], "nearby_terms": []}
    section = ""
    for raw in read_text(path).splitlines():
        line = raw.strip()
        if not line or line == "[]":
            continue
        if line.startswith("- id:"):
            maybe_add_matcher(matchers, draft, lists)
            draft = {"id": clean_value(line.split(":", 1)[1])}
            lists = {"globs": [], "patterns": [], "nearby_terms": []}
            section = ""
        elif line.rstrip(":") in lists:
            section = line.rstrip(":")
        elif line.startswith("- ") and section:
            lists[section].append(clean_value(line[2:]))
        elif ":" in line:
            key, value = line.split(":", 1)
            draft[key.strip()] = clean_value(value)
    maybe_add_matcher(matchers, draft, lists)
    return matchers


def maybe_add_matcher(items: list[Matcher], draft: dict[str, str], lists: dict[str, list[str]]) -> None:
    matcher_id = draft.get("id", "")
    if matcher_id and lists["patterns"]:
        items.append(Matcher(
            matcher_id=matcher_id,
            category=draft.get("category", "other"),
            severity_hint=draft.get("severity_hint", "medium"),
            confidence_hint=draft.get("confidence_hint", "medium"),
            globs=tuple(lists["globs"] or ["**/*"]),
            patterns=tuple(lists["patterns"]),
            nearby_terms=tuple(lists["nearby_terms"]),
            reason=draft.get("reason", "Potential security review candidate."),
        ))


def clean_value(value: str) -> str:
    return value.strip().strip('"').strip("'")


def fallback_matchers() -> list[Matcher]:
    return [
        Matcher("possible-secret-literal", "secrets", "high", "medium", ("**/*",), ("api_key", "private_key", "client_secret"), ("=", ":"), "Potential hardcoded secret."),
        Matcher("ai-output-to-shell", "ai-agentic", "high", "medium", ("**/*.py", "**/*.ts", "**/*.js"), ("subprocess.", "os.system(", "child_process"), ("model", "openai", "agent"), "Potential model output to command execution."),
        Matcher("github-actions-pr-target", "ci-cd", "high", "high", ("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"), ("pull_request_target",), ("checkout", "run:"), "Privileged workflow may execute untrusted fork code."),
    ]


def matcher_applies(matcher: Matcher, rel: str, content: str, line: str) -> bool:
    lower_line = line.lower()
    lower_content = content.lower()
    return (
        any(fnmatch.fnmatch(rel, glob) for glob in matcher.globs)
        and any(pattern.lower() in lower_line for pattern in matcher.patterns)
        and (not matcher.nearby_terms or any(term.lower() in lower_content for term in matcher.nearby_terms))
    )


def scan_candidates(root: Path) -> list[JsonMap]:
    candidates: list[JsonMap] = []
    matchers = load_matchers(root)
    for path in iter_repo_files(root):
        rel = rel_path(root, path)
        content = read_text(path)
        for line_number, line in enumerate(content.splitlines(), start=1):
            for matcher in matchers:
                if matcher_applies(matcher, rel, content, line):
                    candidates.append({
                        "matcher_id": matcher.matcher_id,
                        "path": rel,
                        "line": line_number,
                        "snippet_redacted": redact(line.strip())[:180],
                        "reason": matcher.reason,
                        "category": matcher.category,
                        "severity_hint": matcher.severity_hint,
                        "confidence_hint": matcher.confidence_hint,
                    })
                    if len(candidates) >= MAX_CANDIDATES:
                        return candidates
    return candidates


def inventory_payload(root: Path) -> JsonMap:
    return {"project": detect_inventory(root), "scope": {"mode": "inventory", "files_considered": [], "files_skipped": []}, "candidates": []}


def diff_payload(root: Path) -> JsonMap:
    files = changed_files(root)
    changed = [{"path": item, "risk_categories": risk_categories_for_path(item)} for item in files]
    return {"project": detect_inventory(root), "scope": {"mode": "diff", "files_considered": files, "files_skipped": []}, "changed_files": changed, "candidates": []}


def scan_payload(root: Path) -> JsonMap:
    candidates = scan_candidates(root)
    files = sorted({candidate["path"] for candidate in candidates if isinstance(candidate.get("path"), str)})
    return {"project": detect_inventory(root), "scope": {"mode": "scan", "files_considered": files, "files_skipped": []}, "candidates": candidates}
