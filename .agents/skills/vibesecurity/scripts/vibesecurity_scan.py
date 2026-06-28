from __future__ import annotations

import fnmatch
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, MAX_CANDIDATES, read_text, redacted_snippet, rel_path, select_repo_files
from vibesecurity_inventory import detect_inventory

NEARBY_WINDOW_LINES: Final = 6

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
    review_prompt: str


@dataclass(frozen=True, slots=True)
class GitNames:
    names: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScanResult:
    candidates: list[JsonMap]
    truncated: bool


def iter_repo_files(root: Path) -> list[Path]:
    return list(select_repo_files(root).files)


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


def run_git(root: Path, args: tuple[str, ...]) -> GitNames:
    label = "git " + " ".join(args)
    try:
        result = subprocess.run(("git", *args), cwd=root, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        return GitNames(names=(), warnings=(f"{label} failed: git executable not found",))
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip().splitlines()
        message = detail[0] if detail else "unknown git error"
        return GitNames(names=(), warnings=(f"{label} failed: {message}",))
    return GitNames(names=tuple(line.strip() for line in result.stdout.splitlines() if line.strip()), warnings=())


def changed_files(root: Path) -> GitNames:
    names: list[str] = []
    warnings: list[str] = []
    for args in (("diff", "--name-only"), ("diff", "--cached", "--name-only"), ("ls-files", "--others", "--exclude-standard")):
        result = run_git(root, args)
        names.extend(result.names)
        warnings.extend(result.warnings)
    return GitNames(names=tuple(sorted(set(names))), warnings=tuple(warnings))


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
            review_prompt=draft.get("review_prompt", "Validate reachability, boundary crossing, and impact before confirming."),
        ))


def clean_value(value: str) -> str:
    return value.strip().strip('"').strip("'")


def fallback_matchers() -> list[Matcher]:
    return [
        Matcher("possible-secret-literal", "secrets", "high", "medium", ("**/*",), ("api_key", "private_key", "client_secret"), ("=", ":"), "Potential hardcoded secret.", "Confirm whether the value is real without printing it."),
        Matcher("ai-output-to-shell", "ai-agentic", "high", "medium", ("**/*.py", "**/*.ts", "**/*.js"), ("subprocess.", "os.system(", "child_process"), ("model", "openai", "agent"), "Potential model output to command execution.", "Confirm whether model output can influence command execution."),
        Matcher("github-actions-pr-target", "ci-cd", "high", "high", ("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"), ("pull_request_target",), ("checkout", "run:"), "Privileged workflow may execute untrusted fork code.", "Confirm whether attacker-controlled code runs with trusted token or secrets."),
    ]


def matched_nearby_terms(matcher: Matcher, window_lines: list[str]) -> list[str]:
    window = "\n".join(window_lines).lower()
    return [term for term in matcher.nearby_terms if term.lower() in window]


def glob_matches(rel: str, glob: str) -> bool:
    if glob == "**/*":
        return True
    variants = {glob}
    queue = [glob]
    while queue:
        item = queue.pop()
        if "/**/" not in item:
            continue
        collapsed = item.replace("/**/", "/", 1)
        if collapsed not in variants:
            variants.add(collapsed)
            queue.append(collapsed)
    for variant in variants:
        if fnmatch.fnmatch(rel, variant):
            return True
        if variant.startswith("**/") and fnmatch.fnmatch(rel, variant[3:]):
            return True
    return False


def matcher_applies(matcher: Matcher, rel: str, line: str, window_lines: list[str]) -> bool:
    lower_line = line.lower()
    return (
        any(glob_matches(rel, glob) for glob in matcher.globs)
        and any(pattern.lower() in lower_line for pattern in matcher.patterns)
        and (not matcher.nearby_terms or bool(matched_nearby_terms(matcher, window_lines)))
    )


def line_window(lines: list[str], line_index: int) -> list[str]:
    start = max(0, line_index - NEARBY_WINDOW_LINES)
    stop = min(len(lines), line_index + NEARBY_WINDOW_LINES + 1)
    return lines[start:stop]


def scan_candidates(root: Path) -> ScanResult:
    candidates: list[JsonMap] = []
    matchers = load_matchers(root)
    for path in iter_repo_files(root):
        rel = rel_path(root, path)
        lines = read_text(path).splitlines()
        for line_index, line in enumerate(lines):
            window = line_window(lines, line_index)
            for matcher in matchers:
                if matcher_applies(matcher, rel, line, window):
                    candidates.append({
                        "matcher_id": matcher.matcher_id,
                        "path": rel,
                        "line": line_index + 1,
                        "snippet_redacted": redacted_snippet(path, line),
                        "nearby_terms_matched": matched_nearby_terms(matcher, window),
                        "reason": matcher.reason,
                        "review_prompt": matcher.review_prompt,
                        "category": matcher.category,
                        "severity_hint": matcher.severity_hint,
                        "confidence_hint": matcher.confidence_hint,
                        "status": "needs-review",
                    })
                    if len(candidates) >= MAX_CANDIDATES:
                        return ScanResult(candidates=candidates, truncated=True)
    return ScanResult(candidates=candidates, truncated=False)


def inventory_payload(root: Path) -> JsonMap:
    selection = select_repo_files(root)
    return {"project": detect_inventory(root), "scope": {"mode": "inventory", "files_considered": [], "files_skipped": selection.skipped_json()}, "candidates": []}


def diff_payload(root: Path) -> JsonMap:
    selection = select_repo_files(root)
    result = changed_files(root)
    changed = [{"path": item, "risk_categories": risk_categories_for_path(item)} for item in result.names]
    return {"project": detect_inventory(root), "scope": {"mode": "diff", "files_considered": list(result.names), "files_skipped": selection.skipped_json()}, "changed_files": changed, "warnings": list(result.warnings), "candidates": []}


def scan_payload(root: Path) -> JsonMap:
    selection = select_repo_files(root)
    result = scan_candidates(root)
    files = sorted({candidate["path"] for candidate in result.candidates if isinstance(candidate.get("path"), str)})
    return {
        "project": detect_inventory(root),
        "scope": {"mode": "scan", "files_considered": files, "files_skipped": selection.skipped_json()},
        "truncated": result.truncated,
        "candidate_limit": MAX_CANDIDATES,
        "candidates_returned": len(result.candidates),
        "candidates": result.candidates,
    }
