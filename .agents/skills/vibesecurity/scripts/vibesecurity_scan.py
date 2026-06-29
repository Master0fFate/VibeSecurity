from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from vibesecurity_common import JsonMap, MAX_CANDIDATES, read_text, redacted_snippet, rel_path, select_repo_files
from vibesecurity_coverage import CoverageInput, coverage_payload
from vibesecurity_inventory import detect_inventory
from vibesecurity_matchers import Matcher, glob_matches, line_window, load_matchers, matched_nearby_terms, matcher_applies
from vibesecurity_prioritize import candidate_sort_key, priority_fields


@dataclass(frozen=True, slots=True)
class GitNames:
    names: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScanResult:
    candidates: list[JsonMap]
    truncated: bool
    total_candidates: int
    matcher_ids: tuple[str, ...]
    rule_packs: tuple[str, ...]


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
                    candidate = {
                        "matcher_id": matcher.matcher_id,
                        "rule_pack": matcher.rule_pack,
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
                    }
                    candidate.update(priority_fields(rel, matcher.severity_hint, matcher.category, matcher.matcher_id))
                    candidates.append(candidate)
    ranked = sorted(candidates, key=candidate_sort_key)
    returned = ranked[:MAX_CANDIDATES]
    return ScanResult(
        candidates=returned,
        truncated=len(ranked) > MAX_CANDIDATES,
        total_candidates=len(ranked),
        matcher_ids=tuple(sorted({matcher.matcher_id for matcher in matchers})),
        rule_packs=tuple(sorted({matcher.rule_pack for matcher in matchers})),
    )


def coverage_for(root: Path, project: JsonMap, selection_matchers: tuple[str, ...], rule_packs: tuple[str, ...]) -> JsonMap:
    selection = select_repo_files(root)
    return coverage_payload(CoverageInput(
        root=root,
        project=project,
        selection=selection,
        matcher_ids=selection_matchers,
        rule_packs=rule_packs,
    ))


def inventory_payload(root: Path) -> JsonMap:
    selection = select_repo_files(root)
    project = detect_inventory(root)
    matchers = load_matchers(root)
    return {
        "project": project,
        "scope": {
            "mode": "inventory",
            "files_considered": [rel_path(root.resolve(), path) for path in selection.files][:25],
            "files_considered_count": len(selection.files),
            "files_skipped": selection.skipped_json(),
            "coverage": coverage_for(root, project, tuple(matcher.matcher_id for matcher in matchers), tuple(matcher.rule_pack for matcher in matchers)),
        },
        "candidates": [],
    }


def diff_payload(root: Path) -> JsonMap:
    selection = select_repo_files(root)
    result = changed_files(root)
    project = detect_inventory(root)
    matchers = load_matchers(root)
    changed = [{"path": item, "risk_categories": risk_categories_for_path(item)} for item in result.names]
    return {
        "project": project,
        "scope": {
            "mode": "diff",
            "files_considered": list(result.names),
            "files_considered_count": len(result.names),
            "files_skipped": selection.skipped_json(),
            "coverage": coverage_for(root, project, tuple(matcher.matcher_id for matcher in matchers), tuple(matcher.rule_pack for matcher in matchers)),
        },
        "changed_files": changed,
        "warnings": list(result.warnings),
        "candidates": [],
    }


def scan_payload(root: Path) -> JsonMap:
    selection = select_repo_files(root)
    project = detect_inventory(root)
    result = scan_candidates(root)
    files = sorted({candidate["path"] for candidate in result.candidates if isinstance(candidate.get("path"), str)})
    return {
        "project": project,
        "scope": {
            "mode": "scan",
            "files_considered": [rel_path(root.resolve(), path) for path in selection.files][:500],
            "files_considered_count": len(selection.files),
            "candidate_files": files,
            "files_skipped": selection.skipped_json(),
            "coverage": coverage_for(root, project, result.matcher_ids, result.rule_packs),
            "rule_packs": list(result.rule_packs),
            "matchers_loaded": list(result.matcher_ids),
        },
        "truncated": result.truncated,
        "candidate_limit": MAX_CANDIDATES,
        "candidates_total": result.total_candidates,
        "candidates_returned": len(result.candidates),
        "candidates": result.candidates,
    }
