from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vibesecurity_common import read_text

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
    rule_pack: str


def load_matchers(root: Path) -> list[Matcher]:
    matchers: list[Matcher] = []
    bundled = Path(__file__).resolve().parents[1] / "references" / "matchers"
    for matcher_root in (bundled, root / ".vibesecurity"):
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
    draft: dict[str, str] = {"rule_pack": path.stem}
    lists: dict[str, list[str]] = {"globs": [], "patterns": [], "nearby_terms": []}
    section = ""
    for raw in read_text(path).splitlines():
        line = raw.strip()
        if not line or line == "[]":
            continue
        if line.startswith("- id:"):
            maybe_add_matcher(matchers, draft, lists)
            draft = {"id": clean_value(line.split(":", 1)[1]), "rule_pack": path.stem}
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
            rule_pack=draft.get("rule_pack", "local"),
        ))


def clean_value(value: str) -> str:
    return value.strip().strip('"').strip("'")


def fallback_matchers() -> list[Matcher]:
    return [
        Matcher(
            matcher_id="possible-secret-literal",
            category="secrets",
            severity_hint="high",
            confidence_hint="medium",
            globs=("**/*",),
            patterns=("api_key", "private_key", "client_secret"),
            nearby_terms=("=", ":"),
            reason="Potential hardcoded secret.",
            review_prompt="Confirm whether the value is real without printing it.",
            rule_pack="fallback",
        ),
        Matcher(
            matcher_id="ai-output-to-shell",
            category="ai-agentic",
            severity_hint="high",
            confidence_hint="medium",
            globs=("**/*.py", "**/*.ts", "**/*.js"),
            patterns=("subprocess.", "os.system(", "child_process"),
            nearby_terms=("model", "openai", "agent"),
            reason="Potential model output to command execution.",
            review_prompt="Confirm whether model output can influence command execution.",
            rule_pack="fallback",
        ),
        Matcher(
            matcher_id="github-actions-pr-target",
            category="ci-cd",
            severity_hint="high",
            confidence_hint="high",
            globs=("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"),
            patterns=("pull_request_target",),
            nearby_terms=("checkout", "run:"),
            reason="Privileged workflow may execute untrusted fork code.",
            review_prompt="Confirm whether attacker-controlled code runs with trusted token or secrets.",
            rule_pack="fallback",
        ),
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
