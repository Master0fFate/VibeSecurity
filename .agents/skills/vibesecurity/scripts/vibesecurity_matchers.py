from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vibesecurity_common import stays_within_root
from vibesecurity_standards import valid_asvs, valid_cwe, valid_owasp

NEARBY_WINDOW_LINES: Final = 6
MAX_MATCHER_FILE_BYTES: Final = 256_000
MAX_MATCHERS: Final = 512
MAX_LIST_VALUES: Final = 64
MAX_FIELD_CHARS: Final = 500
MAX_REGEX_CHARS: Final = 300
MAX_REGEX_LINE_CHARS: Final = 4_000
MATCHER_ID: Final = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
BACKREFERENCE: Final = re.compile(r"\\[1-9]|\(\?P=")
UNBOUNDED_BRACE: Final = re.compile(r"\{\d*,\}")
SCALAR_FIELDS: Final = {
    "category",
    "severity_hint",
    "confidence_hint",
    "reason",
    "review_prompt",
    "cwe",
    "owasp",
    "asvs",
}
LIST_FIELDS: Final = {
    "globs",
    "patterns",
    "regex_patterns",
    "exclude_patterns",
    "same_line_terms",
    "nearby_terms",
    "nearby_excludes",
    "positive_examples",
    "negative_examples",
}
LOWERCASE_LIST_FIELDS: Final = {
    "patterns",
    "exclude_patterns",
    "same_line_terms",
    "nearby_terms",
    "nearby_excludes",
}
ALLOWED_CATEGORIES: Final = {
    "authz",
    "authn",
    "injection",
    "ssrf",
    "xss",
    "secrets",
    "supply-chain",
    "ci-cd",
    "ai-agentic",
    "privacy",
    "crypto",
    "availability",
    "other",
}
ALLOWED_SEVERITIES: Final = {"critical", "high", "medium", "low", "info"}
ALLOWED_CONFIDENCE: Final = {"high", "medium", "low"}
PROJECT_SPECIFIC_MARKERS: Final = (
    "\\Users\\",
    "/home/",
    "/Users/",
    "C:\\",
    "D:\\",
)


def is_project_specific_value(value: str, glob: bool = False) -> bool:
    """Reject absolute paths, home expansions, and user-directory markers.

    Bundled and taught matchers must describe vulnerability classes, never one
    machine, user, or repository. Globs may never be absolute; substring
    patterns may start with a slash (for example a well-known socket path).
    """
    stripped = value.strip()
    if stripped.startswith("~") or (glob and stripped.startswith("/")):
        return True
    return any(marker in stripped for marker in PROJECT_SPECIFIC_MARKERS)


def has_nested_unbounded_quantifier(pattern: str) -> bool:
    stack: list[bool] = []
    in_class = False
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            index += 2
            continue
        if in_class:
            in_class = character != "]"
            index += 1
            continue
        if character == "[":
            in_class = True
        elif character == "(":
            stack.append(False)
        elif character == ")":
            inner_repeats = stack.pop() if stack else False
            following = pattern[index + 1 : index + 2]
            if inner_repeats and (following in {"*", "+"} or UNBOUNDED_BRACE.match(pattern[index + 1 :])):
                return True
        elif character in {"*", "+"} or UNBOUNDED_BRACE.match(pattern[index:]):
            if stack:
                stack[-1] = True
        index += 1
    return False


def unsafe_regex_reason(pattern: str) -> str:
    if len(pattern) > MAX_REGEX_CHARS:
        return f"regex exceeds {MAX_REGEX_CHARS} characters"
    if BACKREFERENCE.search(pattern):
        return "regex backreferences are not allowed"
    if has_nested_unbounded_quantifier(pattern):
        return "regex nests an unbounded quantifier inside a repeated group"
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"regex does not compile ({exc.msg})"
    return ""


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
    positive_examples: tuple[str, ...] = ()
    negative_examples: tuple[str, ...] = ()
    regex_patterns: tuple[re.Pattern[str], ...] = ()
    exclude_patterns: tuple[str, ...] = ()
    same_line_terms: tuple[str, ...] = ()
    nearby_excludes: tuple[str, ...] = ()
    cwe: str = ""
    owasp: str = ""
    asvs: str = ""


@dataclass(frozen=True, slots=True)
class MatcherCatalog:
    matchers: tuple[Matcher, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MatcherFile:
    path: Path
    label: str
    bundled: bool


def matcher_paths(root: Path) -> list[MatcherFile]:
    resolved_root = root.resolve()
    bundled = Path(__file__).resolve().parents[1] / "references" / "matchers"
    bundled_paths = sorted(bundled.glob("*.yaml"), key=lambda path: path.as_posix())
    local_paths: list[Path] = []
    local = resolved_root / ".vibesecurity"
    if local.exists():
        local_paths.extend(local.glob("*.yaml"))
        local_paths.extend((local / "matchers").glob("*.yaml"))
    bundled_files = [
        MatcherFile(path, f"bundled/{path.name}", True) for path in bundled_paths
    ]
    local_files = [
        MatcherFile(path, path.relative_to(resolved_root).as_posix(), False)
        for path in sorted(set(local_paths), key=lambda item: item.as_posix())
    ]
    return [*bundled_files, *local_files]


def load_matcher_catalog(root: Path) -> MatcherCatalog:
    matchers: list[Matcher] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for matcher_file in matcher_paths(root):
        path = matcher_file.path
        source = matcher_file.label
        if path.is_symlink() or (
            not matcher_file.bundled and not stays_within_root(root, path)
        ):
            warnings.append(f"{source}: symlink or outside-root matcher ignored")
            continue
        parsed, parse_warnings = parse_matcher_file_with_warnings(path)
        warnings.extend(f"{source}: {warning}" for warning in parse_warnings)
        for matcher in parsed:
            if matcher.matcher_id in seen:
                warnings.append(
                    f"{source}: duplicate matcher id '{matcher.matcher_id}' ignored"
                )
                continue
            if len(matchers) >= MAX_MATCHERS:
                warnings.append(
                    f"matcher limit {MAX_MATCHERS} reached; remaining rules ignored"
                )
                return MatcherCatalog(tuple(matchers), tuple(warnings))
            seen.add(matcher.matcher_id)
            matchers.append(matcher)
    if not matchers:
        warnings.append("no valid matcher files loaded; using built-in fallback rules")
        matchers = fallback_matchers()
    return MatcherCatalog(tuple(matchers), tuple(warnings))


def load_matchers(root: Path) -> list[Matcher]:
    return list(load_matcher_catalog(root).matchers)


def parse_matcher_file(path: Path) -> list[Matcher]:
    matchers, _ = parse_matcher_file_with_warnings(path)
    return matchers


def validate_matcher_examples(matcher: Matcher) -> tuple[int, int, list[str]]:
    """Run a matcher's own examples through the engine.

    Returns (positives_fired, negatives_fired, problems). Every bundled
    matcher must fire on all positive examples and on no negative examples.
    """
    problems: list[str] = []
    positives = 0
    negatives = 0
    for example in matcher.positive_examples:
        lines = example.splitlines() or [example]
        if any(
            matcher_matches_line(matcher, line, lines) for line in lines
        ):
            positives += 1
        else:
            problems.append(f"positive example did not fire: {example[:80]}")
    for example in matcher.negative_examples:
        lines = example.splitlines() or [example]
        if any(matcher_matches_line(matcher, line, lines) for line in lines):
            negatives += 1
            problems.append(f"negative example fired: {example[:80]}")
    return positives, negatives, problems


def parse_matcher_file_with_warnings(path: Path) -> tuple[list[Matcher], list[str]]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return [], [f"could not stat matcher file ({type(exc).__name__})"]
    if size > MAX_MATCHER_FILE_BYTES:
        return [], [f"file exceeds {MAX_MATCHER_FILE_BYTES} bytes and was ignored"]
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [], [f"could not read matcher file ({type(exc).__name__})"]
    matchers: list[Matcher] = []
    warnings: list[str] = []
    draft: dict[str, str] = {"rule_pack": path.stem}
    lists: dict[str, list[str]] = {field: [] for field in LIST_FIELDS}
    section = ""
    start_line = 0
    for line_number, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line == "[]":
            continue
        if line.startswith("- id:"):
            maybe_add_matcher(matchers, draft, lists, warnings, start_line)
            start_line = line_number
            draft = {"id": clean_value(line.split(":", 1)[1]), "rule_pack": path.stem}
            lists = {field: [] for field in LIST_FIELDS}
            section = ""
            continue
        if line.endswith(":") and line[:-1] in LIST_FIELDS:
            section = line[:-1]
            continue
        if line.startswith("- "):
            if not section:
                warnings.append(
                    f"line {line_number}: list value outside a supported section ignored"
                )
                continue
            lists[section].append(clean_value(line[2:]))
            continue
        if ":" not in line:
            warnings.append(f"line {line_number}: unsupported matcher syntax ignored")
            section = ""
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        section = ""
        if key not in SCALAR_FIELDS:
            warnings.append(f"line {line_number}: unknown field '{key}' ignored")
            continue
        cleaned = clean_value(value)
        if cleaned in {">", "|"}:
            warnings.append(
                f"line {line_number}: multiline scalars are unsupported; use one quoted line"
            )
            continue
        draft[key] = cleaned
    maybe_add_matcher(matchers, draft, lists, warnings, start_line)
    return matchers, warnings


def invalid_matcher_reason(draft: dict[str, str], lists: dict[str, list[str]]) -> str:
    matcher_id = draft.get("id", "")
    if not MATCHER_ID.fullmatch(matcher_id):
        return "id must use 2-64 lowercase letters, numbers, or hyphens"
    category = draft.get("category", "other")
    if category not in ALLOWED_CATEGORIES:
        return f"unsupported category '{category}'"
    severity = draft.get("severity_hint", "medium")
    if severity not in ALLOWED_SEVERITIES:
        return f"unsupported severity_hint '{severity}'"
    confidence = draft.get("confidence_hint", "medium")
    if confidence not in ALLOWED_CONFIDENCE:
        return f"unsupported confidence_hint '{confidence}'"
    if not lists.get("patterns") and not lists.get("regex_patterns"):
        return "at least one pattern is required"
    for field, values in lists.items():
        if len(values) > MAX_LIST_VALUES:
            return f"{field} exceeds {MAX_LIST_VALUES} values"
        if any(not value or len(value) > MAX_FIELD_CHARS for value in values):
            return f"{field} contains an empty or oversized value"
        if field in {"globs", "patterns", "regex_patterns"}:
            for value in values:
                if is_project_specific_value(value, glob=field == "globs"):
                    return f"{field} value looks project-specific or machine-specific: {value[:80]}"
    for value in lists.get("regex_patterns", []):
        reason = unsafe_regex_reason(value)
        if reason:
            return f"regex_patterns rejected: {reason}: {value[:80]}"
    for field in ("reason", "review_prompt"):
        if len(draft.get(field, "")) > MAX_FIELD_CHARS:
            return f"{field} exceeds {MAX_FIELD_CHARS} characters"
    if not valid_cwe(draft.get("cwe", "")):
        return "cwe must be one or more comma-separated CWE-<number> ids"
    if not valid_owasp(draft.get("owasp", "")):
        return "owasp must use A<nn>:2025, LLM<nn>:2025, or ASI<nn>:2026 ids"
    if not valid_asvs(draft.get("asvs", "")):
        return "asvs must use V<chapter>.<section>.<requirement> ids"
    return ""


def maybe_add_matcher(
    items: list[Matcher],
    draft: dict[str, str],
    lists: dict[str, list[str]],
    warnings: list[str] | None = None,
    line_number: int = 0,
) -> None:
    if not draft.get("id"):
        return
    reason = invalid_matcher_reason(draft, lists)
    if reason:
        if warnings is not None:
            warnings.append(
                f"line {line_number}: matcher '{draft.get('id', 'unknown')}' ignored: {reason}"
            )
        return
    lowered = {
        field: tuple(value.lower() for value in lists.get(field, []))
        for field in LOWERCASE_LIST_FIELDS
    }
    items.append(
        Matcher(
            matcher_id=draft["id"],
            category=draft.get("category", "other"),
            severity_hint=draft.get("severity_hint", "medium"),
            confidence_hint=draft.get("confidence_hint", "medium"),
            globs=tuple(lists["globs"] or ["**/*"]),
            patterns=lowered["patterns"],
            nearby_terms=lowered["nearby_terms"],
            reason=draft.get("reason", "Potential security review candidate."),
            review_prompt=draft.get(
                "review_prompt",
                "Validate reachability, boundary crossing, and impact before confirming.",
            ),
            rule_pack=draft.get("rule_pack", "local"),
            positive_examples=tuple(lists["positive_examples"]),
            negative_examples=tuple(lists["negative_examples"]),
            regex_patterns=tuple(re.compile(value) for value in lists.get("regex_patterns", [])),
            exclude_patterns=lowered["exclude_patterns"],
            same_line_terms=lowered["same_line_terms"],
            nearby_excludes=lowered["nearby_excludes"],
            cwe=draft.get("cwe", ""),
            owasp=draft.get("owasp", ""),
            asvs=draft.get("asvs", ""),
        )
    )


def clean_value(value: str) -> str:
    """Unquote one scalar.

    Double-quoted values honour only the \\\" escape so regex escapes such as
    \\b survive untouched; single-quoted values honour the YAML '' escape.
    """
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == '"' and stripped[-1] == '"':
        return stripped[1:-1].replace('\\"', '"')
    if len(stripped) >= 2 and stripped[0] == "'" and stripped[-1] == "'":
        return stripped[1:-1].replace("''", "'")
    return stripped


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
            cwe="CWE-798",
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
            cwe="CWE-78",
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
            cwe="CWE-829",
        ),
    ]


def matched_nearby_terms(matcher: Matcher, window_lines: list[str]) -> list[str]:
    window = "\n".join(window_lines).lower()
    return [term for term in matcher.nearby_terms if term in window]


def needs_window(matcher: Matcher) -> bool:
    return bool(matcher.nearby_terms or matcher.nearby_excludes)


def glob_matches(rel: str, glob: str) -> bool:
    if glob == "**/*":
        return True
    normalized_rel = rel.replace("\\", "/").casefold()
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
        normalized_variant = variant.replace("\\", "/").casefold()
        if fnmatch.fnmatchcase(normalized_rel, normalized_variant):
            return True
        if normalized_variant.startswith("**/") and fnmatch.fnmatchcase(
            normalized_rel, normalized_variant[3:]
        ):
            return True
    return False


def matcher_matches_line(matcher: Matcher, line: str, window_lines: list[str]) -> bool:
    lower_line = line.lower()
    if not any(pattern in lower_line for pattern in matcher.patterns) and not any(
        regex.search(line[:MAX_REGEX_LINE_CHARS]) for regex in matcher.regex_patterns
    ):
        return False
    if any(excluded in lower_line for excluded in matcher.exclude_patterns):
        return False
    if matcher.same_line_terms and not any(term in lower_line for term in matcher.same_line_terms):
        return False
    if matcher.nearby_terms and not matched_nearby_terms(matcher, window_lines):
        return False
    if matcher.nearby_excludes:
        window = "\n".join(window_lines).lower()
        if any(term in window for term in matcher.nearby_excludes):
            return False
    return True


def matcher_applies(
    matcher: Matcher, rel: str, line: str, window_lines: list[str]
) -> bool:
    return any(
        glob_matches(rel, glob) for glob in matcher.globs
    ) and matcher_matches_line(matcher, line, window_lines)


def line_window(lines: list[str], line_index: int) -> list[str]:
    start = max(0, line_index - NEARBY_WINDOW_LINES)
    stop = min(len(lines), line_index + NEARBY_WINDOW_LINES + 1)
    return lines[start:stop]
