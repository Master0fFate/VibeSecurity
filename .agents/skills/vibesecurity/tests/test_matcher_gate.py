from __future__ import annotations

import tempfile
from pathlib import Path

from support import TestFunc, write
from vibesecurity_matchers import (
    Matcher,
    glob_matches,
    invalid_matcher_reason,
    load_matcher_catalog,
    validate_matcher_examples,
)


def _draft(**overrides):
    base = {
        "id": "test-matcher",
        "category": "secrets",
        "severity_hint": "high",
        "confidence_hint": "medium",
        "reason": "test",
        "review_prompt": "test",
    }
    base.update(overrides)
    return base


def _lists(**overrides):
    base = {"globs": ["**/*.py"], "patterns": ["pattern-a"], "nearby_terms": [], "positive_examples": [], "negative_examples": []}
    base.update(overrides)
    return base


def test_project_specific_patterns_are_rejected() -> None:
    assert invalid_matcher_reason(_draft(), _lists(patterns=["/home/alice/secret-path"])) != ""
    assert invalid_matcher_reason(_draft(), _lists(patterns=["C:\\Users\\bob\\token"])) != ""
    assert invalid_matcher_reason(_draft(), _lists(globs=["~/projects/one/**"])) != ""
    assert invalid_matcher_reason(_draft(), _lists(globs=["/etc/passwd"])) != ""
    assert invalid_matcher_reason(_draft(), _lists()) == ""


def test_bundled_matcher_examples_all_validate() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        catalog = load_matcher_catalog(root)
        problems: list[str] = []
        for matcher in catalog.matchers:
            if not matcher.positive_examples and not matcher.negative_examples:
                continue
            _, _, matcher_problems = validate_matcher_examples(matcher)
            for problem in matcher_problems:
                problems.append(f"{matcher.matcher_id}: {problem}")
    assert problems == [], "bundled matcher example failures: " + "; ".join(problems)


def test_leaks_and_ai_agentic_packs_are_loaded() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        catalog = load_matcher_catalog(Path(tmp))
    rule_packs = {matcher.rule_pack for matcher in catalog.matchers}
    matcher_ids = {matcher.matcher_id for matcher in catalog.matchers}
    assert "leaks" in rule_packs
    assert "ai-agentic" in rule_packs
    assert "workflow-echo-dumps-secret" in matcher_ids
    assert "secret-into-model-payload" in matcher_ids


def test_validate_matcher_examples_reports_failures() -> None:
    broken = Matcher(
        matcher_id="broken-example",
        category="secrets",
        severity_hint="high",
        confidence_hint="medium",
        globs=("**/*",),
        patterns=("nonexistent-pattern-xyz",),
        nearby_terms=(),
        reason="x",
        review_prompt="x",
        rule_pack="test",
        positive_examples=("this line cannot match",),
        negative_examples=(),
    )
    _, _, problems = validate_matcher_examples(broken)
    assert problems and "positive example did not fire" in problems[0]


def test_glob_matches_stays_case_insensitive() -> None:
    assert glob_matches("src/App/route.TS", "**/route.ts")
    assert glob_matches("deep/nested/lib/route.py", "**/*.py")


TESTS = [
    test_project_specific_patterns_are_rejected,
    test_bundled_matcher_examples_all_validate,
    test_leaks_and_ai_agentic_packs_are_loaded,
    test_validate_matcher_examples_reports_failures,
    test_glob_matches_stays_case_insensitive,
]
