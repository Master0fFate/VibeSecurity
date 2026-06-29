from __future__ import annotations

from typing import Final

from vibesecurity_common import JsonMap, JsonValue

SEVERITY_SCORE: Final = {
    "critical": 90,
    "high": 70,
    "medium": 45,
    "low": 20,
    "info": 5,
}
HIGH_VALUE_CATEGORIES: Final = {"authz", "authn", "ci-cd", "ai-agentic", "secrets", "supply-chain"}
HIGH_VALUE_TERMS: Final = {
    "admin", "auth", "billing", "payment", "checkout", "tenant", "permission", "role",
    "deploy", "workflow", "secret", "token", "webhook", "agent", "tool", "llm",
}
LOW_SIGNAL_PARTS: Final = {
    "test", "tests", "fixtures", "fixture", "docs", "doc", "examples", "example",
    "__snapshots__", "node_modules", "vendor",
}


def priority_fields(rel: str, severity: str, category: str, matcher_id: str) -> JsonMap:
    score = SEVERITY_SCORE.get(severity, 30)
    reasons: list[JsonValue] = [f"severity:{severity}"]
    parts = {part.lower() for part in rel.replace("\\", "/").split("/")}
    lower = rel.lower()
    if category in HIGH_VALUE_CATEGORIES:
        score += 10
        reasons.append(f"category:{category}")
    if any(term in lower for term in HIGH_VALUE_TERMS):
        score += 12
        reasons.append("sensitive-path-term")
    if ".github/workflows/" in lower or lower.endswith((".gitlab-ci.yml", "jenkinsfile")):
        score += 12
        reasons.append("workflow-boundary")
    if parts.intersection(LOW_SIGNAL_PARTS):
        score -= 25
        reasons.append("test-doc-fixture-penalty")
    if matcher_id in {"github-actions-pr-target", "ai-output-to-shell", "missing-auth-route-candidate"}:
        score += 8
        reasons.append("high-signal-matcher")
    return {"priority_score": score, "priority_reasons": reasons}


def candidate_sort_key(candidate: JsonMap) -> tuple[int, str, int]:
    raw_score = candidate.get("priority_score")
    score = raw_score if isinstance(raw_score, int) else 0
    raw_path = candidate.get("path")
    path = raw_path if isinstance(raw_path, str) else ""
    raw_line = candidate.get("line")
    line = raw_line if isinstance(raw_line, int) else 0
    return (-score, path, line)
