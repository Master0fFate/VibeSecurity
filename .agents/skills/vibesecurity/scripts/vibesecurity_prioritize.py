from __future__ import annotations

from typing import Final

from vibesecurity_common import JsonMap, JsonValue
from vibesecurity_standards import cwe_top25_rank, split_ids

SEVERITY_SCORE: Final = {
    "critical": 90,
    "high": 70,
    "medium": 45,
    "low": 20,
    "info": 5,
}
HIGH_VALUE_CATEGORIES: Final = {
    "authz",
    "authn",
    "ci-cd",
    "ai-agentic",
    "secrets",
    "supply-chain",
}
HIGH_VALUE_TERMS: Final = {
    "admin",
    "auth",
    "billing",
    "payment",
    "checkout",
    "tenant",
    "permission",
    "role",
    "deploy",
    "workflow",
    "secret",
    "token",
    "webhook",
    "agent",
    "tool",
    "llm",
}
LOW_SIGNAL_PARTS: Final = {
    "test",
    "tests",
    "fixtures",
    "fixture",
    "docs",
    "doc",
    "examples",
    "example",
    "references",
    "matchers",
    "templates",
    "__snapshots__",
    "node_modules",
    "vendor",
}
LOW_SIGNAL_SUFFIXES: Final = {".md", ".txt"}
HIGH_SIGNAL_MATCHERS: Final = {
    "github-actions-pr-target",
    "ai-output-to-shell",
    "missing-auth-route-candidate",
    "supabase-service-key-in-client",
    "supabase-rls-disabled",
    "firebase-rules-open",
    "llm-sdk-in-browser",
}
EPSS_HIGH: Final = 0.5
EPSS_ELEVATED: Final = 0.1


def cwe_rank_bonus(cwe: str) -> tuple[int, list[str]]:
    best: int | None = None
    for cwe_id in split_ids(cwe):
        rank = cwe_top25_rank(cwe_id)
        if rank is not None and (best is None or rank < best):
            best = rank
    if best is None:
        return 0, []
    bonus = 10 if best <= 10 else 5
    return bonus, [f"cwe-top25-2025-rank-{best}"]


def priority_fields(
    rel: str, severity: str, category: str, matcher_id: str, cwe: str = ""
) -> JsonMap:
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
    if ".github/workflows/" in lower or lower.endswith(
        (".gitlab-ci.yml", "jenkinsfile")
    ):
        score += 12
        reasons.append("workflow-boundary")
    if parts.intersection(LOW_SIGNAL_PARTS):
        score -= 25
        reasons.append("test-doc-fixture-penalty")
    elif any(lower.endswith(suffix) for suffix in LOW_SIGNAL_SUFFIXES):
        score -= 25
        reasons.append("documentation-penalty")
    if matcher_id in HIGH_SIGNAL_MATCHERS:
        score += 8
        reasons.append("high-signal-matcher")
    bonus, rank_reasons = cwe_rank_bonus(cwe)
    score += bonus
    reasons.extend(rank_reasons)
    return {"priority_score": score, "priority_reasons": reasons}


def advisory_priority_fields(
    severity: str, kev: bool, epss_score: float | None, cwe: str = ""
) -> JsonMap:
    score = SEVERITY_SCORE.get(severity, 30) + 10
    reasons: list[JsonValue] = [f"severity:{severity}", "category:supply-chain"]
    if kev:
        score += 25
        reasons.append("cisa-kev-listed")
    if epss_score is not None:
        if epss_score >= EPSS_HIGH:
            score += 15
            reasons.append(f"epss-{epss_score:.2f}-above-{EPSS_HIGH}")
        elif epss_score >= EPSS_ELEVATED:
            score += 10
            reasons.append(f"epss-{epss_score:.2f}-above-{EPSS_ELEVATED}")
        else:
            reasons.append(f"epss-{epss_score:.3f}")
    bonus, rank_reasons = cwe_rank_bonus(cwe)
    score += bonus
    reasons.extend(rank_reasons)
    return {"priority_score": score, "priority_reasons": reasons}


def candidate_sort_key(candidate: JsonMap) -> tuple[int, str, int]:
    raw_score = candidate.get("priority_score")
    score = raw_score if isinstance(raw_score, int) else 0
    raw_path = candidate.get("path")
    path = raw_path if isinstance(raw_path, str) else ""
    raw_line = candidate.get("line")
    line = raw_line if isinstance(raw_line, int) else 0
    return (-score, path, line)
