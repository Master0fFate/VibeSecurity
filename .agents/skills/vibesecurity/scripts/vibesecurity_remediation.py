from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, JsonValue, redact
from vibesecurity_report import map_items, standards_field, text_field

CATEGORY_INVARIANTS: Final[dict[str, str]] = {
    "authz": "Sensitive actions and objects must be authorized against the current principal and tenant before data is returned or mutated.",
    "authn": "Authentication state must be established, verified, and bound to the active request before protected behavior runs.",
    "injection": "Untrusted input must cross a parser or parameterization boundary before reaching interpreters, queries, file paths, or command-like sinks.",
    "ssrf": "Server-side fetches must be constrained by scheme, destination, redirect, timeout, and response-size policy before any outbound request is made.",
    "xss": "Untrusted content must be encoded or sanitized for its exact browser context before rendering.",
    "secrets": "Secrets must never be committed, logged, rendered, or passed through prompts; exposed credentials must be rotated outside the repo.",
    "supply-chain": "Build inputs must be pinned, reviewable, least-privileged, and provenance-aware before execution in trusted environments.",
    "ci-cd": "Trusted CI credentials and deployment paths must not execute attacker-controlled code or untrusted artifacts.",
    "ai-agentic": "AI outputs and retrieved content must be treated as untrusted data, with scoped tools, structured validation, approval gates, and auditability.",
}

CATEGORY_STEPS: Final[dict[str, tuple[str, ...]]] = {
    "authz": (
        "Add an explicit authorization check at the route, service, or policy boundary before returning or mutating the protected object.",
        "Bind object lookup to the authenticated subject or tenant instead of checking ownership after broad retrieval.",
        "Add a regression test for allowed and denied principals.",
    ),
    "authn": (
        "Require the established auth/session dependency before the protected handler or tool runs.",
        "Fail closed when credentials are missing, expired, malformed, or scoped for another audience.",
        "Add a regression test for anonymous, expired, and valid sessions.",
    ),
    "injection": (
        "Replace string-built interpreter input with parameterized APIs, structured builders, or allowlisted operations.",
        "Parse untrusted input once at the boundary into typed values before it reaches the sink.",
        "Add a regression test with a payload that previously reached the sink.",
    ),
    "ssrf": (
        "Allowlist schemes and destinations, resolve and reject private/link-local/internal addresses, and block unsafe redirects.",
        "Set bounded timeouts, response-size limits, and safe error handling before performing outbound fetches.",
        "Add tests for blocked internal destinations and allowed external destinations.",
    ),
    "xss": (
        "Use framework-native escaping or a vetted sanitizer for the exact HTML, URL, attribute, CSS, or markdown context.",
        "Avoid rendering model/user content as trusted HTML unless the sanitizer policy is explicit and tested.",
        "Add a regression test that renders the previously unsafe payload harmlessly.",
    ),
    "secrets": (
        "Remove the secret from source-controlled files without printing it in logs, reports, or prompts.",
        "Move runtime access to a secret manager or scoped environment variable and rotate the exposed credential outside the repo.",
        "Add a regression check that the secret pattern is absent from committed fixtures and generated output.",
    ),
    "supply-chain": (
        "Pin or replace the dependency/action/source with a reviewed version or immutable digest where practical.",
        "Remove install/build scripts that execute unnecessary network downloads or shell pipes in trusted contexts.",
        "Add a dependency or workflow regression check for the pinned trust boundary.",
    ),
    "ci-cd": (
        "Separate untrusted pull-request validation from trusted deployment or secret-bearing jobs.",
        "Reduce token permissions to least privilege and avoid checking out attacker-controlled code in privileged contexts.",
        "Add a workflow regression check for permissions, event type, and artifact trust boundaries.",
    ),
    "ai-agentic": (
        "Constrain model outputs with structured schemas or allowlists before using them as commands, paths, HTML, SQL, browser actions, or tool inputs.",
        "Scope tools to the active user, tenant, and operation; require human approval for destructive, financial, external-message, credential, or deployment actions.",
        "Add regression tests for direct or indirect prompt injection, unsafe tool input, and approval boundaries.",
    ),
}

DEFAULT_STEPS: Final[tuple[str, ...]] = (
    "State the security invariant in code or tests before changing behavior.",
    "Patch the narrowest reachable boundary that blocks the attack path.",
    "Add a regression test that fails on the vulnerable behavior and passes after the patch.",
)


def findings_from_json(value: JsonValue) -> list[JsonMap]:
    if isinstance(value, list):
        return map_items(value)
    if isinstance(value, dict):
        findings = value.get("findings")
        candidates = value.get("candidates")
        items: list[JsonValue] = []
        if isinstance(findings, list):
            items.extend(findings)
        if isinstance(candidates, list):
            items.extend(candidates)
        return map_items(items)
    return []


def selected_findings(items: list[JsonMap], finding_id: str) -> list[JsonMap]:
    if finding_id == "all":
        return items
    return [item for item in items if text_field(item, "id", "") == finding_id or text_field(item, "matcher_id", "") == finding_id]


def remediation_steps(category: str) -> list[str]:
    return list(CATEGORY_STEPS.get(category, DEFAULT_STEPS))


def remediation_item(item: JsonMap, patch_allowed: bool) -> JsonMap:
    category = text_field(item, "category", "other")
    return {
        "id": redact(text_field(item, "id", text_field(item, "matcher_id", "unknown"))),
        "title": redact(text_field(item, "title", text_field(item, "matcher_id", "Security remediation"))),
        "severity": redact(text_field(item, "severity", text_field(item, "severity_hint", "unknown"))),
        "confidence": redact(text_field(item, "confidence", text_field(item, "confidence_hint", "unknown"))),
        "category": redact(category),
        "status": redact(text_field(item, "status", "needs-review")),
        "patch_allowed": patch_allowed,
        "security_invariant": CATEGORY_INVARIANTS.get(category, "The confirmed attack path must be blocked at the smallest reliable trust boundary."),
        "remediation_steps": remediation_steps(category),
        "verification": redact(text_field(item, "verification", "Add or update a regression test, re-run the relevant security scan, and manually recheck the affected path.")),
        "standards": standards_field(item),
    }


def blocked_item(item: JsonMap, reason: str) -> JsonMap:
    return {
        "id": redact(text_field(item, "id", text_field(item, "matcher_id", "unknown"))),
        "status": redact(text_field(item, "status", "needs-review")),
        "category": redact(text_field(item, "category", "other")),
        "reason": reason,
    }


def fix_plan_payload(input_path: Path, finding_id: str, review_only: bool) -> JsonMap:
    data: JsonValue = json.loads(input_path.read_text(encoding="utf-8"))
    selected = selected_findings(findings_from_json(data), finding_id)
    patch_ready: list[JsonMap] = []
    review_items: list[JsonMap] = []
    blocked: list[JsonMap] = []
    for item in selected:
        if text_field(item, "status", "needs-review") != "confirmed":
            blocked.append(blocked_item(item, "not patch-ready: validate reachability, boundary crossing, impact, and verification before remediation"))
            continue
        if review_only:
            review_items.append(remediation_item(item, False))
            continue
        patch_ready.append(remediation_item(item, True))
    return {
        "project": {},
        "scope": {"mode": "fix-plan", "files_considered": [str(input_path)], "files_skipped": []},
        "selected_finding": finding_id,
        "review_only": review_only,
        "patch_ready": patch_ready,
        "review_items": review_items,
        "blocked": blocked,
        "summary": {
            "selected": len(selected),
            "patch_ready": len(patch_ready),
            "review_items": len(review_items),
            "blocked": len(blocked),
        },
        "candidates": [],
    }
