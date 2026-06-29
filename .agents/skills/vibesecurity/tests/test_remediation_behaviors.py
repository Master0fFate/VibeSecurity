from __future__ import annotations

import json
import tempfile
from pathlib import Path

from support import TestFunc, write
from vibesecurity_remediation import fix_plan_payload


def test_fix_plan_requires_confirmed_findings() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "findings.json"
        write(input_path, json.dumps({
            "findings": [
                {"id": "VSEC-0001", "status": "confirmed", "category": "authz", "title": "Missing object authorization", "verification": "Denied user gets 403."},
                {"id": "VSEC-0002", "status": "needs-review", "category": "ssrf", "title": "Candidate fetch"},
            ],
            "candidates": [{"matcher_id": "possible-secret-literal", "status": "needs-review", "category": "secrets"}],
        }))
        payload = fix_plan_payload(input_path, "all", False)
    patch_ready = payload["patch_ready"]
    blocked = payload["blocked"]
    assert isinstance(patch_ready, list)
    assert isinstance(blocked, list)
    assert len(patch_ready) == 1
    assert len(blocked) == 2
    first = patch_ready[0]
    assert isinstance(first, dict)
    assert first["id"] == "VSEC-0001"
    assert first["patch_allowed"] is True
    assert "authorized" in str(first["security_invariant"]).lower()


def test_fix_plan_review_only_blocks_patch_ready_output() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "findings.json"
        write(input_path, json.dumps({"findings": [{"id": "VSEC-0001", "status": "confirmed", "category": "ai-agentic", "title": "Unsafe tool use"}]}))
        payload = fix_plan_payload(input_path, "VSEC-0001", True)
    assert payload["patch_ready"] == []
    review_items = payload["review_items"]
    assert isinstance(review_items, list)
    assert len(review_items) == 1
    first = review_items[0]
    assert isinstance(first, dict)
    assert first["patch_allowed"] is False


TESTS: list[TestFunc] = [
    test_fix_plan_requires_confirmed_findings,
    test_fix_plan_review_only_blocks_patch_ready_output,
]
