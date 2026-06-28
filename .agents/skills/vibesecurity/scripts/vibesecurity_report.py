from __future__ import annotations

import json
from pathlib import Path

from vibesecurity_scan import JsonMap, JsonValue, redact


def as_map(value: JsonValue) -> JsonMap | None:
    return value if isinstance(value, dict) else None


def text_field(item: JsonMap, key: str, default: str) -> str:
    value = item.get(key)
    return value if isinstance(value, str) else default


def findings_from_json(value: JsonValue) -> list[JsonValue]:
    match value:
        case list() as items:
            return items
        case {"findings": list() as items}:
            return items
        case {"candidates": list() as items}:
            return items
        case _:
            return []


def render_report(items: list[JsonValue]) -> str:
    lines = ["# VibeSecurity Security Report", "", "## Findings", ""]
    if not items:
        lines.extend(["No findings or candidates were supplied.", ""])
        return "\n".join(lines)
    for index, value in enumerate(items, start=1):
        item = as_map(value)
        if item is None:
            continue
        title = text_field(item, "title", text_field(item, "matcher_id", "Needs review"))
        lines.extend([
            f"### {text_field(item, 'id', f'VSEC-{index:04d}')} - {title}",
            "",
            f"- Severity: {text_field(item, 'severity', text_field(item, 'severity_hint', 'unknown'))}",
            f"- Confidence: {text_field(item, 'confidence', text_field(item, 'confidence_hint', 'unknown'))}",
            f"- Category: {text_field(item, 'category', 'unknown')}",
            f"- Status: {text_field(item, 'status', 'needs-review')}",
            "",
            "**Evidence**",
            "",
            redact(text_field(item, "evidence", text_field(item, "snippet_redacted", "Review candidate requires manual validation."))),
            "",
        ])
    return "\n".join(lines)


def report_payload(input_path: Path, output_path: Path | None) -> JsonMap:
    data: JsonValue = json.loads(input_path.read_text(encoding="utf-8"))
    report = render_report(findings_from_json(data))
    if output_path is not None:
        output_path.write_text(report, encoding="utf-8")
    return {
        "project": {},
        "scope": {"mode": "report", "files_considered": [str(input_path)], "files_skipped": []},
        "report_markdown": report,
        "candidates": [],
    }
