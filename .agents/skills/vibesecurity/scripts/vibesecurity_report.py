from __future__ import annotations

import re
from dataclasses import dataclass
from html import escape
from pathlib import Path

from vibesecurity_common import (
    MAX_FINDING_ITEMS,
    JsonMap,
    JsonValue,
    display_path,
    load_json_file,
    redact,
    visible_text,
)
from vibesecurity_report_context import render_coverage_notes, render_scope

RESOLVED_STATUSES = {"fixed", "wont-fix", "false-positive"}


def as_map(value: JsonValue) -> JsonMap | None:
    return value if isinstance(value, dict) else None


def text_field(item: JsonMap, key: str, default: str) -> str:
    value = item.get(key)
    return value if isinstance(value, str) else default


def safe_text_field(item: JsonMap, key: str, default: str) -> str:
    raw = text_field(item, key, default)
    redacted = redact(raw)
    return (
        "<redacted-metadata>"
        if redacted != raw
        else markdown_text(visible_text(redacted, 500))
    )


def markdown_text(value: str) -> str:
    escaped = escape(value, quote=False)
    return "".join(
        f"\\{character}" if character in "\\`*_[]#>" else character
        for character in escaped
    )


def safe_block(value: str) -> str:
    lines: list[str] = []
    for line in markdown_text(visible_text(value, 4_000)).splitlines() or [""]:
        stripped = line.lstrip()
        leading = line[: len(line) - len(stripped)]
        numeric_marker = re.match(r"(\d+)([.)])(\s.*)", stripped)
        if numeric_marker:
            stripped = f"{numeric_marker.group(1)}\\{numeric_marker.group(2)}{numeric_marker.group(3)}"
        elif re.match(r"(?:[-+]\s|[-=]{3,}\s*$)", stripped):
            stripped = f"\\{stripped}"
        escaped_line = stripped.replace("|", "\\|")
        lines.append(f"{leading}{escaped_line}")
    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class ReportSections:
    confirmed: list[JsonMap]
    resolved: list[JsonMap]
    candidates: list[JsonMap]
    project: JsonMap
    scope: JsonMap


@dataclass(frozen=True, slots=True)
class RenderGroup:
    heading: str
    items: list[JsonMap]
    start_index: int


def is_confirmed(item: JsonMap) -> bool:
    return item.get("status") == "confirmed"


def is_candidate(item: JsonMap) -> bool:
    status = item.get("status", "needs-review")
    return (
        not isinstance(status, str)
        or status == "needs-review"
        or status not in {"confirmed", *RESOLVED_STATUSES}
    )


def is_resolved(item: JsonMap) -> bool:
    status = item.get("status")
    return isinstance(status, str) and status in RESOLVED_STATUSES


def sections_from_items(
    findings: list[JsonValue],
    candidates: list[JsonValue],
    project: JsonMap,
    scope: JsonMap,
) -> ReportSections:
    mapped_findings = map_items(findings)
    mapped_candidates = map_items(candidates)
    return ReportSections(
        confirmed=[item for item in mapped_findings if is_confirmed(item)],
        resolved=[item for item in mapped_findings if is_resolved(item)],
        candidates=[item for item in mapped_findings if is_candidate(item)]
        + mapped_candidates,
        project=project,
        scope=scope,
    )


def map_items(items: list[JsonValue]) -> list[JsonMap]:
    return [item for value in items if (item := as_map(value)) is not None]


def report_sections_from_json(value: JsonValue) -> ReportSections:
    match value:
        case list() as items:
            return sections_from_items(items, [], {}, {})
        case {"findings": list() as findings, "candidates": list() as candidates}:
            return sections_from_items(
                findings,
                candidates,
                as_map(value.get("project")) or {},
                as_map(value.get("scope")) or {},
            )
        case {"findings": list() as findings}:
            return sections_from_items(
                findings,
                [],
                as_map(value.get("project")) or {},
                as_map(value.get("scope")) or {},
            )
        case {"candidates": list() as items}:
            return ReportSections(
                confirmed=[],
                resolved=[],
                candidates=map_items(items),
                project=as_map(value.get("project")) or {},
                scope=as_map(value.get("scope")) or {},
            )
        case _:
            return ReportSections(
                confirmed=[], resolved=[], candidates=[], project={}, scope={}
            )


def lines_field(item: JsonMap) -> str:
    affected = item.get("affected_files")
    if isinstance(affected, list) and affected:
        rendered: list[str] = []
        for value in affected:
            affected_item = as_map(value)
            if affected_item is None:
                continue
            path = safe_text_field(affected_item, "path", "unknown")
            lines = affected_item.get("lines")
            line_values = (
                [str(line) for line in lines if isinstance(line, int)]
                if isinstance(lines, list)
                else []
            )
            line_text = ", ".join(line_values) if line_values else "unknown"
            rendered.append(f"{path}:{line_text}")
        if rendered:
            return "; ".join(rendered)
    path = safe_text_field(item, "path", "unknown")
    line = item.get("line")
    return f"{path}:{line}" if isinstance(line, int) else path


def standards_field(item: JsonMap) -> str:
    refs = item.get("standard_refs")
    if isinstance(refs, list) and refs:
        values = [
            markdown_text(visible_text(value, 200))
            for value in refs
            if isinstance(value, str)
        ]
        if values:
            return ", ".join(values)
    category = text_field(item, "category", "other")
    return {
        "authz": "OWASP ASVS 5.0 V8",
        "authn": "OWASP ASVS 5.0 V6",
        "injection": "OWASP ASVS 5.0 V1",
        "ssrf": "OWASP ASVS 5.0 V4",
        "xss": "OWASP ASVS 5.0 V1/V3",
        "secrets": "OWASP ASVS 5.0 V13",
        "privacy": "OWASP ASVS 5.0 V14",
        "crypto": "OWASP ASVS 5.0 V11/V12",
        "supply-chain": "NIST SSDF / SLSA",
        "ci-cd": "NIST SSDF / SLSA",
        "ai-agentic": "OWASP LLM Top 10 / Agentic Top 10",
    }.get(category, "Not mapped")


def category_summary(sections: ReportSections) -> str:
    categories = sorted(
        {
            safe_text_field(item, "category", "unknown")
            for item in [*sections.confirmed, *sections.resolved, *sections.candidates]
        }
    )
    return ", ".join(categories) if categories else "None supplied"


def reviewed_files_summary(sections: ReportSections) -> str:
    files = sorted(
        {
            lines_field(item).split(":", 1)[0]
            for item in [*sections.confirmed, *sections.resolved, *sections.candidates]
        }
    )
    return ", ".join(files) if files else "None supplied"


def render_executive_summary(lines: list[str], sections: ReportSections) -> None:
    caveat = "Candidates require manual validation before they are treated as confirmed vulnerabilities."
    if sections.confirmed:
        caveat = "Confirmed findings should still be rechecked after remediation."
    lines.extend(
        [
            "## Executive Summary",
            "",
            f"- Confirmed findings: {len(sections.confirmed)}",
            f"- Resolved or closed findings: {len(sections.resolved)}",
            f"- Needs-review candidates: {len(sections.candidates)}",
            f"- High-risk areas reviewed: {category_summary(sections)}",
            f"- Main caveats: {caveat}",
            "",
        ]
    )


def render_items(lines: list[str], group: RenderGroup) -> int:
    lines.extend([group.heading, ""])
    if not group.items:
        lines.extend(["None supplied.", ""])
        return group.start_index
    index = group.start_index
    for item in group.items:
        title = safe_text_field(
            item, "title", text_field(item, "matcher_id", "Needs review")
        )
        lines.extend(
            [
                f"### {safe_text_field(item, 'id', f'VSEC-{index:04d}')} - {title}",
                "",
                f"- Severity: {safe_text_field(item, 'severity', text_field(item, 'severity_hint', 'unknown'))}",
                f"- Confidence: {safe_text_field(item, 'confidence', text_field(item, 'confidence_hint', 'unknown'))}",
                f"- Category: {safe_text_field(item, 'category', 'unknown')}",
                f"- Status: {safe_text_field(item, 'status', 'needs-review')}",
                f"- Affected files: {lines_field(item)}",
                f"- Standards: {standards_field(item)}",
                "",
                "**Evidence**",
                "",
                safe_block(
                    text_field(
                        item,
                        "evidence",
                        text_field(
                            item,
                            "snippet_redacted",
                            "Review candidate requires manual validation.",
                        ),
                    )
                ),
                "",
                "**Attack scenario**",
                "",
                safe_block(
                    text_field(
                        item,
                        "attack_scenario",
                        "Not confirmed. Validate reachability and attacker control before claiming an attack path.",
                    )
                ),
                "",
                "**Impact**",
                "",
                safe_block(
                    text_field(
                        item,
                        "impact",
                        text_field(
                            item,
                            "reason",
                            "Candidate needs validation before impact is claimed.",
                        ),
                    )
                ),
                "",
                "**Recommendation**",
                "",
                safe_block(
                    text_field(
                        item,
                        "recommendation",
                        text_field(
                            item,
                            "review_prompt",
                            "Validate the code path, security boundary, and exploitability before confirming.",
                        ),
                    )
                ),
                "",
                "**Verification**",
                "",
                safe_block(
                    text_field(
                        item,
                        "verification",
                        "Trace reachability and add a regression test before marking this confirmed or fixed.",
                    )
                ),
                "",
            ]
        )
        index += 1
    return index


def render_report(sections: ReportSections) -> str:
    lines = ["# VibeSecurity Security Report", ""]
    render_scope(
        lines, sections.scope, sections.project, reviewed_files_summary(sections)
    )
    render_executive_summary(lines, sections)
    if not sections.confirmed and not sections.resolved and not sections.candidates:
        lines.extend(["No findings or candidates were supplied.", ""])
        render_coverage_notes(lines, sections.scope, 0, 0)
        return "\n".join(lines)
    next_index = render_items(
        lines, RenderGroup("## Confirmed Findings", sections.confirmed, 1)
    )
    next_index = render_items(
        lines,
        RenderGroup("## Resolved or Closed Findings", sections.resolved, next_index),
    )
    render_items(
        lines,
        RenderGroup(
            "## Candidate Findings Requiring Review", sections.candidates, next_index
        ),
    )
    render_coverage_notes(
        lines, sections.scope, len(sections.confirmed), len(sections.candidates)
    )
    return "\n".join(lines)


def report_payload(input_path: Path, output_path: Path | None) -> JsonMap:
    data = load_json_file(input_path)
    if not isinstance(data, (dict, list)):
        raise ValueError("report input must be a JSON object or array")
    if isinstance(data, dict) and not any(
        isinstance(data.get(key), list) for key in ("findings", "candidates")
    ):
        raise ValueError(
            "report input object must contain a findings or candidates array"
        )
    sections = report_sections_from_json(data)
    item_count = (
        len(sections.confirmed) + len(sections.resolved) + len(sections.candidates)
    )
    if item_count > MAX_FINDING_ITEMS:
        raise ValueError(
            f"report input exceeds {MAX_FINDING_ITEMS} finding and candidate items"
        )
    report = render_report(sections)
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding="utf-8")
    return {
        "project": sections.project,
        "scope": sections.scope
        or {
            "mode": "report",
            "files_considered": [display_path(str(input_path))],
            "files_skipped": [],
        },
        "report_markdown": report,
        "candidates": [],
    }
