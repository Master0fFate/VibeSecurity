from __future__ import annotations

from datetime import date

from vibesecurity_common import JsonMap, JsonValue, redact


def as_list(value: JsonValue) -> list[JsonValue]:
    return value if isinstance(value, list) else []


def text_values(value: JsonValue) -> list[str]:
    return [item for item in as_list(value) if isinstance(item, str)]


def map_value(value: JsonValue) -> JsonMap:
    return value if isinstance(value, dict) else {}


def files_reviewed_summary(scope: JsonMap, fallback: str) -> str:
    count = scope.get("files_considered_count")
    candidates = text_values(scope.get("candidate_files"))
    files = text_values(scope.get("files_considered"))
    if isinstance(count, int) and candidates:
        return f"{count} files considered; candidates in {', '.join(candidates[:10])}"
    if isinstance(count, int):
        return f"{count} files considered"
    return ", ".join(files[:10]) if files else fallback


def skipped_summary(scope: JsonMap) -> str:
    skipped = as_list(scope.get("files_skipped"))
    if not skipped:
        return "None supplied"
    samples: list[str] = []
    for item in skipped[:5]:
        if isinstance(item, dict):
            path = item.get("path")
            reason = item.get("reason")
            if isinstance(path, str) and isinstance(reason, str):
                samples.append(f"{path} ({reason})")
    suffix = f"; sample: {', '.join(samples)}" if samples else ""
    return f"{len(skipped)} skipped{suffix}"


def project_summary(project: JsonMap) -> str:
    parts: list[str] = []
    for label, key in (
        ("languages", "languages"),
        ("frameworks", "frameworks"),
        ("workflows", "workflows"),
        ("package managers", "package_managers"),
    ):
        values = text_values(project.get(key))
        if values:
            parts.append(f"{label}: {', '.join(values)}")
    return "; ".join(parts) if parts else "None supplied"


def coverage_map(scope: JsonMap) -> JsonMap:
    return map_value(scope.get("coverage"))


def unsupported_summary(scope: JsonMap) -> str:
    unsupported = text_values(coverage_map(scope).get("unsupported_or_profile_only"))
    return ", ".join(unsupported) if unsupported else "None supplied"


def rule_pack_summary(scope: JsonMap) -> str:
    direct = text_values(scope.get("rule_packs"))
    coverage = text_values(coverage_map(scope).get("rule_packs"))
    values = direct or coverage
    return ", ".join(values) if values else "None supplied"


def adapter_summary(scope: JsonMap) -> str:
    adapters = as_list(coverage_map(scope).get("optional_adapters"))
    if not adapters:
        return "None supplied"
    rendered: list[str] = []
    for item in adapters:
        if isinstance(item, dict):
            name = item.get("adapter")
            available = item.get("available")
            if isinstance(name, str) and isinstance(available, bool):
                rendered.append(f"{name}:{'available' if available else 'missing'}")
    return ", ".join(rendered) if rendered else "None supplied"


def render_scope(lines: list[str], scope: JsonMap, project: JsonMap, fallback_files: str) -> None:
    mode = scope.get("mode")
    mode_text = mode if isinstance(mode, str) else "report"
    lines.extend([
        "## Scope",
        "",
        f"- Mode: {redact(mode_text)}",
        f"- Date: {date.today().isoformat()}",
        f"- Project profile: {redact(project_summary(project))}",
        f"- Files reviewed: {redact(files_reviewed_summary(scope, fallback_files))}",
        f"- Files skipped: {redact(skipped_summary(scope))}",
        f"- Rule packs loaded: {redact(rule_pack_summary(scope))}",
        f"- Unsupported/profile-only surfaces: {redact(unsupported_summary(scope))}",
        "",
    ])


def render_coverage_notes(lines: list[str], scope: JsonMap, confirmed_count: int, candidate_count: int) -> None:
    lines.extend([
        "## Coverage Notes",
        "",
        f"- Report input included {confirmed_count} confirmed findings and {candidate_count} candidates.",
        "- Candidate detectors are not vulnerability proof; the agent must validate reachability, boundary crossing, impact, and verification.",
        f"- Optional local analyzers: {redact(adapter_summary(scope))}",
        f"- Unsupported/profile-only surfaces require manual review: {redact(unsupported_summary(scope))}",
        "",
        "## Follow-Up Recommendations",
        "",
        "- Validate each candidate with code-path reachability, boundary crossing, impact, and a regression test before confirming.",
        "- Re-run `vibesecurity.py scan` after fixes and render a fresh report from the updated JSON.",
        "",
    ])
