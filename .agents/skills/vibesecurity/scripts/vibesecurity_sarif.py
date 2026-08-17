from __future__ import annotations

from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, JsonValue, VIBESEC_VERSION

SARIF_SCHEMA: Final = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION: Final = "2.1.0"
SEVERITY_TO_LEVEL: Final = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _text(value: JsonValue, default: str = "") -> str:
    return value if isinstance(value, str) else default


def _rule_id(item: JsonMap) -> str:
    return _text(item.get("matcher_id"), "vibesecurity-unknown-rule")[:120]


def _rule_name(item: JsonMap) -> str:
    return _text(item.get("rule_pack"), "candidate")[:120]


def _result_level(item: JsonMap) -> str:
    severity = _text(item.get("severity"), _text(item.get("severity_hint"), "info")).lower()
    return SEVERITY_TO_LEVEL.get(severity, "note")


def _result_message(item: JsonMap) -> JsonMap:
    text = _text(
        item.get("reason"),
        _text(item.get("snippet_redacted"), _text(item.get("title"), "Review candidate")),
    )
    return {"text": text[:1_000]}


def _result_location(item: JsonMap) -> JsonMap:
    path = _text(item.get("path"), "unknown")
    affected = item.get("affected_files")
    start_line = item.get("line") if isinstance(item.get("line"), int) else 1
    if isinstance(affected, list) and affected and isinstance(affected[0], dict):
        first = affected[0]
        path = _text(first.get("path"), path)
        lines = first.get("lines")
        if isinstance(lines, list) and lines and isinstance(lines[0], int):
            start_line = lines[0]
    region: JsonMap = {"startLine": max(1, start_line)}
    return {"physicalLocation": {"artifactLocation": {"uri": path}, "region": region}}


def _result_fingerprints(item: JsonMap) -> JsonMap:
    fingerprint = item.get("fingerprint")
    partial: JsonMap = {}
    if isinstance(fingerprint, str) and fingerprint:
        partial["vibesecurityLocator/v1"] = fingerprint
    return partial


def _result_properties(item: JsonMap) -> JsonMap:
    properties: JsonMap = {
        "vibesecurityStatus": _text(item.get("status"), "needs-review"),
        "vibesecuritySource": _text(item.get("source"), "matcher"),
    }
    advisory_ids = item.get("advisory_ids")
    if isinstance(advisory_ids, list) and advisory_ids:
        properties["vibesecurityAdvisoryIds"] = [
            value for value in advisory_ids if isinstance(value, str)
        ][:8]
    kev = item.get("kev")
    if kev is True:
        properties["vibesecurityKev"] = True
    return properties


def sarif_from_items(items: list[JsonMap], project: JsonMap | None = None) -> JsonMap:
    """Render findings/candidates as a SARIF 2.1.0 log (structural subset)."""
    rules: list[JsonMap] = []
    rule_ids_seen: set[str] = set()
    results: list[JsonMap] = []
    for item in items:
        rule_id = _rule_id(item)
        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            rules.append({"id": rule_id, "name": _rule_name(item)})
        result: JsonMap = {
            "ruleId": rule_id,
            "level": _result_level(item),
            "message": _result_message(item),
            "locations": [_result_location(item)],
        }
        partial = _result_fingerprints(item)
        if partial:
            result["partialFingerprints"] = partial
        result["properties"] = _result_properties(item)
        results.append(result)
    driver: JsonMap = {
        "name": "VibeSecurity",
        "version": VIBESEC_VERSION,
        "informationUri": "https://github.com/Master0fFate/VibeSecurity",
        "rules": rules,
    }
    run: JsonMap = {"tool": {"driver": driver}, "results": results}
    if isinstance(project, dict) and project:
        run["properties"] = {"vibesecurityProject": _flatten_project(project)}
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def _flatten_project(project: JsonMap) -> JsonMap:
    flat: JsonMap = {}
    for key, value in project.items():
        if isinstance(value, (str, int, bool)) or value is None:
            flat[key] = value
        elif isinstance(value, list):
            flat[key] = [str(item) for item in value[:20]]
    return flat


def validate_sarif_shape(payload: JsonMap) -> list[str]:
    """Minimal structural validation of the emitted SARIF subset."""
    problems: list[str] = []
    if payload.get("version") != "2.1.0":
        problems.append("version must be the string 2.1.0")
    runs = payload.get("runs")
    if not isinstance(runs, list) or not runs:
        problems.append("runs must be a non-empty array")
        return problems
    for run in runs:
        if not isinstance(run, dict):
            problems.append("each run must be an object")
            continue
        tool = run.get("tool")
        if not isinstance(tool, dict) or not isinstance(tool.get("driver"), dict):
            problems.append("run.tool.driver must be an object")
            continue
        driver = tool["driver"]
        for key in ("name", "version"):
            if not isinstance(driver.get(key), str) or not driver.get(key):
                problems.append(f"tool.driver.{key} must be a non-empty string")
        rules = driver.get("rules")
        if rules is not None and not isinstance(rules, list):
            problems.append("tool.driver.rules must be an array when present")
        results = run.get("results")
        if results is not None:
            if not isinstance(results, list):
                problems.append("run.results must be an array when present")
                continue
            for result in results:
                if not isinstance(result, dict):
                    problems.append("each result must be an object")
                    continue
                for key in ("ruleId", "level", "message"):
                    if not isinstance(result.get(key), (str, dict)) or not result.get(key):
                        problems.append(f"result.{key} must be a non-empty string or object")
                if result.get("level") not in {"none", "note", "warning", "error"}:
                    problems.append("result.level must be none, note, warning, or error")
                locations = result.get("locations")
                if locations is not None:
                    if not isinstance(locations, list) or not all(
                        isinstance(location, dict) for location in locations
                    ):
                        problems.append("result.locations must be an array of objects")
    return problems


def sarif_payload(input_path: Path) -> JsonMap:
    from vibesecurity_common import load_json_file
    from vibesecurity_report import report_sections_from_json

    data = load_json_file(input_path)
    sections = report_sections_from_json(data)
    items = [*sections.confirmed, *sections.candidates]
    return sarif_from_items(items, sections.project)
