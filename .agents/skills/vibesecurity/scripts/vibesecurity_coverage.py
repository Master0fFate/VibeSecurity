from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vibesecurity_common import FileSelection, JsonMap, JsonValue, rel_path

CANDIDATE_LANGUAGE_LEVELS: Final = {
    "typescript": "candidate-detector",
    "javascript": "candidate-detector",
    "python": "candidate-detector",
    "go": "candidate-detector",
    "ruby": "candidate-detector",
    "rust": "candidate-detector",
    "java": "candidate-detector",
    "csharp": "candidate-detector",
    "php": "candidate-detector",
}
PROFILE_LANGUAGE_LEVELS: Final = {
    "kotlin": "profile-only",
    "swift": "profile-only",
    "scala": "profile-only",
    "elixir": "profile-only",
    "clojure": "profile-only",
    "sql": "profile-only",
}
CANDIDATE_WORKFLOW_LEVELS: Final = {
    "github-actions": "candidate-detector",
    "gitlab-ci": "candidate-detector",
    "circleci": "candidate-detector",
    "jenkins": "candidate-detector",
    "docker": "candidate-detector",
    "kubernetes": "candidate-detector",
    "terraform": "candidate-detector",
}
OPTIONAL_ADAPTERS: Final = {
    "ast-grep": "sg",
    "semgrep": "semgrep",
    "gitleaks": "gitleaks",
    "npm-audit": "npm",
    "pip-audit": "pip-audit",
    "cargo-audit": "cargo-audit",
}


@dataclass(frozen=True, slots=True)
class CoverageInput:
    root: Path
    project: JsonMap
    selection: FileSelection
    matcher_ids: tuple[str, ...]
    rule_packs: tuple[str, ...]


def string_list(value: JsonValue) -> list[str]:
    if isinstance(value, list):
        return sorted(item for item in value if isinstance(item, str))
    return []


def level_for_language(language: str) -> str:
    if language in CANDIDATE_LANGUAGE_LEVELS:
        return CANDIDATE_LANGUAGE_LEVELS[language]
    return PROFILE_LANGUAGE_LEVELS.get(language, "unsupported")


def level_for_workflow(workflow: str) -> str:
    return CANDIDATE_WORKFLOW_LEVELS.get(workflow, "unsupported")


def adapter_status() -> list[JsonMap]:
    statuses: list[JsonMap] = []
    for adapter, executable in sorted(OPTIONAL_ADAPTERS.items()):
        statuses.append({
            "adapter": adapter,
            "executable": executable,
            "available": shutil.which(executable) is not None,
        })
    return statuses


def path_inventory(root: Path, selection: FileSelection) -> list[str]:
    return [rel_path(root.resolve(), path) for path in selection.files]


def unsupported_items(levels: list[JsonMap]) -> list[str]:
    items: list[str] = []
    for level in levels:
        name = level.get("name")
        support = level.get("support")
        if isinstance(name, str) and support in {"profile-only", "unsupported"}:
            items.append(f"{name}:{support}")
    return items


def level_entries(names: list[str], workflow: bool) -> list[JsonMap]:
    entries: list[JsonMap] = []
    for name in names:
        support = level_for_workflow(name) if workflow else level_for_language(name)
        entries.append({"name": name, "support": support})
    return entries


def coverage_payload(input_data: CoverageInput) -> JsonMap:
    languages = string_list(input_data.project.get("languages"))
    workflows = string_list(input_data.project.get("workflows"))
    language_levels = level_entries(languages, False)
    workflow_levels = level_entries(workflows, True)
    unsupported = [*unsupported_items(language_levels), *unsupported_items(workflow_levels)]
    considered = path_inventory(input_data.root, input_data.selection)
    return {
        "summary": "candidate detectors plus manual agent validation; unsupported/profile-only surfaces must be reviewed manually",
        "language_levels": language_levels,
        "workflow_levels": workflow_levels,
        "unsupported_or_profile_only": sorted(unsupported),
        "rule_packs": sorted(set(input_data.rule_packs)),
        "matchers_loaded": sorted(set(input_data.matcher_ids)),
        "optional_adapters": adapter_status(),
        "files_considered_count": len(considered),
        "files_considered_sample": considered[:25],
    }
