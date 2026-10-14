from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, JsonValue, fingerprint, read_text, rel_path, visible_text
from vibesecurity_deps import LOCKFILE_NAMES, OSV_ECOSYSTEMS, PARSERS, walk_skip_parts
from vibesecurity_feed import parse_utc
from vibesecurity_inventory import dependency_names_from_package
from vibesecurity_prioritize import priority_fields
from vibesecurity_standards import standards_block

NEW_PACKAGE_DAYS: Final = 90
MAX_DRIFT_PER_MANIFEST: Final = 50
MAX_REGISTRY_CANDIDATES: Final = 500
NPM_LOCKFILES: Final = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")
HALLUCINATION_SOURCE: Final = {
    "type": "documented-pattern",
    "id": "spracklen-2025-package-hallucinations",
    "url": "https://arxiv.org/abs/2406.10279",
}
MISSING_CWE: Final = "CWE-829"
NEW_PACKAGE_CWE: Final = "CWE-1357"


def _registry_record(records: dict[str, JsonValue], ecosystem: str, name: str) -> JsonMap | None:
    record = records.get(f"registry/{ecosystem}/{name.replace('/', '__')}.json")
    if isinstance(record, dict) and record.get("schema") == "vibesecurity-registry-record/1":
        return record
    return None


def _base(dep: JsonMap, matcher_id: str, severity: str, confidence: str, cwe: str, reason: str, prompt: str, snippet: str) -> JsonMap:
    name = str(dep.get("name", "unknown"))
    path = str(dep.get("source_file", "unknown"))
    line = dep.get("line", 0)
    candidate: JsonMap = {
        "matcher_id": matcher_id,
        "rule_pack": "registry",
        "path": visible_text(path, 500),
        "line": line if isinstance(line, int) else 0,
        "snippet_redacted": visible_text(snippet, 300),
        "reason": visible_text(reason, 500),
        "review_prompt": visible_text(prompt, 500),
        "category": "supply-chain",
        "severity_hint": severity,
        "confidence_hint": confidence,
        "status": "needs-review",
        "source": "registry",
        "cwe": cwe,
        "standards": standards_block(cwe, "", "", "supply-chain"),
        "sources": [HALLUCINATION_SOURCE],
        "fingerprint": fingerprint("registry", matcher_id, str(dep.get("ecosystem", "")), name),
    }
    candidate.update(priority_fields(path, severity, "supply-chain", matcher_id, cwe))
    return candidate


def registry_candidates(
    dependencies: list[JsonMap],
    records: dict[str, JsonValue],
    today: datetime | None = None,
) -> list[JsonMap]:
    """Flag dependencies missing from the public registry or published very recently."""
    now = today or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=NEW_PACKAGE_DAYS)
    candidates: list[JsonMap] = []
    seen: set[tuple[str, str]] = set()
    for dep in dependencies:
        ecosystem = dep.get("ecosystem")
        name = dep.get("name")
        if not isinstance(ecosystem, str) or not isinstance(name, str):
            continue
        mapped = OSV_ECOSYSTEMS.get(ecosystem, "")
        if (mapped, name) in seen:
            continue
        record = _registry_record(records, mapped, name)
        if record is None:
            continue
        seen.add((mapped, name))
        if record.get("exists") is False:
            candidates.append(
                _base(
                    dep,
                    "dependency-not-in-public-registry",
                    "high",
                    "high",
                    MISSING_CWE,
                    f"{name} is not published on the public {mapped} registry; a hallucinated or mistyped name is a slopsquatting target",
                    "Confirm whether the package comes from a private registry or a typo; if neither, remove it before anyone registers the name.",
                    f"{mapped} registry returned 404 for {name}",
                )
            )
        else:
            created = parse_utc(str(record.get("created", "")))
            if created is not None and created > cutoff:
                candidates.append(
                    _base(
                        dep,
                        "dependency-recently-published",
                        "low",
                        "low",
                        NEW_PACKAGE_CWE,
                        f"{name} was first published on {mapped} on {created.date().isoformat()}, within the last {NEW_PACKAGE_DAYS} days",
                        "Check maintainer identity, download history, and source repository before trusting a package this new.",
                        f"first published {created.date().isoformat()}; latest {record.get('latest_version', '?')}",
                    )
                )
        if len(candidates) >= MAX_REGISTRY_CANDIDATES:
            break
    return candidates


def manifest_drift_candidates(root: Path) -> list[JsonMap]:
    """npm dependencies declared in package.json but absent from the sibling lockfile."""
    root = root.resolve()
    skip_parts = walk_skip_parts()
    candidates: list[JsonMap] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name.lower() not in skip_parts]
        if "package.json" not in filenames:
            continue
        lock_name = next((name for name in NPM_LOCKFILES if name in filenames), None)
        if lock_name is None:
            continue
        manifest = Path(dirpath) / "package.json"
        declared = dependency_names_from_package(manifest)
        if not declared:
            continue
        lock_path = Path(dirpath) / lock_name
        locked, _ = PARSERS[LOCKFILE_NAMES[lock_name]](read_text(lock_path), rel_path(root, lock_path))
        locked_names = {dep.name for dep in locked}
        if not locked_names:
            continue
        manifest_rel = rel_path(root, manifest)
        for name in sorted(declared - locked_names)[:MAX_DRIFT_PER_MANIFEST]:
            dep: JsonMap = {"ecosystem": "npm", "name": name, "source_file": manifest_rel, "line": _manifest_line(manifest, name)}
            candidates.append(
                _base(
                    dep,
                    "dependency-declared-not-locked",
                    "medium",
                    "medium",
                    MISSING_CWE,
                    f"{name} is declared in package.json but absent from {lock_name}; it was never installed or resolved",
                    "Run the package manager install; if the name does not resolve on the registry, treat it as a hallucinated dependency.",
                    f"declared in {manifest_rel}, missing from {lock_name}",
                )
            )
    return candidates


def _manifest_line(manifest: Path, name: str) -> int:
    needle = json.dumps(name)
    for number, line in enumerate(read_text(manifest).splitlines(), start=1):
        if needle in line:
            return number
    return 0
