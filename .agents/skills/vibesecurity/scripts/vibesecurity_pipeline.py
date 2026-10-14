from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from vibesecurity_baseline import Baseline, apply_baseline, load_baseline
from vibesecurity_common import (
    EXIT_CLEAN,
    EXIT_FINDINGS,
    JsonMap,
    JsonValue,
    sha256_bytes,
)
from vibesecurity_config import PolicyConfig
from vibesecurity_deps import deps_payload
from vibesecurity_feed import BUNDLE_SCHEMA, cache_dir as default_cache_dir, provenance_block
from vibesecurity_registry import manifest_drift_candidates, registry_candidates
from vibesecurity_sca import sca_candidates
from vibesecurity_scan import scan_payload

FAIL_ON_LEVELS: Final = ("none", "confirmed", "confirmed-high", "critical")


def default_advisory_source(root: Path, cache_dir: Path | None) -> Path | None:
    directory = cache_dir if cache_dir is not None else default_cache_dir(root)
    return directory if directory.is_dir() else None


def resolve_advisory_records(
    source: Path | None,
) -> tuple[dict[str, JsonValue], list[str], JsonMap | None]:
    """Load advisories from a cache dir or a verified bundle file."""
    if source is None:
        return {}, [], None
    resolved = source.resolve()
    if resolved.is_dir():
        from vibesecurity_feed import load_advisory_db

        records, warnings = load_advisory_db(resolved, 10**6)
        return records, warnings, None
    if resolved.is_file():
        try:
            bundle = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"advisory bundle unreadable: {exc}") from exc
        if not isinstance(bundle, dict) or bundle.get("schema") != BUNDLE_SCHEMA:
            raise ValueError(
                f"{resolved} is neither a cache directory nor a '{BUNDLE_SCHEMA}' bundle"
            )
        sections = bundle.get("sections")
        if not isinstance(sections, dict):
            raise ValueError("advisory bundle has no sections")
        recomputed = sha256_bytes(json.dumps(sections, sort_keys=True).encode("utf-8"))
        if recomputed != bundle.get("sections_sha256"):
            raise ValueError(
                f"advisory bundle integrity failure: {resolved.name} sections sha256 mismatch"
            )
        provenance: JsonMap = {
            "source": f"bundle:{resolved.name}",
            "fetched_at": bundle.get("created_at"),
            "bundle_sha256": sha256_bytes(resolved.read_bytes()),
            "records": len(sections),
            "fresh": True,
            "note": "pinned bundle; freshness is the consumer's responsibility (air-gap mode)",
        }
        return dict(sections), [], provenance
    raise ValueError(f"advisory source not found: {source}")


def enriched_scan_payload(
    root: Path,
    config: PolicyConfig,
    advisory_source: Path | None,
    analyzers: list[str] | None,
    cache_dir: Path | None = None,
    baseline: Baseline | None = None,
) -> JsonMap:
    """Scan = matchers + secret engine + dependency hygiene (+ SCA) (+ bridge), with baseline and gate data."""
    root = root.resolve()
    payload = scan_payload(root)
    candidates: list[JsonMap] = [
        item for item in payload.get("candidates", []) if isinstance(item, dict)
    ]
    warnings: list[str] = [
        str(item) for item in payload.get("scope", {}).get("matcher_warnings", [])
    ]
    source = advisory_source if advisory_source is not None else default_advisory_source(root, cache_dir)
    advisory_block: JsonMap | None = None
    records, load_warnings, bundle_provenance = resolve_advisory_records(source)
    warnings.extend(load_warnings)
    deps = deps_payload(root)
    dependencies = deps.get("dependencies")
    dependency_list = dependencies if isinstance(dependencies, list) else []
    hygiene: JsonMap = {"dependencies": len(dependency_list), "registry_checked": 0}
    if records:
        if bundle_provenance is not None:
            provenance = bundle_provenance
            fresh = True
        else:
            directory = cache_dir if cache_dir is not None else source
            provenance = (
                provenance_block(directory, config.max_cache_age_hours)
                if directory is not None
                else {}
            )
            fresh = bool(provenance.get("fresh"))
        sca_items, sca_warnings = sca_candidates(dependency_list, records, fresh)
        advisory_block = provenance
        candidates.extend(sca_items)
        warnings.extend(sca_warnings)
        for dep_warning in deps.get("warnings", [])[:20]:
            if isinstance(dep_warning, str):
                warnings.append(dep_warning)
        registry_items = registry_candidates(dependency_list, records)
        hygiene["registry_checked"] = sum(1 for key in records if key.startswith("registry/"))
        hygiene["not_in_registry"] = sum(1 for item in registry_items if item.get("matcher_id") == "dependency-not-in-public-registry")
        hygiene["recently_published"] = sum(1 for item in registry_items if item.get("matcher_id") == "dependency-recently-published")
        candidates.extend(registry_items)
    drift_items = manifest_drift_candidates(root)
    hygiene["declared_not_locked"] = len(drift_items)
    candidates.extend(drift_items)
    if analyzers:
        from vibesecurity_bridge import bridge_payload

        bridge = bridge_payload(root, analyzers, config.allowed_analyzers)
        bridge_items = bridge.get("candidates")
        if isinstance(bridge_items, list):
            candidates.extend(item for item in bridge_items if isinstance(item, dict))
        warnings.extend(str(item) for item in bridge.get("warnings", []))
        payload["tool_results"] = bridge.get("tool_results", [])
    active_baseline = baseline if baseline is not None else load_baseline(root)
    visible, suppressed, re_fired = apply_baseline(candidates, active_baseline)
    payload["candidates"] = visible
    payload["suppressed"] = suppressed
    payload["suppression_expired"] = re_fired
    payload["baseline"] = {
        "loaded": active_baseline.loaded,
        "active": len(active_baseline.active),
        "expired": len(active_baseline.expired),
        "max_age_days": config.baseline_max_age_days,
        "warnings": list(active_baseline.warnings[:20]),
    }
    payload["dependency_hygiene"] = hygiene
    if advisory_block is not None:
        payload["advisory_db"] = advisory_block
    scope_warnings = payload.get("scope", {})
    if isinstance(scope_warnings, dict):
        scope_warnings["scan_warnings"] = warnings[:100]
    payload["warnings"] = warnings[:100]
    payload["gate"] = gate_summary(visible, config.fail_on)
    payload["candidates_total"] = payload.get("candidates_total", 0) + len(suppressed)
    return payload


def gate_summary(items: list[JsonMap], fail_on: str) -> JsonMap:
    """Machine-readable verdict data for CI gating."""
    confirmed = [item for item in items if item.get("status") == "confirmed"]
    counts = {"confirmed": len(confirmed), "total": len(items)}
    for band in ("critical", "high", "medium", "low"):
        counts[band] = sum(
            1
            for item in confirmed
            if str(item.get("severity", item.get("severity_hint", "info"))) == band
        )
    if fail_on == "none":
        tripped = False
    elif fail_on == "confirmed":
        tripped = len(confirmed) > 0
    elif fail_on == "confirmed-high":
        tripped = counts["critical"] + counts["high"] > 0
    elif fail_on == "critical":
        tripped = counts["critical"] > 0
    else:
        tripped = False
    return {
        "fail_on": fail_on,
        "counts": counts,
        "tripped": tripped,
        "exit_code": EXIT_FINDINGS if tripped else EXIT_CLEAN,
    }
