from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vibesecurity_common import (
    JsonMap,
    JsonValue,
    fingerprint,
    visible_text,
)
from vibesecurity_cvss import cvss_summary
from vibesecurity_deps import OSV_ECOSYSTEMS, deps_payload
from vibesecurity_feed import EPSS_RECORD_KEY, load_advisory_db, provenance_block
from vibesecurity_prioritize import advisory_priority_fields
from vibesecurity_standards import standards_block

OSV_URL_PREFIX: Final = "https://osv.dev/vulnerability/"
NVD_URL_PREFIX: Final = "https://nvd.nist.gov/vuln/detail/"
GHSA_URL_PREFIX: Final = "https://github.com/advisories/"
MAX_SCA_CANDIDATES: Final = 500
RELEASE_NUMBER: Final = re.compile(r"^(\d+(?:\.\d+)*)")
GO_PSEUDO: Final = re.compile(r"^0\.0\.0-(\d{14})-[0-9a-f]+$")
SEVERITY_BANDS: Final = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}
DEFAULT_SEVERITY: Final = "medium"


@dataclass(frozen=True, slots=True)
class VersionKey:
    release: tuple[int, ...]
    is_release: bool
    pre: tuple[tuple[int, str | int], ...]

    def __lt__(self, other: VersionKey) -> bool:
        left = self.release + (0,) * max(0, len(other.release) - len(self.release))
        right = other.release + (0,) * max(0, len(self.release) - len(other.release))
        if left != right:
            return left < right
        if self.is_release != other.is_release:
            return not self.is_release
        return self.pre < other.pre


def version_key(version: str) -> VersionKey | None:
    """Best-effort orderable key for semver, PEP 440 subset, and Go pseudo versions."""
    cleaned = version.strip()
    if cleaned.startswith(("v", "V")) and len(cleaned) > 1 and cleaned[1].isdigit():
        cleaned = cleaned[1:]
    pseudo = GO_PSEUDO.match(cleaned)
    if pseudo:
        return VersionKey((0, 0), False, ((0, int(pseudo.group(1))),))
    match = RELEASE_NUMBER.match(cleaned)
    if not match:
        return None
    release = tuple(int(part) for part in match.group(1).split("."))
    remainder = cleaned[match.end() :]
    if not remainder or remainder.startswith("+"):
        return VersionKey(release, True, ())
    suffix = remainder.lstrip("-_.")
    parts: list[tuple[int, str | int]] = []
    for token in re.split(r"[.-]", suffix):
        if not token:
            continue
        if token.isdigit():
            parts.append((0, int(token)))
        else:
            parts.append((1, token))
    return VersionKey(release, False, tuple(parts))


def version_lt(left: str, right: str) -> bool | None:
    left_key = version_key(left)
    right_key = version_key(right)
    if left_key is None or right_key is None:
        return None
    return left_key < right_key


def _events_text(events: list[JsonValue]) -> str:
    rendered: list[str] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            value = event.get(kind)
            if isinstance(value, str):
                rendered.append(f"{kind} {value}")
    return ", ".join(rendered)


def _fixed_versions_from_ranges(affected: JsonMap) -> list[str]:
    fixed: list[str] = []
    ranges = affected.get("ranges")
    if isinstance(ranges, list):
        for item in ranges:
            if not isinstance(item, dict):
                continue
            events = item.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.append(event["fixed"])
    return fixed


@dataclass(frozen=True, slots=True)
class AdvisorySeverity:
    band: str
    basis: str
    cvss: JsonMap | None


def advisory_severity(vuln: JsonMap) -> AdvisorySeverity:
    cvss = cvss_summary(vuln.get("severity"))
    database_specific = vuln.get("database_specific")
    if isinstance(database_specific, dict):
        severity = database_specific.get("severity")
        if isinstance(severity, str):
            band = SEVERITY_BANDS.get(severity.upper())
            if band:
                return AdvisorySeverity(band, "advisory database_specific.severity (GHSA review band)", cvss)
    if cvss and isinstance(cvss.get("severity"), str):
        return AdvisorySeverity(str(cvss["severity"]), str(cvss.get("basis", "cvss")), cvss)
    return AdvisorySeverity(
        DEFAULT_SEVERITY,
        f"advisory carries no severity band or CVSS v3 vector; defaulted to {DEFAULT_SEVERITY} for triage",
        cvss,
    )


def advisory_cwe(vuln: JsonMap) -> str:
    database_specific = vuln.get("database_specific")
    if isinstance(database_specific, dict):
        cwe_ids = database_specific.get("cwe_ids")
        if isinstance(cwe_ids, list):
            ids = [item for item in cwe_ids if isinstance(item, str) and item.startswith("CWE-")]
            if ids:
                return ", ".join(ids[:4])
    return ""


@dataclass(frozen=True, slots=True)
class MatchOutcome:
    affected: bool
    unknown_version: bool
    affected_range: str
    fixed_versions: tuple[str, ...]
    reason: str


def match_version(affected: JsonMap, version: str) -> MatchOutcome:
    listed = affected.get("versions")
    if isinstance(listed, list) and version in [item for item in listed if isinstance(item, str)]:
        return MatchOutcome(True, False, "explicitly listed affected version", (), "listed")
    ranges = affected.get("ranges")
    if not isinstance(ranges, list) or not ranges:
        return MatchOutcome(False, False, "", (), "no comparable range data")
    for item in ranges:
        if not isinstance(item, dict):
            continue
        range_type = item.get("type")
        if range_type == "GIT":
            continue
        events = item.get("events")
        if not isinstance(events, list) or not events:
            continue
        introduced: str | None = None
        fixed: str | None = None
        last_affected: str | None = None
        for event in events:
            if not isinstance(event, dict):
                continue
            if isinstance(event.get("introduced"), str):
                introduced = event["introduced"]
            if isinstance(event.get("fixed"), str):
                fixed = event["fixed"]
            if isinstance(event.get("last_affected"), str):
                last_affected = event["last_affected"]
        above_introduced = True
        if introduced and introduced != "0":
            comparison = version_lt(introduced, version)
            if comparison is None:
                return MatchOutcome(False, True, _events_text(events), (), "unparseable introduced version")
            above_introduced = comparison or introduced == version
        below_fixed = True
        if fixed:
            comparison = version_lt(version, fixed)
            if comparison is None:
                return MatchOutcome(False, True, _events_text(events), (), "unparseable fixed version")
            below_fixed = comparison
        at_or_below_last = True
        if last_affected:
            comparison = version_lt(version, last_affected)
            if comparison is None:
                return MatchOutcome(False, True, _events_text(events), (), "unparseable last_affected version")
            at_or_below_last = comparison or version == last_affected
        if above_introduced and below_fixed and at_or_below_last:
            fixed_all = _fixed_versions_from_ranges(affected)
            return MatchOutcome(
                True,
                False,
                _events_text(events),
                tuple(fixed_all),
                f"version within advisory range ({_events_text(events)})",
            )
    return MatchOutcome(False, False, "", (), "not in any advisory range")


def kev_cve_ids(records: dict[str, JsonValue]) -> set[str]:
    ids: set[str] = set()
    for record in records.values():
        if not isinstance(record, dict) or record.get("schema") != "vibesecurity-kev-record/1":
            continue
        catalog = record.get("catalog")
        if not isinstance(catalog, dict):
            continue
        entries = catalog.get("vulns")
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and isinstance(entry.get("cveID"), str):
                    ids.add(entry["cveID"])
    return ids


def epss_scores(records: dict[str, JsonValue]) -> dict[str, JsonMap]:
    record = records.get(EPSS_RECORD_KEY)
    if not isinstance(record, dict) or record.get("schema") != "vibesecurity-epss-record/1":
        return {}
    scores = record.get("scores")
    if not isinstance(scores, dict):
        return {}
    return {key: value for key, value in scores.items() if isinstance(value, dict)}


def _source_citations(vuln: JsonMap) -> list[JsonMap]:
    sources: list[JsonMap] = []
    vuln_id = vuln.get("id")
    if isinstance(vuln_id, str):
        sources.append({"type": "OSV", "id": vuln_id, "url": OSV_URL_PREFIX + vuln_id})
    aliases = vuln.get("aliases")
    if isinstance(aliases, list):
        for alias in aliases:
            if not isinstance(alias, str):
                continue
            if alias.startswith("CVE-") and not any(item["id"] == alias for item in sources):
                sources.append({"type": "CVE", "id": alias, "url": NVD_URL_PREFIX + alias})
            elif alias.startswith("GHSA-") and not any(item["id"] == alias for item in sources):
                sources.append({"type": "GHSA", "id": alias, "url": GHSA_URL_PREFIX + alias.lower()})
    return sources[:8]


def _recommended_version(installed: str, fixed_versions: tuple[str, ...]) -> str | None:
    if not fixed_versions:
        return None
    candidates: list[tuple[VersionKey, str]] = []
    installed_key = version_key(installed)
    for fixed in fixed_versions:
        key = version_key(fixed)
        if key is None:
            continue
        if installed_key is not None and not (installed_key < key):
            continue
        candidates.append((key, fixed))
    if candidates:
        candidates.sort()
        return candidates[0][1]
    return None


def _advisory_order(vuln: JsonValue) -> tuple[int, str]:
    """GHSA records (reviewed severity band) before ecosystem mirrors of the same CVE."""
    if not isinstance(vuln, dict):
        return (2, "")
    vuln_id = str(vuln.get("id", ""))
    database_specific = vuln.get("database_specific")
    has_band = isinstance(database_specific, dict) and isinstance(database_specific.get("severity"), str)
    return (0 if has_band else 1, vuln_id)


def _cve_aliases(vuln: JsonMap) -> list[str]:
    ids: list[str] = []
    vuln_id = vuln.get("id")
    if isinstance(vuln_id, str) and vuln_id.startswith("CVE-"):
        ids.append(vuln_id)
    aliases = vuln.get("aliases")
    if isinstance(aliases, list):
        ids.extend(alias for alias in aliases if isinstance(alias, str) and alias.startswith("CVE-"))
    return ids


def sca_candidates(
    dependencies: list[JsonMap],
    records: dict[str, JsonValue],
    fresh: bool,
) -> tuple[list[JsonMap], list[str]]:
    """Match installed versions against cached advisory records. Factual only."""
    warnings: list[str] = []
    candidates: list[JsonMap] = []
    kev = kev_cve_ids(records)
    epss = epss_scores(records)
    for dep in dependencies:
        ecosystem = dep.get("ecosystem")
        name = dep.get("name")
        version = dep.get("version")
        source_file = dep.get("source_file", "unknown")
        line = dep.get("line", 0)
        if not (isinstance(ecosystem, str) and isinstance(name, str) and isinstance(version, str)):
            continue
        mapped = OSV_ECOSYSTEMS.get(ecosystem)
        if not mapped:
            continue
        record_key = f"osv/{mapped.replace('/', '_')}/{name.replace('/', '__')}.json"
        record = records.get(record_key)
        if not isinstance(record, dict):
            continue
        vulns = record.get("vulns")
        if not isinstance(vulns, list):
            continue
        seen_cves: set[str] = set()
        for vuln in sorted(vulns, key=_advisory_order):
            if not isinstance(vuln, dict):
                continue
            cve_ids = _cve_aliases(vuln)
            if cve_ids and seen_cves.intersection(cve_ids):
                continue
            affected_entries = vuln.get("affected")
            if not isinstance(affected_entries, list):
                continue
            for affected in affected_entries:
                if not isinstance(affected, dict):
                    continue
                package = affected.get("package")
                if not isinstance(package, dict):
                    continue
                if package.get("name") != name or package.get("ecosystem") != mapped:
                    continue
                outcome = match_version(affected, version)
                if outcome.unknown_version:
                    warnings.append(
                        f"{mapped}/{name}@{version}: version format not comparable for advisory {vuln.get('id', '?')}; marked needs-review"
                    )
                    candidates.append(
                        _candidate(
                            dep=dep,
                            source_file=str(source_file),
                            line=int(line) if isinstance(line, int) else 0,
                            vuln=vuln,
                            outcome=outcome,
                            mapped=mapped,
                            kev_hit=False,
                            epss=epss,
                            fresh=False,
                            status="needs-review",
                            note="version format not comparable to advisory range; verify manually",
                        )
                    )
                    break
                if not outcome.affected:
                    continue
                seen_cves.update(cve_ids)
                kev_hit = any(alias in kev for alias in cve_ids)
                candidates.append(
                    _candidate(
                        dep=dep,
                        source_file=str(source_file),
                        line=int(line) if isinstance(line, int) else 0,
                        vuln=vuln,
                        outcome=outcome,
                        mapped=mapped,
                        kev_hit=kev_hit,
                        epss=epss,
                        fresh=fresh,
                        status="confirmed" if fresh else "needs-review",
                        note=None,
                    )
                )
                break
        if len(candidates) >= MAX_SCA_CANDIDATES:
            warnings.append(f"sca candidates truncated at {MAX_SCA_CANDIDATES}")
            break
    return candidates, warnings


def _epss_for(vuln: JsonMap, epss: dict[str, JsonMap]) -> JsonMap | None:
    best: JsonMap | None = None
    for cve in _cve_aliases(vuln):
        entry = epss.get(cve)
        if entry is None:
            continue
        score = entry.get("epss")
        if not isinstance(score, (int, float)):
            continue
        if best is None or float(score) > float(best.get("epss", 0)):
            best = {
                "cve": cve,
                "epss": float(score),
                "percentile": float(entry["percentile"]) if isinstance(entry.get("percentile"), (int, float)) else None,
                "date": entry.get("date"),
                "source": "FIRST EPSS",
            }
    return best


def _candidate(
    dep: JsonMap,
    source_file: str,
    line: int,
    vuln: JsonMap,
    outcome: MatchOutcome,
    mapped: str,
    kev_hit: bool,
    epss: dict[str, JsonMap],
    fresh: bool,
    status: str,
    note: str | None,
) -> JsonMap:
    name = str(dep.get("name", "unknown"))
    version = str(dep.get("version", "?"))
    advisory_id = str(vuln.get("id", "unknown-advisory"))
    assessed = advisory_severity(vuln)
    severity = assessed.band
    escalation = ""
    if kev_hit and severity != "critical":
        severity = "critical"
        escalation = "listed in CISA KEV catalog; severity escalated to critical"
    elif kev_hit:
        escalation = "listed in CISA KEV catalog (already critical)"
    fixed_versions = outcome.fixed_versions
    recommended = _recommended_version(version, fixed_versions)
    cwe = advisory_cwe(vuln)
    epss_block = _epss_for(vuln, epss)
    candidate: JsonMap = {
        "matcher_id": f"sca-{mapped}-{name}".lower().replace(" ", "-")[:80],
        "rule_pack": "sca",
        "path": visible_text(source_file, 500),
        "line": line,
        "snippet_redacted": f"{name} {version} pinned; advisory {advisory_id} applies",
        "reason": visible_text(
            note
            or f"{name} {version} is affected by {advisory_id}: {outcome.reason}",
            500,
        ),
        "review_prompt": visible_text(
            vuln.get("summary")
            or "Verify exploitability in this project, then upgrade per advisory fixed versions.",
            500,
        ),
        "category": "supply-chain",
        "severity_hint": severity,
        "severity_basis": assessed.basis,
        "confidence_hint": "high" if status == "confirmed" else "medium",
        "status": status,
        "source": "advisory",
        "advisory_ids": [advisory_id, *(alias for alias in (vuln.get("aliases") or []) if isinstance(alias, str))][:8],
        "affected_range": outcome.affected_range,
        "fixed_versions": list(fixed_versions),
        "kev": kev_hit,
        "known_exploited": kev_hit,
        "advisory_fix": {
            "advisory_id": advisory_id,
            "installed_version": version,
            "fixed_versions": list(fixed_versions),
            "recommended_version": recommended,
        },
        "sources": _source_citations(vuln),
        "cwe": cwe,
        "standards": standards_block(cwe, "", "", "supply-chain"),
        "fingerprint": fingerprint("sca", mapped, name, advisory_id),
        "fresh_advisory_data": fresh,
    }
    if assessed.cvss:
        candidate["cvss"] = assessed.cvss
    if epss_block:
        candidate["epss"] = epss_block
    candidate.update(
        advisory_priority_fields(
            severity, kev_hit, epss_block["epss"] if epss_block else None, cwe
        )
    )
    if escalation:
        candidate["escalation_reason"] = escalation
    if fixed_versions:
        candidate["recommendation"] = (
            f"Upgrade {name} to {recommended or fixed_versions[0]} or later per {advisory_id}."
        )
    else:
        candidate["recommendation"] = (
            f"No fixed version published in {advisory_id}; review advisory mitigations and constraints."
        )
    return candidate


def sca_payload(root: Path, cache: Path, max_age_hours: int) -> JsonMap:
    root = root.resolve()
    deps = deps_payload(root)
    dependencies = deps.get("dependencies")
    dependencies = dependencies if isinstance(dependencies, list) else []
    records, load_warnings = load_advisory_db(cache, max_age_hours)
    provenance = provenance_block(cache, max_age_hours)
    fresh = bool(provenance.get("fresh"))
    candidates, warnings = sca_candidates(dependencies, records, fresh)
    return {
        "project": {},
        "scope": {
            "mode": "sca",
            "advisory_db": provenance,
            "dependencies_count": len(dependencies),
        },
        "advisory_db": provenance,
        "candidates": candidates,
        "candidates_total": len(candidates),
        "warnings": [*load_warnings, *warnings][:100],
    }
