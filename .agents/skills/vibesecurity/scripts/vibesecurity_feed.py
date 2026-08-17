from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final

from vibesecurity_common import (
    JsonMap,
    JsonValue,
    sha256_bytes,
    sha256_file,
)
from vibesecurity_deps import deps_payload, osv_query_packages

CACHE_DIR: Final = ".vibesecurity/cache"
OSV_QUERY_BATCH_URL: Final = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL: Final = "https://api.osv.dev/v1/vulns/"
KEV_URL: Final = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
USER_AGENT: Final = "VibeSecurity-feed/3 (+https://github.com/Master0fFate/VibeSecurity)"
HTTP_TIMEOUT_SECONDS: Final = 30
HTTP_RETRIES: Final = 2
MAX_PACKAGES_PER_REFRESH: Final = 2_000
MAX_VULN_RECORDS: Final = 500
MAX_RESPONSE_BYTES: Final = 100_000_000
BUNDLE_SCHEMA: Final = "vibesecurity-advisory-bundle/1"


@dataclass(frozen=True, slots=True)
class FetchResult:
    ok: bool
    bytes_fetched: int
    detail: str


def cache_dir(root: Path) -> Path:
    return (root.resolve() / CACHE_DIR).resolve()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None


def _http_get(url: str, accept: str = "application/json") -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    context = ssl.create_default_context()
    last_error: Exception | None = None
    for attempt in range(HTTP_RETRIES + 1):
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS, context=context) as response:
                data = response.read(MAX_RESPONSE_BYTES + 1)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise ValueError(f"response exceeds {MAX_RESPONSE_BYTES} bytes: {url}")
                return data
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            last_error = exc
            if attempt < HTTP_RETRIES:
                time.sleep(2**attempt)
    raise OSError(f"GET {url} failed after {HTTP_RETRIES + 1} attempts: {last_error}")


def _http_post_json(url: str, payload: JsonMap) -> bytes:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
        method="POST",
    )
    context = ssl.create_default_context()
    last_error: Exception | None = None
    for attempt in range(HTTP_RETRIES + 1):
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS, context=context) as response:
                data = response.read(MAX_RESPONSE_BYTES + 1)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise ValueError(f"response exceeds {MAX_RESPONSE_BYTES} bytes: {url}")
                return data
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            last_error = exc
            if attempt < HTTP_RETRIES:
                time.sleep(2**attempt)
    raise OSError(f"POST {url} failed after {HTTP_RETRIES + 1} attempts: {last_error}")


def _write_cache(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def refresh_osv(root: Path, directory: Path) -> tuple[FetchResult, list[str]]:
    """Query OSV (which aggregates GitHub GHSA advisories) per installed package.

    querybatch returns only advisory ids, so each id is fetched once as a full
    OSV record (ranges, aliases, fixed events) and cached.
    """
    deps = deps_payload(root)
    dependencies = deps.get("dependencies")
    packages = osv_query_packages(dependencies if isinstance(dependencies, list) else [])
    warnings: list[str] = []
    if not packages:
        return FetchResult(False, 0, "no supported lockfiles or packages found"), [
            "no supported lockfiles found; nothing to query"
        ]
    if len(packages) > MAX_PACKAGES_PER_REFRESH:
        warnings.append(
            f"package count {len(packages)} exceeds {MAX_PACKAGES_PER_REFRESH}; truncated"
        )
        packages = packages[:MAX_PACKAGES_PER_REFRESH]
    queries = [
        {"package": {"ecosystem": ecosystem, "name": name}}
        for ecosystem, name in packages
    ]
    try:
        response = _http_post_json(OSV_QUERY_BATCH_URL, {"queries": queries})
        batch = json.loads(response.decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return FetchResult(False, 0, str(exc)), [f"osv querybatch failed: {exc}"]
    results = batch.get("results") if isinstance(batch, dict) else None
    if not isinstance(results, list) or len(results) != len(packages):
        return FetchResult(False, len(response), "osv querybatch shape unexpected"), [
            "osv querybatch returned unexpected shape; nothing cached"
        ]
    vuln_ids: set[str] = set()
    for result in results:
        vulns = result.get("vulns") if isinstance(result, dict) else None
        if isinstance(vulns, list):
            for vuln in vulns:
                if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                    vuln_ids.add(vuln["id"])
    ordered_ids = sorted(vuln_ids)[:MAX_VULN_RECORDS]
    full_records: dict[str, JsonValue] = {}
    total_bytes = len(response)
    for vuln_id in ordered_ids:
        try:
            data = _http_get(OSV_VULN_URL + vuln_id)
            total_bytes += len(data)
            full_records[vuln_id] = json.loads(data.decode("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            warnings.append(f"osv vuln fetch failed for {vuln_id}: {exc}")
    fetched = 0
    for index, (ecosystem, name) in enumerate(packages):
        record_path = directory / "osv" / ecosystem.replace("/", "_") / f"{name.replace('/', '__')}.json"
        result = results[index]
        vulns = result.get("vulns") if isinstance(result, dict) else None
        record = {
            "schema": "vibesecurity-osv-record/1",
            "ecosystem": ecosystem,
            "package": name,
            "fetched_at": _utc_iso(_now()),
        }
        ids: list[str] = []
        if isinstance(vulns, list):
            for vuln in vulns:
                if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                    ids.append(vuln["id"])
        record["advisory_ids"] = ids
        record["vulns"] = [full_records[vuln_id] for vuln_id in ids if vuln_id in full_records]
        payload = json.dumps(record, sort_keys=True).encode("utf-8")
        _write_cache(record_path, payload)
        record_path.with_suffix(".sha256").write_text(sha256_bytes(payload), encoding="utf-8")
        fetched += 1
    detail = f"{fetched}/{len(packages)} package records, {len(full_records)}/{len(vuln_ids)} advisory records stored"
    return FetchResult(fetched > 0, total_bytes, detail), warnings


def refresh_kev(directory: Path) -> tuple[FetchResult, list[str]]:
    warnings: list[str] = []
    try:
        data = _http_get(KEV_URL)
    except OSError as exc:
        return FetchResult(False, 0, str(exc)), [f"kev fetch failed: {exc}"]
    try:
        parsed = json.loads(data.decode("utf-8"))
        title = parsed.get("title")
        if not isinstance(parsed, dict) or not isinstance(title, str):
            raise ValueError("kev payload missing expected title field")
    except (json.JSONDecodeError, ValueError) as exc:
        return FetchResult(False, len(data), str(exc)), [f"kev payload invalid: {exc}"]
    record = {
        "schema": "vibesecurity-kev-record/1",
        "source": KEV_URL,
        "fetched_at": _utc_iso(_now()),
        "catalog": parsed,
    }
    payload = json.dumps(record, sort_keys=True).encode("utf-8")
    path = directory / "kev" / "known_exploited_vulnerabilities.json"
    _write_cache(path, payload)
    path.with_suffix(".sha256").write_text(sha256_bytes(payload), encoding="utf-8")
    return FetchResult(True, len(data), f"kev catalog stored ({len(data)} bytes)"), warnings


def feed_refresh_payload(
    root: Path,
    directory: Path,
    network_enabled: bool = True,
) -> JsonMap:
    warnings: list[str] = []
    results: list[JsonMap] = []
    if not network_enabled:
        return {
            "project": {},
            "scope": {"mode": "feed", "action": "refresh", "cache_dir": str(directory)},
            "network_enabled": False,
            "results": [],
            "warnings": ["network disabled by policy; refresh refused"],
            "candidates": [],
        }
    osv_result, osv_warnings = refresh_osv(root, directory)
    warnings.extend(osv_warnings)
    results.append({"source": "osv+ghsa", **_result_json(osv_result)})
    kev_result, kev_warnings = refresh_kev(directory)
    warnings.extend(kev_warnings)
    results.append({"source": "kev", **_result_json(kev_result)})
    manifest = build_manifest(directory)
    _write_cache(directory / "manifest.json", json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8"))
    return {
        "project": {},
        "scope": {"mode": "feed", "action": "refresh", "cache_dir": str(directory)},
        "network_enabled": True,
        "results": results,
        "manifest": manifest,
        "warnings": warnings[:100],
        "candidates": [],
    }


def _result_json(result: FetchResult) -> JsonMap:
    return {"ok": result.ok, "bytes": result.bytes_fetched, "detail": result.detail}


def build_manifest(directory: Path) -> JsonMap:
    files: list[JsonMap] = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.suffix == ".json":
            try:
                digest = sha256_file(path)
                stat = path.stat()
            except OSError:
                continue
            files.append(
                {
                    "path": path.relative_to(directory).as_posix(),
                    "sha256": digest,
                    "bytes": stat.st_size,
                    "mtime": _utc_iso(
                        datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                    ),
                }
            )
    return {
        "schema": "vibesecurity-cache-manifest/1",
        "generated_at": _utc_iso(_now()),
        "files": files[:10_000],
    }


def load_advisory_db(
    directory: Path,
    max_age_hours: int,
) -> tuple[dict[str, JsonValue], list[str]]:
    """Load the local cache (or an exported bundle directory) for offline SCA."""
    warnings: list[str] = []
    records: dict[str, JsonValue] = {}
    if not directory.is_dir():
        return records, [f"advisory cache not found at {directory}"]
    manifest_path = directory / "manifest.json"
    newest: datetime | None = None
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            newest = parse_utc(str(manifest.get("generated_at", "")))
        except (OSError, json.JSONDecodeError, ValueError):
            warnings.append("advisory cache manifest unreadable; freshness unknown")
    else:
        warnings.append("advisory cache manifest missing; freshness unknown")
    for path in sorted(directory.rglob("*.json")):
        if path.name in {"manifest.json", "bundle.json"}:
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            warnings.append(f"unreadable advisory record: {path.name}")
            continue
        records[path.relative_to(directory).as_posix()] = record
        fetched = parse_utc(str(record.get("fetched_at", ""))) if isinstance(record, dict) else None
        if fetched and (newest is None or fetched > newest):
            newest = fetched
    age_hours: float | None = None
    stale = False
    if newest is not None:
        age_hours = (_now() - newest).total_seconds() / 3600
        stale = age_hours > max_age_hours
        if stale:
            warnings.append(
                f"advisory data is {age_hours:.0f}h old (limit {max_age_hours}h); advisory results downgraded to needs-review"
            )
    else:
        stale = True
        warnings.append("advisory data age unknown; advisory results downgraded to needs-review")
    return records, warnings


def provenance_block(directory: Path, max_age_hours: int) -> JsonMap:
    records, warnings = load_advisory_db(directory, max_age_hours)
    newest: datetime | None = None
    for record in records.values():
        if isinstance(record, dict):
            fetched = parse_utc(str(record.get("fetched_at", "")))
            if fetched and (newest is None or fetched > newest):
                newest = fetched
    age_hours = (_now() - newest).total_seconds() / 3600 if newest else None
    return {
        "source": "osv+ghsa+kev local cache",
        "cache_dir": str(directory),
        "fetched_at": _utc_iso(newest) if newest else None,
        "age_hours": round(age_hours, 1) if age_hours is not None else None,
        "max_age_hours": max_age_hours,
        "fresh": bool(newest) and age_hours is not None and age_hours <= max_age_hours,
        "records": len(records),
        "warnings": warnings[:20],
    }


def export_bundle(directory: Path, output: Path) -> JsonMap:
    """D5: write a checksummed, single-file advisory bundle for air-gapped use."""
    manifest = build_manifest(directory)
    sections: dict[str, JsonValue] = {}
    for path in sorted(directory.rglob("*.json")):
        if path.name in {"manifest.json", "bundle.json"}:
            continue
        key = path.relative_to(directory).as_posix()
        try:
            sections[key] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
    section_bytes = json.dumps(sections, sort_keys=True).encode("utf-8")
    bundle: JsonMap = {
        "schema": BUNDLE_SCHEMA,
        "created_at": _utc_iso(_now()),
        "manifest": manifest,
        "sections_sha256": sha256_bytes(section_bytes),
        "sections": sections,
    }
    payload = json.dumps(bundle, sort_keys=True, indent=1).encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    return {
        "project": {},
        "scope": {"mode": "feed", "action": "export"},
        "bundle_path": str(output),
        "bundle_sha256": sha256_bytes(payload),
        "bundle_bytes": len(payload),
        "sections": len(sections),
        "created_at": bundle["created_at"],
        "warnings": [],
        "candidates": [],
    }


def import_bundle(bundle_path: Path, directory: Path) -> JsonMap:
    """Verify a bundle's checksums and unpack it into a cache directory."""
    try:
        data = bundle_path.read_bytes()
        bundle = json.loads(data.decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"advisory bundle unreadable: {exc}") from exc
    if not isinstance(bundle, dict) or bundle.get("schema") != BUNDLE_SCHEMA:
        raise ValueError("advisory bundle schema mismatch")
    sections = bundle.get("sections")
    if not isinstance(sections, dict):
        raise ValueError("advisory bundle has no sections")
    recomputed = sha256_bytes(json.dumps(sections, sort_keys=True).encode("utf-8"))
    if recomputed != bundle.get("sections_sha256"):
        raise ValueError(
            f"advisory bundle integrity failure: sections sha256 mismatch ({recomputed} != {bundle.get('sections_sha256')})"
        )
    for key, value in sections.items():
        target = directory / key
        if not str(target.resolve()).startswith(str(directory.resolve())):
            raise ValueError(f"advisory bundle entry escapes cache dir: {key}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    manifest = bundle.get("manifest")
    if isinstance(manifest, dict):
        _write_cache(
            directory / "manifest.json",
            json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8"),
        )
    return {
        "project": {},
        "scope": {"mode": "feed", "action": "import"},
        "cache_dir": str(directory),
        "sections": len(sections),
        "created_at": bundle.get("created_at"),
        "warnings": [],
        "candidates": [],
    }


def feed_status_payload(directory: Path, max_age_hours: int) -> JsonMap:
    return {
        "project": {},
        "scope": {"mode": "feed", "action": "status"},
        "advisory_db": provenance_block(directory, max_age_hours),
        "warnings": [],
        "candidates": [],
    }
