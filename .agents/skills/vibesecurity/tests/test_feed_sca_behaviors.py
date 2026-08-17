from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile

from support import TestFunc, write
import vibesecurity_feed as feed
from vibesecurity_deps import deps_payload
from vibesecurity_feed import (
    export_bundle,
    feed_refresh_payload,
    provenance_block,
)
from vibesecurity_pipeline import resolve_advisory_records
from vibesecurity_sca import sca_candidates, sca_payload
from vibesecurity_common import load_json_file

OSV_RECORD = {
    "id": "OSV-TEST-0001",
    "aliases": ["CVE-2024-99999", "GHSA-test-test-test"],
    "summary": "Synthetic advisory used only by the VibeSecurity test suite.",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "express"},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}, {"fixed": "2.0.1"}]}
            ],
        }
    ],
}

KEV_CATALOG = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "synthetic-test",
    "vulns": [{"cveID": "CVE-2024-99999", "knownRansomwareCampaignUse": "Unknown"}],
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        return

    def do_POST(self):  # noqa: N802
        if self.path.endswith("/querybatch"):
            body = json.dumps({"results": [{"vulns": [{"id": "OSV-TEST-0001"}]}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_GET(self):  # noqa: N802
        if "/vulns/" in self.path:
            body = json.dumps(OSV_RECORD).encode()
        elif self.path.endswith("known_exploited_vulnerabilities.json"):
            body = json.dumps(KEV_CATALOG).encode()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_server() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _sample_root(tmp: str) -> Path:
    root = Path(tmp)
    write(
        root / "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/express": {"version": "1.1.0"}},
            }
        ),
    )
    return root


def test_feed_refresh_stores_cache_and_sca_confirms_with_kev() -> None:
    server = _start_server()
    base = f"http://127.0.0.1:{server.server_port}"
    original_batch = feed.OSV_QUERY_BATCH_URL
    original_vuln = feed.OSV_VULN_URL
    original_kev = feed.KEV_URL
    feed.OSV_QUERY_BATCH_URL = base + "/v1/querybatch"
    feed.OSV_VULN_URL = base + "/v1/vulns/"
    feed.KEV_URL = base + "/feeds/known_exploited_vulnerabilities.json"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = _sample_root(tmp)
            cache = root / ".vibesecurity" / "cache"
            payload = feed_refresh_payload(root, cache, True)
            assert payload["network_enabled"] is True
            results = {item["source"]: item["ok"] for item in payload["results"]}
            assert results.get("osv+ghsa") is True
            assert results.get("kev") is True
            record_path = cache / "osv" / "npm" / "express.json"
            assert record_path.is_file()
            record = json.loads(record_path.read_text(encoding="utf-8"))
            assert record["vulns"][0]["id"] == "OSV-TEST-0001"
            sca = sca_payload(root, cache, 72)
            candidates = sca["candidates"]
            assert candidates, "expected an SCA candidate for express@1.1.0"
            item = candidates[0]
            assert item["status"] == "confirmed"
            assert item["known_exploited"] is True
            assert item["severity_hint"] == "critical"
            assert "CISA KEV" in item["escalation_reason"]
            assert item["advisory_fix"]["recommended_version"] == "1.2.0"
            assert "OSV-TEST-0001" in item["advisory_ids"]
            source_types = {source["type"] for source in item["sources"]}
            assert {"OSV", "CVE", "GHSA"} <= source_types
    finally:
        feed.OSV_QUERY_BATCH_URL = original_batch
        feed.OSV_VULN_URL = original_vuln
        feed.KEV_URL = original_kev
        server.shutdown()


def test_stale_cache_downgrades_sca_to_needs_review() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = _sample_root(tmp)
        cache = root / ".vibesecurity" / "cache" / "osv" / "npm"
        cache.mkdir(parents=True)
        from datetime import datetime, timedelta, timezone

        old = (datetime.now(timezone.utc) - timedelta(hours=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record = {
            "schema": "vibesecurity-osv-record/1",
            "ecosystem": "npm",
            "package": "express",
            "fetched_at": old,
            "vulns": [OSV_RECORD],
        }
        write(cache / "express.json", json.dumps(record))
        provenance = provenance_block(cache.parents[1], 72)
        assert provenance["fresh"] is False
        deps = deps_payload(root)
        candidates, warnings = sca_candidates(deps["dependencies"], {"osv/npm/express.json": record}, False)
        assert candidates
        assert candidates[0]["status"] == "needs-review"
        assert provenance["warnings"], "expected a staleness warning in the provenance block"


def test_bundle_export_import_and_tamper_detection() -> None:
    server = _start_server()
    base = f"http://127.0.0.1:{server.server_port}"
    original_batch = feed.OSV_QUERY_BATCH_URL
    original_vuln = feed.OSV_VULN_URL
    original_kev = feed.KEV_URL
    feed.OSV_QUERY_BATCH_URL = base + "/v1/querybatch"
    feed.OSV_VULN_URL = base + "/v1/vulns/"
    feed.KEV_URL = base + "/feeds/known_exploited_vulnerabilities.json"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = _sample_root(tmp)
            cache = root / ".vibesecurity" / "cache"
            feed_refresh_payload(root, cache, True)
            bundle_path = root / "advisory-bundle.json"
            export = export_bundle(cache, bundle_path)
            assert export["sections"] >= 1
            records, warnings, provenance = resolve_advisory_records(bundle_path)
            assert records and provenance and provenance["fresh"] is True
            bundle = load_json_file(bundle_path)
            bundle["sections"]["osv/npm/express.json"]["vulns"] = []
            tampered = root / "tampered-bundle.json"
            write(tampered, json.dumps(bundle))
            try:
                resolve_advisory_records(tampered)
            except ValueError as exc:
                assert "integrity" in str(exc)
            else:
                raise AssertionError("tampered bundle passed integrity check")
    finally:
        feed.OSV_QUERY_BATCH_URL = original_batch
        feed.OSV_VULN_URL = original_vuln
        feed.KEV_URL = original_kev
        server.shutdown()


def test_version_comparison_subset() -> None:
    from vibesecurity_sca import version_key, version_lt

    assert version_lt("1.0.0", "1.2.0") is True
    assert version_lt("1.2.0", "1.0.0") is False
    assert version_lt("v1.9.9", "v2.0.0") is True
    assert version_lt("1.0.0rc1", "1.0.0") is True
    assert version_lt("1.0.0", "1.0.0") is False
    assert version_key("not-a-version") is None
    assert version_lt("garbage", "1.0.0") is None


def test_fixed_versions_come_only_from_advisory_events() -> None:
    affected = OSV_RECORD["affected"][0]
    deps = [{"ecosystem": "npm", "name": "express", "version": "1.1.0"}]
    record = {"schema": "vibesecurity-osv-record/1", "vulns": [OSV_RECORD]}
    candidates, _ = sca_candidates(deps, {"osv/npm/express.json": record}, True)
    item = candidates[0]
    fixed = set(item["fixed_versions"])
    assert fixed == {"1.2.0", "2.0.1"}
    assert item["advisory_fix"]["recommended_version"] in fixed


TESTS = [
    test_feed_refresh_stores_cache_and_sca_confirms_with_kev,
    test_stale_cache_downgrades_sca_to_needs_review,
    test_bundle_export_import_and_tamper_detection,
    test_version_comparison_subset,
    test_fixed_versions_come_only_from_advisory_events,
]
