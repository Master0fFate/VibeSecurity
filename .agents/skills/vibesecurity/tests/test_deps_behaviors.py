from __future__ import annotations

from support import FIXTURES, TestFunc
from vibesecurity_deps import deps_payload, osv_query_packages

SAMPLE = FIXTURES / "deps-sample"

EXPECTED_EXACT = {
    ("npm", "express", "4.18.2"),
    ("npm", "lodash", "4.17.21"),
    ("npm", "@scope/util", "2.1.0"),
    ("npm", "debug", "4.3.4"),
    ("npm", "@babel/code-frame", "7.22.13"),
    ("npm", "chalk", "4.1.2"),
    ("npm", "ms", "2.1.3"),
    ("pypi", "flask", "2.3.2"),
    ("pypi", "requests", "2.31.0"),
    ("pypi", "sqlalchemy", "2.0.20"),
    ("pypi", "jinja2", "3.1.2"),
    ("pypi", "celery", "5.3.4"),
    ("pypi", "redis", "5.0.1"),
    ("pypi", "click", "8.1.7"),
    ("go", "github.com/gin-gonic/gin", "v1.9.1"),
    ("go", "github.com/stretchr/testify", "v1.8.4"),
    ("go", "golang.org/x/text", "v0.13.0"),
    ("crates.io", "serde", "1.0.188"),
    ("crates.io", "tokio", "1.32.0"),
    ("crates.io", "rand", "0.8.5"),
    ("rubygems", "rails", "7.0.8"),
    ("rubygems", "rack", "2.2.8"),
    ("rubygems", "puma", "6.3.1"),
    ("packagist", "symfony/console", "v6.3.4"),
    ("packagist", "monolog/monolog", "3.4.0"),
    ("packagist", "psr/log", "3.0.0"),
    ("packagist", "phpunit/phpunit", "10.4.1"),
}


def test_lockfile_parsers_extract_expected_entries() -> None:
    payload = deps_payload(SAMPLE)
    entries = payload["dependencies"]
    found = {(item["ecosystem"], item["name"], item["version"]) for item in entries}
    missing = EXPECTED_EXACT - found
    assert not missing, f"missing lockfile entries: {missing}"
    parse_rate = len(EXPECTED_EXACT & found) / len(EXPECTED_EXACT)
    assert parse_rate >= 0.98


def test_ranged_requirements_are_reported_not_matched() -> None:
    payload = deps_payload(SAMPLE)
    names = {(item["ecosystem"], item["name"]) for item in payload["dependencies"]}
    assert ("pypi", "urllib3") not in names
    assert any("ranged" in warning for warning in payload["warnings"])


def test_osv_query_pairs_are_bounded_and_mapped() -> None:
    payload = deps_payload(SAMPLE)
    pairs = osv_query_packages(payload["dependencies"])
    assert ("npm", "lodash") in pairs
    assert ("PyPI", "flask") in pairs
    assert ("Go", "github.com/gin-gonic/gin") in pairs
    assert ("crates.io", "serde") in pairs
    assert ("RubyGems", "rails") in pairs
    assert ("Packagist", "symfony/console") in pairs
    assert all(" " not in ecosystem for ecosystem, _ in pairs)


def test_deps_output_is_redactable_and_bounded() -> None:
    payload = deps_payload(SAMPLE)
    assert payload["dependencies_count"] == len(payload["dependencies"])
    assert payload["dependencies_count"] <= 20000
    assert isinstance(payload["scope"]["files_considered_count"], int)


TESTS = [
    test_lockfile_parsers_extract_expected_entries,
    test_ranged_requirements_are_reported_not_matched,
    test_osv_query_pairs_are_bounded_and_mapped,
    test_deps_output_is_redactable_and_bounded,
]
