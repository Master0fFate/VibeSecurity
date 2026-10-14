from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, JsonValue, visible_text

CONFIG_SCHEMA_VERSION: Final = "1"
CONFIG_FILE: Final = ".vibesecurity/config.json"
MAX_CONFIG_BYTES: Final = 100_000
DEFAULT_MAX_CACHE_AGE_HOURS: Final = 72
DEFAULT_HISTORY_WINDOW_MONTHS: Final = 12
DEFAULT_BASELINE_MAX_AGE_DAYS: Final = 180
FAIL_ON_VALUES: Final = frozenset({"none", "confirmed", "confirmed-high", "critical"})

BOOL_KEYS: Final = {"network_enabled", "registry_lookups"}
STR_KEYS: Final = {"fail_on"}
INT_KEYS: Final = {
    "max_cache_age_hours",
    "history_window_months",
    "baseline_max_age_days",
}
LIST_KEYS: Final = {"allowed_analyzers"}
KNOWN_KEYS: Final = {
    "schema_version",
    *BOOL_KEYS,
    *STR_KEYS,
    *INT_KEYS,
    *LIST_KEYS,
}


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    network_enabled: bool = True
    registry_lookups: bool = True
    fail_on: str = "none"
    max_cache_age_hours: int = DEFAULT_MAX_CACHE_AGE_HOURS
    history_window_months: int = DEFAULT_HISTORY_WINDOW_MONTHS
    baseline_max_age_days: int = DEFAULT_BASELINE_MAX_AGE_DAYS
    allowed_analyzers: tuple[str, ...] = (
        "npm-audit",
        "pip-audit",
        "cargo-audit",
        "govulncheck",
        "semgrep",
        "gitleaks",
    )
    warnings: tuple[str, ...] = ()
    source: str = "defaults"

    def to_json(self) -> JsonMap:
        return {
            "schema_version": CONFIG_SCHEMA_VERSION,
            "network_enabled": self.network_enabled,
            "registry_lookups": self.registry_lookups,
            "fail_on": self.fail_on,
            "max_cache_age_hours": self.max_cache_age_hours,
            "history_window_months": self.history_window_months,
            "baseline_max_age_days": self.baseline_max_age_days,
            "allowed_analyzers": list(self.allowed_analyzers),
        }


def _coerce_bool(value: JsonValue, key: str, warnings: list[str]) -> bool | None:
    if isinstance(value, bool):
        return value
    warnings.append(f"config key '{key}' must be a boolean; ignored")
    return None


def _coerce_int(
    value: JsonValue, key: str, warnings: list[str], minimum: int, maximum: int
) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        if minimum <= value <= maximum:
            return value
        warnings.append(
            f"config key '{key}' outside {minimum}..{maximum}; ignored"
        )
        return None
    warnings.append(f"config key '{key}' must be an integer; ignored")
    return None


def _coerce_str(
    value: JsonValue, key: str, warnings: list[str], allowed: frozenset[str]
) -> str | None:
    if isinstance(value, str):
        if not allowed or value in allowed:
            return value
        warnings.append(
            f"config key '{key}' must be one of {sorted(allowed)}; ignored"
        )
        return None
    warnings.append(f"config key '{key}' must be a string; ignored")
    return None


def _coerce_list(value: JsonValue, key: str, warnings: list[str]) -> tuple[str, ...] | None:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        if len(value) <= 64:
            return tuple(value)
        warnings.append(f"config key '{key}' exceeds 64 entries; ignored")
        return None
    warnings.append(f"config key '{key}' must be a list of strings; ignored")
    return None


def load_policy_config(root: Path) -> PolicyConfig:
    """Load .vibesecurity/config.json. Unknown or invalid keys become warnings."""
    path = root.resolve() / CONFIG_FILE
    warnings: list[str] = []
    settings: dict[str, JsonValue] = {}
    try:
        size = path.stat().st_size
    except OSError:
        return PolicyConfig(warnings=(), source="defaults")
    if size > MAX_CONFIG_BYTES:
        return PolicyConfig(
            warnings=(f"{CONFIG_FILE} exceeds {MAX_CONFIG_BYTES} bytes; ignored",),
            source="defaults",
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return PolicyConfig(
            warnings=(
                f"{CONFIG_FILE} could not be parsed ({type(exc).__name__}); defaults used",
            ),
            source="defaults",
        )
    if not isinstance(data, dict):
        return PolicyConfig(
            warnings=(f"{CONFIG_FILE} must contain a JSON object; ignored",),
            source="defaults",
        )
    schema = data.get("schema_version")
    if schema != CONFIG_SCHEMA_VERSION:
        warnings.append(
            f"{CONFIG_FILE} schema_version {schema!r} is not '{CONFIG_SCHEMA_VERSION}'; file ignored"
        )
        return PolicyConfig(warnings=tuple(warnings), source="defaults")
    for key, value in data.items():
        if key not in KNOWN_KEYS:
            warnings.append(f"{CONFIG_FILE}: unknown key '{key}' ignored")
            continue
        settings[key] = value
    defaults = PolicyConfig()
    network = (
        _coerce_bool(settings["network_enabled"], "network_enabled", warnings)
        if "network_enabled" in settings
        else None
    )
    registry = (
        _coerce_bool(settings["registry_lookups"], "registry_lookups", warnings)
        if "registry_lookups" in settings
        else None
    )
    fail_on = (
        _coerce_str(settings["fail_on"], "fail_on", warnings, FAIL_ON_VALUES)
        if "fail_on" in settings
        else None
    )
    cache_age = (
        _coerce_int(
            settings["max_cache_age_hours"], "max_cache_age_hours", warnings, 1, 24 * 90
        )
        if "max_cache_age_hours" in settings
        else None
    )
    history = (
        _coerce_int(
            settings["history_window_months"], "history_window_months", warnings, 1, 240
        )
        if "history_window_months" in settings
        else None
    )
    baseline_age = (
        _coerce_int(
            settings["baseline_max_age_days"], "baseline_max_age_days", warnings, 1, 3650
        )
        if "baseline_max_age_days" in settings
        else None
    )
    analyzers = (
        _coerce_list(settings["allowed_analyzers"], "allowed_analyzers", warnings)
        if "allowed_analyzers" in settings
        else None
    )
    return PolicyConfig(
        network_enabled=network if network is not None else defaults.network_enabled,
        registry_lookups=registry if registry is not None else defaults.registry_lookups,
        fail_on=fail_on if fail_on is not None else defaults.fail_on,
        max_cache_age_hours=cache_age if cache_age is not None else defaults.max_cache_age_hours,
        history_window_months=history if history is not None else defaults.history_window_months,
        baseline_max_age_days=baseline_age if baseline_age is not None else defaults.baseline_max_age_days,
        allowed_analyzers=analyzers if analyzers is not None else defaults.allowed_analyzers,
        warnings=tuple(warnings[:20]),
        source="file",
    )


def merge_policy(config: PolicyConfig, **cli_overrides: JsonValue) -> PolicyConfig:
    """Apply CLI overrides on top of the config file. CLI > config > defaults."""
    merged = dict(
        network_enabled=config.network_enabled,
        registry_lookups=config.registry_lookups,
        fail_on=config.fail_on,
        max_cache_age_hours=config.max_cache_age_hours,
        history_window_months=config.history_window_months,
        baseline_max_age_days=config.baseline_max_age_days,
        allowed_analyzers=config.allowed_analyzers,
    )
    for key, value in cli_overrides.items():
        if value is None:
            continue
        if key in BOOL_KEYS and isinstance(value, bool):
            merged[key] = value
        elif key in STR_KEYS and isinstance(value, str):
            merged[key] = value
        elif key in INT_KEYS and isinstance(value, int) and not isinstance(value, bool):
            merged[key] = value
    return PolicyConfig(
        warnings=config.warnings,
        source=config.source,
        **merged,
    )


def visible_warnings(config: PolicyConfig) -> list[str]:
    return [visible_text(item, 300) for item in config.warnings]
