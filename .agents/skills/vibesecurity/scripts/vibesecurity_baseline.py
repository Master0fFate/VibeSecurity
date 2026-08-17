from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, JsonValue, visible_text

BASELINE_FILE: Final = ".vibesecurity/baseline.json"
BASELINE_SCHEMA: Final = "vibesecurity-baseline/1"
MAX_BASELINE_BYTES: Final = 1_000_000
MAX_BASELINE_ENTRIES: Final = 5_000


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    fingerprint: str
    reason: str
    approved_by: str
    expires_on: date
    raw_expiry: str

    def to_json(self) -> JsonMap:
        return {
            "fingerprint": self.fingerprint,
            "reason": visible_text(self.reason, 500),
            "approved_by": visible_text(self.approved_by, 200),
            "expires_on": self.expires_on.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class Baseline:
    entries: tuple[BaselineEntry, ...]
    active: dict[str, BaselineEntry]
    expired: tuple[BaselineEntry, ...]
    warnings: tuple[str, ...]
    loaded: bool


def _parse_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def load_baseline(root: Path, today: date | None = None) -> Baseline:
    """Load the project baseline. Expired entries re-fire; errors never silence findings."""
    path = root.resolve() / BASELINE_FILE
    today = today or datetime.now().date()
    try:
        size = path.stat().st_size
    except OSError:
        return Baseline((), {}, (), (), False)
    if size > MAX_BASELINE_BYTES:
        return Baseline(
            (),
            {},
            (),
            (f"{BASELINE_FILE} exceeds {MAX_BASELINE_BYTES} bytes; ignored",),
            False,
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return Baseline(
            (),
            {},
            (),
            (f"{BASELINE_FILE} unreadable ({type(exc).__name__}); no suppressions applied",),
            False,
        )
    if not isinstance(data, dict):
        return Baseline((), {}, (), (f"{BASELINE_FILE} must be an object; ignored",), False)
    if data.get("schema") != BASELINE_SCHEMA:
        return Baseline(
            (),
            {},
            (),
            (f"{BASELINE_FILE} schema must be '{BASELINE_SCHEMA}'; ignored",),
            False,
        )
    raw_entries = data.get("entries")
    if not isinstance(raw_entries, list):
        return Baseline((), {}, (), (f"{BASELINE_FILE} entries must be a list; ignored",), False)
    warnings: list[str] = []
    entries: list[BaselineEntry] = []
    active: dict[str, BaselineEntry] = {}
    expired: list[BaselineEntry] = []
    for value in raw_entries[:MAX_BASELINE_ENTRIES]:
        if not isinstance(value, dict):
            continue
        fingerprint = value.get("fingerprint")
        expiry = value.get("expires_on")
        reason = value.get("reason", "")
        approved_by = value.get("approved_by", "")
        if not isinstance(fingerprint, str) or not isinstance(expiry, str):
            warnings.append("baseline entry missing fingerprint or expires_on; ignored")
            continue
        parsed = _parse_date(expiry)
        if parsed is None:
            warnings.append(f"baseline entry '{fingerprint[:12]}' has invalid expires_on; treated as expired")
            parsed = today - timedelta(days=1)
        entry = BaselineEntry(
            fingerprint=fingerprint,
            reason=str(reason),
            approved_by=str(approved_by),
            expires_on=parsed,
            raw_expiry=expiry,
        )
        entries.append(entry)
        if parsed < today:
            expired.append(entry)
        else:
            active[fingerprint] = entry
    if len(raw_entries) > MAX_BASELINE_ENTRIES:
        warnings.append(f"baseline truncated at {MAX_BASELINE_ENTRIES} entries")
    return Baseline(tuple(entries), active, tuple(expired), tuple(warnings), True)


def apply_baseline(
    items: list[JsonMap], baseline: Baseline
) -> tuple[list[JsonMap], list[JsonMap], list[JsonMap]]:
    """Split items into (visible, suppressed, re_fired_expired)."""
    visible: list[JsonMap] = []
    suppressed: list[JsonMap] = []
    re_fired: list[JsonMap] = []
    active = baseline.active
    expired_prints = {entry.fingerprint for entry in baseline.expired}
    for item in items:
        fingerprint = item.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint in active:
            marked = dict(item)
            marked["suppressed"] = True
            marked["suppression_reason"] = active[fingerprint].reason
            marked["suppression_approved_by"] = active[fingerprint].approved_by
            marked["suppression_expires_on"] = active[fingerprint].expires_on.isoformat()
            suppressed.append(marked)
            continue
        if isinstance(fingerprint, str) and fingerprint in expired_prints:
            marked = dict(item)
            marked["suppression_expired"] = True
            re_fired.append(marked)
            visible.append(marked)
            continue
        visible.append(item)
    return visible, suppressed, re_fired


def baseline_payload(root: Path, max_age_days: int) -> JsonMap:
    baseline = load_baseline(root)
    over_aged = [
        entry.to_json()
        for entry in baseline.expired
        if (datetime.now().date() - entry.expires_on).days > max_age_days
    ]
    return {
        "project": {},
        "scope": {"mode": "baseline"},
        "loaded": baseline.loaded,
        "entries": len(baseline.entries),
        "active": len(baseline.active),
        "expired": len(baseline.expired),
        "max_age_days": max_age_days,
        "long_expired": over_aged,
        "warnings": [visible_text(item, 300) for item in baseline.warnings],
        "candidates": [],
    }
