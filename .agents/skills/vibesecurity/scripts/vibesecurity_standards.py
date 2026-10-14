from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, JsonValue

STANDARDS_DIR: Final = Path(__file__).resolve().parents[1] / "references" / "standards"
CWE_ID: Final = re.compile(r"^CWE-\d{1,5}$")
OWASP_ID: Final = re.compile(r"^(?:A\d{2}:2025|LLM\d{2}:2025|ASI\d{2}:2026)$")
ASVS_ID: Final = re.compile(r"^V\d{1,2}\.\d{1,2}\.\d{1,2}$")


@cache
def _load(name: str) -> JsonMap:
    path = STANDARDS_DIR / name
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _entries(name: str, key: str = "entries") -> JsonMap:
    value = _load(name).get(key)
    return value if isinstance(value, dict) else {}


def split_ids(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def valid_cwe(value: str) -> bool:
    return not value or all(CWE_ID.fullmatch(item) for item in split_ids(value))


def valid_owasp(value: str) -> bool:
    return not value or all(OWASP_ID.fullmatch(item) for item in split_ids(value))


def valid_asvs(value: str) -> bool:
    return not value or all(ASVS_ID.fullmatch(item) for item in split_ids(value))


def cwe_name(cwe_id: str) -> str:
    entry = _entries("cwe-catalog.json").get(cwe_id)
    name = entry.get("name") if isinstance(entry, dict) else None
    return name if isinstance(name, str) else ""


@cache
def cwe_top25_ranks() -> dict[str, int]:
    ranks: dict[str, int] = {}
    entries = _load("cwe-top25-2025.json").get("entries")
    if isinstance(entries, list):
        for item in entries:
            if isinstance(item, dict) and isinstance(item.get("id"), str) and isinstance(item.get("rank"), int):
                ranks[item["id"]] = item["rank"]
    return ranks


def cwe_top25_rank(cwe_id: str) -> int | None:
    return cwe_top25_ranks().get(cwe_id)


def owasp_name(owasp_id: str) -> str:
    data = _load("owasp-top10-2025.json")
    for group in ("top10_2025", "llm_top10_2025", "agentic_top10_2026"):
        block = data.get(group)
        if isinstance(block, dict):
            entries = block.get("entries")
            if isinstance(entries, dict) and isinstance(entries.get(owasp_id), str):
                return entries[owasp_id]
    return ""


def asvs_requirement(asvs_id: str) -> JsonMap:
    entry = _entries("asvs-5.0.0.json", "requirements").get(asvs_id)
    return entry if isinstance(entry, dict) else {}


def category_defaults(category: str) -> JsonMap:
    owasp_map = _load("owasp-top10-2025.json").get("category_map")
    asvs_map = _load("asvs-5.0.0.json").get("category_map")
    owasp = owasp_map.get(category) if isinstance(owasp_map, dict) else None
    asvs = asvs_map.get(category) if isinstance(asvs_map, dict) else None
    return {
        "owasp": [item for item in owasp if isinstance(item, str)] if isinstance(owasp, list) else [],
        "asvs": [item for item in asvs if isinstance(item, str)] if isinstance(asvs, list) else [],
    }


def standards_block(cwe: str, owasp: str, asvs: str, category: str) -> JsonMap:
    defaults = category_defaults(category)
    owasp_ids = split_ids(owasp) or list(defaults["owasp"])[:2]
    asvs_ids = split_ids(asvs) or list(defaults["asvs"])[:3]
    block: JsonMap = {}
    cwe_ids = split_ids(cwe)
    if cwe_ids:
        block["cwe"] = [
            {"id": item, "name": cwe_name(item), "top25_2025_rank": cwe_top25_rank(item)}
            for item in cwe_ids
        ]
    if owasp_ids:
        block["owasp"] = [{"id": item, "name": owasp_name(item)} for item in owasp_ids]
    if asvs_ids:
        block["asvs"] = [
            {"id": item, "level": asvs_requirement(item).get("level"), "text": asvs_requirement(item).get("text")}
            for item in asvs_ids
        ]
    return block


def render_standards_line(block: JsonValue) -> str:
    if not isinstance(block, dict):
        return ""
    parts: list[str] = []
    for item in block.get("cwe") or []:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            label = item["id"]
            if isinstance(item.get("name"), str) and item["name"]:
                label += f" {item['name']}"
            if isinstance(item.get("top25_2025_rank"), int):
                label += f" (CWE Top 25 2025 #{item['top25_2025_rank']})"
            parts.append(label)
    for item in block.get("owasp") or []:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            name = item.get("name")
            parts.append(f"OWASP {item['id']}" + (f" {name}" if isinstance(name, str) and name else ""))
    asvs_ids = [item["id"] for item in block.get("asvs") or [] if isinstance(item, dict) and isinstance(item.get("id"), str)]
    if asvs_ids:
        parts.append("ASVS 5.0.0 " + ", ".join(asvs_ids))
    return "; ".join(parts)
