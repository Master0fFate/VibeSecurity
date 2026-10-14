from __future__ import annotations

import math
from typing import Final

from vibesecurity_common import JsonMap, JsonValue

ATTACK_VECTOR: Final = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
ATTACK_COMPLEXITY: Final = {"L": 0.77, "H": 0.44}
PRIVILEGES_UNCHANGED: Final = {"N": 0.85, "L": 0.62, "H": 0.27}
PRIVILEGES_CHANGED: Final = {"N": 0.85, "L": 0.68, "H": 0.5}
USER_INTERACTION: Final = {"N": 0.85, "R": 0.62}
IMPACT: Final = {"H": 0.56, "L": 0.22, "N": 0.0}
BASE_METRICS: Final = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(value: float) -> float:
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000
    return (math.floor(scaled / 10_000) + 1) / 10


def severity_band(score: float) -> str:
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def parse_v3_vector(vector: str) -> dict[str, str] | None:
    parts = vector.strip().split("/")
    if not parts or parts[0] not in {"CVSS:3.0", "CVSS:3.1"}:
        return None
    metrics: dict[str, str] = {"version": parts[0][5:]}
    for part in parts[1:]:
        if ":" not in part:
            return None
        key, value = part.split(":", 1)
        metrics[key] = value
    if any(key not in metrics for key in BASE_METRICS):
        return None
    return metrics


def base_score_v3(metrics: dict[str, str]) -> float | None:
    try:
        changed = metrics["S"] == "C"
        privileges = (PRIVILEGES_CHANGED if changed else PRIVILEGES_UNCHANGED)[metrics["PR"]]
        exploitability = (
            8.22
            * ATTACK_VECTOR[metrics["AV"]]
            * ATTACK_COMPLEXITY[metrics["AC"]]
            * privileges
            * USER_INTERACTION[metrics["UI"]]
        )
        iss = 1 - (1 - IMPACT[metrics["C"]]) * (1 - IMPACT[metrics["I"]]) * (1 - IMPACT[metrics["A"]])
    except KeyError:
        return None
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def cvss_summary(severity_entries: JsonValue) -> JsonMap | None:
    if not isinstance(severity_entries, list):
        return None
    v4_vector = ""
    for entry in severity_entries:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("type")
        vector = entry.get("score")
        if not isinstance(vector, str):
            continue
        if kind == "CVSS_V3":
            metrics = parse_v3_vector(vector)
            if metrics is None:
                continue
            score = base_score_v3(metrics)
            if score is None:
                continue
            return {
                "version": metrics["version"],
                "vector": vector[:200],
                "base_score": score,
                "severity": severity_band(score),
                "basis": "base score computed from the vector per FIRST CVSS v3.1 specification section 7.1",
            }
        if kind == "CVSS_V4" and not v4_vector:
            v4_vector = vector
    if v4_vector:
        return {
            "version": "4.0",
            "vector": v4_vector[:300],
            "base_score": None,
            "severity": None,
            "basis": "CVSS v4.0 vector present; the helper does not compute v4.0 scores",
        }
    return None
