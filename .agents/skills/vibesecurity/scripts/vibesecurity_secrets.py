from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vibesecurity_common import (
    SECRET_KEY,
    JsonMap,
    fingerprint,
    visible_text,
)

FORMATS_FILE: Final = Path(__file__).resolve().parents[1] / "references" / "formats" / "secrets.yaml"
MAX_FORMATS: Final = 128
MAX_REGEX_CHARS: Final = 500
ENTROPY_MIN_LENGTH: Final = 25
ENTROPY_CANDIDATE: Final = re.compile(r"[A-Za-z0-9+/_-]{25,}")
HEX_TOKEN: Final = re.compile(r"\A[0-9a-fA-F]+\Z")
BASE32_TOKEN: Final = re.compile(r"\A[A-Z2-7]+=*\Z")
SECRET_CONTEXT: Final = re.compile(rf"(?i)\b{SECRET_KEY}\b|passwd|pwd|credential")
ENTROPY_THRESHOLDS: Final = {
    "hex": (3.9, 40),
    "base32": (4.3, 32),
    "base64": (4.7, 32),
}
ALLOWED_SEVERITIES: Final = {"critical", "high", "medium", "low", "info"}
ALLOWED_CONFIDENCE: Final = {"high", "medium", "low"}


@dataclass(frozen=True, slots=True)
class SecretFormat:
    format_id: str
    severity_hint: str
    confidence_hint: str
    regex: re.Pattern[str]
    description: str
    review_prompt: str


@dataclass(frozen=True, slots=True)
class SecretHit:
    kind: str  # "format" or "entropy"
    format_id: str
    line: int
    column: int
    severity_hint: str
    confidence_hint: str
    description: str
    review_prompt: str


def parse_formats(path: Path = FORMATS_FILE) -> tuple[tuple[SecretFormat, ...], tuple[str, ...]]:
    """Parse the restricted-subset secret format library."""
    warnings: list[str] = []
    formats: list[SecretFormat] = []
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return (), (f"secret format file unreadable ({type(exc).__name__}); format engine disabled",)
    draft: dict[str, str] = {}
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- id:"):
            _add_format(draft, formats, warnings)
            draft = {"id": line.split(":", 1)[1].strip().strip("\"'")}
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        draft[key.strip()] = value.strip().strip("\"'")
    _add_format(draft, formats, warnings)
    if len(formats) > MAX_FORMATS:
        warnings.append(f"format count exceeds {MAX_FORMATS}; truncated")
        formats = formats[:MAX_FORMATS]
    return tuple(formats), tuple(warnings)


def _add_format(draft: dict[str, str], formats: list[SecretFormat], warnings: list[str]) -> None:
    format_id = draft.get("id", "")
    pattern = draft.get("regex", "")
    if not format_id or not pattern:
        if draft:
            warnings.append(f"format '{format_id or 'unknown'}' missing id or regex; ignored")
        return
    if len(pattern) > MAX_REGEX_CHARS:
        warnings.append(f"format '{format_id}' regex exceeds {MAX_REGEX_CHARS} chars; ignored")
        return
    if '"' in pattern:
        warnings.append(f"format '{format_id}' regex contains a quote character; ignored")
        return
    try:
        compiled = re.compile(pattern)
    except re.error:
        warnings.append(f"format '{format_id}' regex does not compile; ignored")
        return
    severity = draft.get("severity_hint", "high")
    confidence = draft.get("confidence_hint", "high")
    if severity not in ALLOWED_SEVERITIES or confidence not in ALLOWED_CONFIDENCE:
        warnings.append(f"format '{format_id}' invalid severity/confidence; ignored")
        return
    formats.append(
        SecretFormat(
            format_id=format_id,
            severity_hint=severity,
            confidence_hint=confidence,
            regex=compiled,
            description=draft.get("description", "Undocumented credential format."),
            review_prompt=draft.get(
                "review_prompt", "Validate the credential is real without printing it."
            ),
        )
    )


def shannon_entropy(token: str) -> float:
    if not token:
        return 0.0
    counts: dict[str, int] = {}
    for character in token:
        counts[character] = counts.get(character, 0) + 1
    total = len(token)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _entropy_class(token: str) -> str:
    if HEX_TOKEN.match(token):
        return "hex"
    if BASE32_TOKEN.match(token):
        return "base32"
    return "base64"


def entropy_hit(token: str) -> bool:
    """B2: high-entropy candidate gated on charset class and length."""
    if len(token) < ENTROPY_MIN_LENGTH:
        return False
    token_class = _entropy_class(token)
    threshold, min_length = ENTROPY_THRESHOLDS[token_class]
    if len(token) < min_length:
        return False
    return shannon_entropy(token) >= threshold


def scan_text(text: str, formats: tuple[SecretFormat, ...]) -> list[SecretHit]:
    """Run format regexes and the entropy layer over one file's text."""
    hits: list[SecretHit] = []
    seen: set[tuple[str, int]] = set()
    lines = text.splitlines()
    for line_index, line in enumerate(lines, start=1):
        for secret_format in formats:
            for match in secret_format.regex.finditer(line):
                key = (secret_format.format_id, line_index)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    SecretHit(
                        kind="format",
                        format_id=secret_format.format_id,
                        line=line_index,
                        column=match.start() + 1,
                        severity_hint=secret_format.severity_hint,
                        confidence_hint=secret_format.confidence_hint,
                        description=secret_format.description,
                        review_prompt=secret_format.review_prompt,
                    )
                )
        if SECRET_CONTEXT.search(line):
            for match in ENTROPY_CANDIDATE.finditer(line):
                token = match.group(0)
                if entropy_hit(token):
                    key = ("high-entropy-literal", line_index)
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append(
                        SecretHit(
                            kind="entropy",
                            format_id="high-entropy-literal",
                            line=line_index,
                            column=match.start() + 1,
                            severity_hint="medium",
                            confidence_hint="low",
                            description="High-entropy value assigned in a secret-named context.",
                            review_prompt="Check whether this value is a real credential without printing it.",
                        )
                    )
                    break
    return hits


def secret_candidates(
    path_text: str,
    rel: str,
    text: str,
    formats: tuple[SecretFormat, ...] | None = None,
) -> list[JsonMap]:
    """Produce scan candidates for one file. Values are never emitted."""
    loaded, warnings = parse_formats() if formats is None else (formats, ())
    candidates: list[JsonMap] = []
    for hit in scan_text(text, loaded):
        candidates.append(
            {
                "matcher_id": f"secret-{hit.format_id}",
                "rule_pack": "secrets",
                "path": visible_text(path_text, 1_000),
                "line": hit.line,
                "snippet_redacted": f"{hit.format_id} match at column {hit.column} (value withheld)",
                "reason": visible_text(hit.description, 500),
                "review_prompt": visible_text(hit.review_prompt, 500),
                "category": "secrets",
                "severity_hint": hit.severity_hint,
                "confidence_hint": hit.confidence_hint,
                "status": "needs-review",
                "source": "secret-engine",
                "fingerprint": fingerprint("secret", hit.format_id, rel),
            }
        )
    if warnings:
        candidates.append(
            {
                "matcher_id": "secret-engine-warnings",
                "rule_pack": "secrets",
                "path": visible_text(path_text, 1_000),
                "line": 0,
                "snippet_redacted": "",
                "reason": "; ".join(warnings)[:500],
                "review_prompt": "Fix the secret format library before relying on format detection.",
                "category": "secrets",
                "severity_hint": "low",
                "confidence_hint": "high",
                "status": "needs-review",
                "source": "secret-engine",
                "fingerprint": fingerprint("secret-engine-warnings", rel),
            }
        )
    return candidates


def corpus_scores(
    positive_texts: list[str], negative_texts: list[str]
) -> dict[str, float]:
    """Measure recall and precision of the engine on labeled texts."""
    formats, _ = parse_formats()
    true_positives = 0
    false_negatives = 0
    for text in positive_texts:
        if any(hit.kind == "format" for hit in scan_text(text, formats)):
            true_positives += 1
        else:
            false_negatives += 1
    hits_negative = 0
    for text in negative_texts:
        if any(hit.kind == "format" for hit in scan_text(text, formats)):
            hits_negative += 1
    recall = true_positives / (true_positives + false_negatives) if positive_texts else 1.0
    precision = (
        true_positives / (true_positives + hits_negative)
        if (true_positives + hits_negative)
        else 1.0
    )
    return {"recall": recall, "precision": precision, "negative_hits": float(hits_negative)}
