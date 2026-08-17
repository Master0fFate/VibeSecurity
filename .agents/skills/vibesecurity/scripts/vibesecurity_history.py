from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final

from vibesecurity_common import JsonMap, fingerprint, visible_text
from vibesecurity_secrets import parse_formats, scan_text

MAX_COMMITS: Final = 5_000
MAX_DIFF_BYTES_PER_COMMIT: Final = 2_000_000
HISTORY_TIMEOUT_SECONDS: Final = 300

HISTORY_SKIP_PARTS: Final = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
}


@dataclass(frozen=True, slots=True)
class HistoryHit:
    commit: str
    path: str
    line: int
    format_id: str
    severity_hint: str
    confidence_hint: str
    description: str
    review_prompt: str


def run_git_history(root: Path, args: tuple[str, ...]) -> tuple[bytes, str]:
    try:
        result = subprocess.run(
            ("git", *args),
            cwd=root,
            check=True,
            capture_output=True,
            timeout=HISTORY_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return b"", "git executable not found"
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or b"").decode("utf-8", errors="replace")
        return b"", detail.strip().splitlines()[0] if detail.strip() else "git failed"
    except subprocess.TimeoutExpired:
        return b"", "git log timed out"
    return result.stdout, ""


def since_date(window_months: int) -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(days=30 * window_months)
    return cutoff.strftime("%Y-%m-%d")


def scan_history(
    root: Path,
    window_months: int,
    all_refs: bool = False,
) -> tuple[list[HistoryHit], list[str]]:
    """Walk `git log -p` within a bounded window and run secret detectors over diffs."""
    warnings: list[str] = []
    log_format = "--pretty=format:@@VSEC:%H"
    args: tuple[str, ...] = (
        "log",
        f"--since={since_date(window_months)}",
        "-p",
        "--no-ext-diff",
        log_format,
    )
    if all_refs:
        args = (*args, "--all")
    raw, error = run_git_history(root, args)
    if error:
        return [], [f"git history walk failed: {error}"]
    formats, format_warnings = parse_formats()
    warnings.extend(format_warnings)
    hits: list[HistoryHit] = []
    seen: set[tuple[str, str, str]] = set()
    commit = ""
    current_path = ""
    line_number = 0
    commits = 0
    consumed = 0
    for raw_line in raw.split(b"\n"):
        consumed += len(raw_line) + 1
        if consumed > MAX_DIFF_BYTES_PER_COMMIT * MAX_COMMITS:
            warnings.append("history output exceeded walk budget; truncated")
            break
        line = raw_line.decode("utf-8", errors="replace")
        if line.startswith("@@VSEC:"):
            commit = line[len("@@VSEC:") :].strip()
            commits += 1
            if commits > MAX_COMMITS:
                warnings.append(f"history walk truncated at {MAX_COMMITS} commits")
                break
            continue
        if line.startswith("+++ b/"):
            current_path = line[6:]
            continue
        if line.startswith("+") and not line.startswith("+++"):
            line_number += 1
            added = line[1:]
            if not added.strip():
                continue
            for hit in scan_text(added, formats):
                key = (commit, current_path, hit.format_id)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    HistoryHit(
                        commit=commit[:12],
                        path=current_path,
                        line=hit.line,
                        format_id=hit.format_id,
                        severity_hint=hit.severity_hint,
                        confidence_hint=hit.confidence_hint,
                        description=hit.description,
                        review_prompt=hit.review_prompt,
                    )
                )
            line_number = 0
        elif line.startswith("-"):
            continue
        else:
            line_number = 0
    return hits, warnings


def history_payload(
    root: Path, window_months: int, all_refs: bool = False
) -> JsonMap:
    root = root.resolve()
    hits, warnings = scan_history(root, window_months, all_refs)
    working_tree_paths = _working_tree_paths(root)
    results: list[JsonMap] = []
    for hit in hits:
        results.append(
            {
                "matcher_id": f"secret-{hit.format_id}",
                "rule_pack": "history",
                "path": visible_text(hit.path, 500),
                "line": 0,
                "commit": hit.commit,
                "only_in_history": hit.path not in working_tree_paths,
                "snippet_redacted": f"{hit.format_id} match in commit {hit.commit} (value withheld)",
                "reason": visible_text(hit.description, 500),
                "review_prompt": visible_text(hit.review_prompt, 500),
                "category": "secrets",
                "severity_hint": hit.severity_hint,
                "confidence_hint": hit.confidence_hint,
                "status": "needs-review",
                "source": "history-scan",
                "fingerprint": fingerprint("history", hit.format_id, hit.path),
            }
        )
    return {
        "project": {},
        "scope": {
            "mode": "history",
            "window_months": window_months,
            "all_refs": all_refs,
        },
        "history_hits": results,
        "history_hits_count": len(results),
        "only_in_history_count": sum(1 for item in results if item.get("only_in_history")),
        "warnings": warnings[:100],
        "candidates": [],
    }


def _working_tree_paths(root: Path) -> set[str]:
    import os

    paths: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in HISTORY_SKIP_PARTS]
        for filename in filenames:
            paths.add(str((Path(dirpath) / filename).relative_to(root)).replace("\\", "/"))
    return paths
