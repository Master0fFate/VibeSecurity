from __future__ import annotations

from pathlib import Path

from support import FIXTURES, TestFunc
from vibesecurity_secrets import (
    corpus_scores,
    entropy_hit,
    parse_formats,
    scan_text,
    secret_candidates,
    shannon_entropy,
)

CORPUS = FIXTURES / "secret-corpus"


def test_format_library_loads_and_compiles() -> None:
    formats, warnings = parse_formats()
    assert not warnings
    assert len(formats) >= 15
    ids = {item.format_id for item in formats}
    assert "aws-access-key-id" in ids
    assert "github-token" in ids
    assert "private-key-block" in ids


def test_corpus_recall_and_precision_meet_targets() -> None:
    positives = [line for line in (CORPUS / "positive-tokens.txt").read_text().splitlines() if line.strip() and not line.startswith("#")]
    # Stripe live keys keep the real 24-char shape only at runtime, so no
    # contiguous token exists in any committed file (push protection safe).
    stripe_live = "sk_" + "live_" + ("0123456789" + "abcdefghij")
    positives.append("stripe_key = " + stripe_live)
    negatives = [line for line in (CORPUS / "negative-benign.txt").read_text().splitlines() if line.strip() and not line.startswith("#")]
    scores = corpus_scores(positives, negatives)
    print(f"secret corpus scores: {scores}")
    assert scores["recall"] >= 0.9, f"recall below target: {scores}"
    assert scores["precision"] >= 0.9, f"precision below target: {scores}"


def test_entropy_layer_is_gated_on_secret_context() -> None:
    formats, _ = parse_formats()
    secret_context = "api_key = Ab3xY9qQ2mZ8kL5vN7rT1wE4uI6oP0aS"
    benign_context = "word = Ab3xY9qQ2mZ8kL5vN7rT1wE4uI6oP0aS"
    assert any(hit.kind == "entropy" for hit in scan_text(secret_context, formats))
    assert not any(hit.kind == "entropy" for hit in scan_text(benign_context, formats))


def test_entropy_thresholds_reject_low_entropy_tokens() -> None:
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") < 1.0
    assert not entropy_hit("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert not entropy_hit("abcdefghijklmnopqrstuvwx")  # too short


def test_secret_candidates_never_emit_values() -> None:
    token = "AKIAIOSFODNN7EXAMPLE"
    candidates = secret_candidates("config.py", "config.py", f"key = {token}\n")
    assert candidates
    rendered = repr(candidates)
    assert token not in rendered
    assert "value withheld" in rendered
    assert candidates[0]["fingerprint"]


def test_fingerprints_stable_across_line_shifts() -> None:
    one = secret_candidates("config.py", "config.py", "\n\n\nkey = AKIAIOSFODNN7EXAMPLE\n")
    two = secret_candidates("config.py", "config.py", "key = AKIAIOSFODNN7EXAMPLE\n")
    assert one[0]["fingerprint"] == two[0]["fingerprint"]


TESTS = [
    test_format_library_loads_and_compiles,
    test_corpus_recall_and_precision_meet_targets,
    test_entropy_layer_is_gated_on_secret_context,
    test_entropy_thresholds_reject_low_entropy_tokens,
    test_secret_candidates_never_emit_values,
    test_fingerprints_stable_across_line_shifts,
]
