from __future__ import annotations

import hashlib
import os
import sys

import pytest
import torch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import ai.scoring as scoring
from ai.scoring import build_reference_index, get_reference_index, score_html

PHISH_BASE = "verify your account now urgent password suspended confirm identity restore access security alert login update billing"
BENIGN_BASE = "welcome to our recipe blog where we share dinner ideas garden tips travel notes and hiking photos"
PHISH_TEXT = " ".join([PHISH_BASE] * 3)
BENIGN_TEXT = " ".join([BENIGN_BASE] * 3)


def fake_encode(texts, dim=256):
    """Deterministic stand-in for MiniLM: hashed bag of words, unit length. No model download."""
    if not texts:
        return []
    if isinstance(texts, str):
        texts = [texts]
    vectors = torch.zeros(len(texts), dim)
    for row, text in enumerate(texts):
        for word in text.lower().split():
            vectors[row, int(hashlib.md5(word.encode()).hexdigest(), 16) % dim] += 1.0
    return vectors / vectors.norm(dim=1, keepdim=True).clamp(min=1e-9)


def page(body, title="Page"):
    return f"<html><head><title>{title}</title></head><body><main><p>{body}</p></main></body></html>"


@pytest.fixture(autouse=True)
def fake_pipeline(monkeypatch):
    monkeypatch.setattr(scoring, "encode_texts", fake_encode)
    monkeypatch.setattr(scoring, "detect_language", lambda text: "en")
    monkeypatch.setattr(scoring, "detect_language_with_confidence", lambda text: ("en", 0.99))
    scoring._INDEX_CACHE.clear()
    yield
    scoring._INDEX_CACHE.clear()


@pytest.fixture
def index():
    return build_reference_index([BENIGN_TEXT], [PHISH_TEXT])


def test_phishing_like_page_is_flagged(index):
    result = score_html(page(PHISH_TEXT), index)
    assert result["status"] == "ok"
    assert result["verdict"] == "fake"
    assert result["margin"] > result["threshold"]
    assert result["reference_pages"] == {"benign": 1, "phishing": 1}


def test_benign_page_is_not_flagged(index):
    result = score_html(page(BENIGN_TEXT), index)
    assert result["status"] == "ok"
    assert result["verdict"] == "real"
    assert result["margin"] < 0


def test_short_page_is_not_scored(index):
    result = score_html(page("too short to judge"), index)
    assert (result["status"], result["verdict"], result["reason"]) == ("skipped", "unknown", "short_text")
    assert result["margin"] is None


@pytest.mark.parametrize(
    "language, probability, reason",
    [("fr", 0.99, "non_english"), ("en", 0.5, "low_language_confidence")],
)
def test_language_gates(monkeypatch, index, language, probability, reason):
    monkeypatch.setattr(scoring, "detect_language_with_confidence", lambda text: (language, probability))
    result = score_html(page(PHISH_TEXT), index)
    assert result["reason"] == reason
    assert result["verdict"] == "unknown"


def test_quality_flags_block_scoring(index):
    parked = "this domain is for sale contact the owner for details about pricing and transfer of this web address today please inquire " * 2
    result = score_html(page(parked), index)
    assert result["reason"] == "flagged"
    assert "parked_domain" in result["flags"]
    assert result["verdict"] == "unknown"


def test_missing_references_are_reported_not_raised():
    result = score_html(page(PHISH_TEXT), None)
    assert (result["status"], result["reason"], result["verdict"]) == ("skipped", "no_references", "unknown")


def test_errors_never_escape(monkeypatch, index):
    def boom(html, charset=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(scoring, "extract_page", boom)
    result = score_html(page(PHISH_TEXT), index)
    assert result["status"] == "error"
    assert result["verdict"] == "unknown"
    assert "boom" in result["error"]


def test_bytes_and_text_give_the_same_answer(index):
    html = page(PHISH_TEXT)
    as_text = score_html(html, index)
    as_bytes = score_html(html.encode("utf-8"), index)
    assert as_text["verdict"] == as_bytes["verdict"]
    assert as_text["margin"] == as_bytes["margin"]


def test_reference_index_is_built_once(monkeypatch):
    calls = []

    def fake_loader(label, limit=None, split="train"):
        calls.append((label, split))
        return [BENIGN_TEXT] if label == "benign" else [PHISH_TEXT]

    monkeypatch.setattr(scoring, "load_reference_texts", fake_loader)
    first = get_reference_index()
    second = get_reference_index()
    assert first is second
    assert len(calls) == 2  # one load per class, not per call

    get_reference_index(refresh=True)
    assert len(calls) == 4


def test_reference_index_is_none_without_references(monkeypatch):
    monkeypatch.setattr(scoring, "load_reference_texts", lambda label, limit=None, split="train": [])
    assert get_reference_index() is None
