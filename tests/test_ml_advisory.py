from __future__ import annotations

import json
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import ai.scoring as ai_scoring
from scanner.ml_advisory import run_ml_advisory

PAGE = b"<html><body>page</body></html>"

FULL_RESULT = {
    "status": "ok", "verdict": "fake", "reason": "decided",
    "real_score": 0.123456789, "fake_score": 0.3456789, "margin": 0.2222222, "threshold": 0.1,
    "flags": [], "word_count": 120, "language": "en", "language_confidence": 0.9999,
    "model": "all-MiniLM-L6-v2", "reference_pages": {"benign": 100, "phishing": 101},
    "max_similarity": 0.8, "text_secret": "must not be copied",
}


@pytest.fixture
def scoring_calls(monkeypatch):
    calls = {}
    index = object()

    def fake_index():
        return index

    def fake_score(html, idx):
        calls["html"] = html
        calls["index"] = idx
        return dict(FULL_RESULT)

    monkeypatch.setattr(ai_scoring, "get_reference_index", fake_index)
    monkeypatch.setattr(ai_scoring, "score_html", fake_score)
    calls["expected_index"] = index
    return calls


def test_http_errors_are_skipped_without_scoring(scoring_calls):
    result = run_ml_advisory(PAGE, 404, "text/html")
    assert (result["status"], result["verdict"], result["reason"]) == ("skipped", "unknown", "http_error")
    assert "html" not in scoring_calls


def test_non_html_is_skipped(scoring_calls):
    result = run_ml_advisory(b"%PDF-1.7", 200, "application/pdf")
    assert (result["status"], result["reason"]) == ("skipped", "not_html")
    assert "html" not in scoring_calls


def test_empty_body_is_skipped(scoring_calls):
    result = run_ml_advisory(b"", 200, "text/html")
    assert result["reason"] == "empty_body"
    assert "html" not in scoring_calls


def test_ok_result_is_trimmed_rounded_and_json_safe(scoring_calls):
    result = run_ml_advisory(PAGE, 200, "text/html")
    assert result["status"] == "ok" and result["verdict"] == "fake"
    assert result["real_score"] == 0.1235
    assert result["margin"] == 0.2222
    assert result["reference_pages"] == {"benign": 100, "phishing": 101}
    assert "max_similarity" not in result and "text_secret" not in result
    assert scoring_calls["html"] == PAGE
    assert scoring_calls["index"] is scoring_calls["expected_index"]
    json.dumps(result)


@pytest.mark.parametrize("content_type", [None, "", "text/html; charset=utf-8", "application/xhtml+xml"])
def test_html_and_missing_content_types_are_scored(scoring_calls, content_type):
    result = run_ml_advisory(PAGE, 200, content_type)
    assert result["status"] == "ok"
    assert scoring_calls["html"] == PAGE


def test_scoring_failure_becomes_error(monkeypatch):
    def boom(html, idx):
        raise RuntimeError("boom")

    monkeypatch.setattr(ai_scoring, "get_reference_index", lambda: object())
    monkeypatch.setattr(ai_scoring, "score_html", boom)
    result = run_ml_advisory(PAGE, 200, "text/html")
    assert (result["status"], result["verdict"], result["reason"]) == ("error", "unknown", "error")
    assert "boom" in result["error"]


def test_index_failure_becomes_error(monkeypatch):
    def mongo_down():
        raise ConnectionError("mongo down")

    monkeypatch.setattr(ai_scoring, "get_reference_index", mongo_down)
    result = run_ml_advisory(PAGE, 200, "text/html")
    assert result["status"] == "error"
    assert "mongo down" in result["error"]