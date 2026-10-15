from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from flask import Flask, render_template

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = os.path.join(PROJECT_ROOT, "templates")


@pytest.fixture
def app():
    return Flask(__name__, template_folder=TEMPLATES)


def render(app, ml):
    with app.test_request_context():
        return render_template("_ml_card.html", scan_report=SimpleNamespace(ml_analysis=ml))


FLAGGED = {"status": "ok", "verdict": "fake", "reason": "decided", "margin": 0.169, "threshold": 0.1,
           "word_count": 27, "reference_pages": {"benign": 100, "phishing": 101}}
NOT_FLAGGED = {**FLAGGED, "verdict": "real", "margin": -0.09}


def test_nothing_is_rendered_when_ml_is_off(app):
    assert render(app, None).strip() == ""


def test_flagged_wording_and_numbers(app):
    html = render(app, FLAGGED)
    assert "Flagged: text resembles known phishing pages" in html
    assert "0.169" in html and "0.10" in html
    assert "101 phishing and 100 benign" in html


def test_not_flagged_wording(app):
    html = render(app, NOT_FLAGGED)
    assert "Not flagged" in html
    assert "Flagged: text resembles" not in html


@pytest.mark.parametrize(
    "reason, text",
    [
        ("short_text", "too little text"),
        ("non_english", "not English"),
        ("low_language_confidence", "could not be identified"),
        ("http_error", "HTTP error"),
        ("not_html", "not an HTML page"),
        ("empty_body", "body was empty"),
        ("no_references", "no reference pages"),
        ("flagged", "parked-domain"),
    ],
)
def test_not_scored_reasons_are_explained(app, reason, text):
    html = render(app, {"status": "skipped", "verdict": "unknown", "reason": reason})
    assert "Not scored:" in html
    assert text in html


def test_error_status_shows_a_fixed_message_not_the_exception_text(app):
    html = render(app, {"status": "error", "verdict": "unknown", "reason": "error", "error": "RuntimeError: /secret/path"})
    assert "Not scored: the check failed" in html
    assert "/secret/path" not in html


def test_unknown_reason_falls_back(app):
    html = render(app, {"status": "skipped", "verdict": "unknown", "reason": "<b>surprise</b>"})
    assert "reason unavailable" in html
    assert "surprise" not in html


def test_quality_flags_are_escaped(app):
    ml = {"status": "skipped", "verdict": "unknown", "reason": "flagged", "flags": ["<script>alert(1)</script>"]}
    html = render(app, ml)
    assert "&lt;script&gt;" in html
    assert "<script>alert(1)" not in html


def test_missing_fields_do_not_crash(app):
    html = render(app, {"status": "ok", "verdict": "fake"})
    assert "Flagged: text resembles known phishing pages" in html


@pytest.mark.parametrize(
    "ml",
    [FLAGGED, NOT_FLAGGED, {"status": "skipped", "verdict": "unknown", "reason": "short_text"}],
    ids=["flagged", "not_flagged", "not_scored"],
)
def test_the_card_never_calls_a_page_safe(app, ml):
    html = render(app, ml).lower()
    assert "safe" not in html
    assert "legitimate" not in html
    assert "does not change the verdict above" in html