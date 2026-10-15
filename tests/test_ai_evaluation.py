from __future__ import annotations

import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ai.evaluation import evaluate_binary_predictions
from ai.scoring import (
    compare_page_to_references,
    decide_similarity_verdict,
    decide_symmetric_verdict,
)


REFERENCE_BENIGN = [
    "This is a secure online banking portal for customer account access and payment management.",
    "Welcome to our official company website with product information, contact details, and customer support.",
    "We provide secure cloud services, account login, and privacy controls for our users.",
    "Your online shopping experience includes secure checkout, order status, and customer support pages.",
]

REFERENCE_PHISHING = [
    "Urgent security alert: your account has been suspended. Verify your identity now to restore access.",
    "Your payment method is expired. Login immediately to prevent account closure and resume service.",
    "Action required: secure your account by confirming your password and updating your login details.",
    "Confirm your identity now to avoid account lockout and fraudulent activity on your profile.",
]


def test_decide_similarity_verdict_is_one_sided_at_the_threshold():
    # Exact binary fractions, so float rounding cannot move the boundary.
    assert decide_similarity_verdict(0.75, 0.5, threshold=0.25)["verdict"] == "real"   # margin 0.25 is not above 0.25
    assert decide_similarity_verdict(0.75, 0.5, threshold=0.125)["verdict"] == "fake"
    assert decide_similarity_verdict(0.5, 0.75, threshold=0.125)["verdict"] == "real"
    assert decide_similarity_verdict(0.5, 0.5)["verdict"] == "real"  # no abstention for margins

    result = decide_similarity_verdict(0.75, 0.5, threshold=0.125)
    assert result["rule"] == "onesided"
    assert result["threshold"] == 0.125
    assert result["margin"] == 0.25


def test_decide_symmetric_verdict_keeps_three_way_behaviour():
    assert decide_symmetric_verdict(0.50, 0.50)["verdict"] == "unknown"
    assert decide_symmetric_verdict(0.40, 0.60)["verdict"] == "real"
    assert decide_symmetric_verdict(0.60, 0.40)["verdict"] == "fake"
    assert decide_symmetric_verdict(0.75, 0.5, dead_zone=0.25)["verdict"] == "unknown"  # the edge abstains


def test_predictions_onesided_uses_the_production_rule():
    from ai.evaluation import predictions_onesided

    rows = [
        {"label": 1, "fake_score": 0.75, "real_score": 0.5, "reason": None},
        {"label": 0, "fake_score": 0.5, "real_score": 0.75, "reason": None},
        {"label": 0, "fake_score": 0.75, "real_score": 0.5, "reason": "short_text"},
    ]
    labels, predictions = predictions_onesided(rows, 0.125)
    assert labels == [1, 0, 0]
    assert predictions == [1, 0, None]  # unreadable pages abstain, everything else gets an answer


def test_compare_page_to_references_rejects_non_english_texts():
    result = compare_page_to_references(
        "Alerta urgente: verifique su cuenta ahora para evitar el cierre del acceso.",
        REFERENCE_BENIGN,
        REFERENCE_PHISHING,
    )
    assert result["verdict"] == "unknown"


def test_evaluate_binary_predictions_excludes_abstentions_and_reports_coverage():
    metrics = evaluate_binary_predictions([1, 0, 1], [1, None, 1])
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["coverage"] == 2 / 3
    assert metrics["answered_count"] == 2
    assert metrics["abstentions"] == 1


def test_compare_page_to_references_detects_real_and_fake_examples():
    real_result = compare_page_to_references(
        "We provide secure online banking with account login and transaction monitoring.",
        REFERENCE_BENIGN,
        REFERENCE_PHISHING,
    )
    fake_result = compare_page_to_references(
        "Urgent security alert: your account has been suspended. Verify your credentials to continue.",
        REFERENCE_BENIGN,
        REFERENCE_PHISHING,
    )

    assert real_result["verdict"] == "real"
    assert fake_result["verdict"] == "fake"


def test_compare_page_to_references_returns_unknown_for_short_text():
    result = compare_page_to_references("Hello world", REFERENCE_BENIGN, REFERENCE_PHISHING)
    assert result["verdict"] == "unknown"
