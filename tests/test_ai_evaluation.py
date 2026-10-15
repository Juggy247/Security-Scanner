from __future__ import annotations

import os
import sys
from functools import lru_cache
from typing import Dict, List

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ai.evaluation import evaluate_binary_predictions
from ai.scoring import (
    compare_page_to_references,
    decide_similarity_verdict,
    decide_symmetric_verdict,
    model,
    util,
)
from ai.text_processing import chunk_text


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

TEST_CASES = [
    {"text": "We provide secure online banking with account login and transaction monitoring.", "label": 0, "category": "benign"},
    {"text": "Our website offers customer support, product information, and secure account management.", "label": 0, "category": "benign"},
    {"text": "Urgent security alert: your account has been suspended. Verify your credentials to continue.", "label": 1, "category": "phishing"},
    {"text": "Login required to restore access. Confirm your payment details before account closure.", "label": 1, "category": "phishing"},
    {"text": "This page is a legitimate login portal for our online banking and customer dashboard.", "label": 0, "category": "legitimate_login"},
    {"text": "To avoid suspension, verify your account immediately to restore secure access now.", "label": 1, "category": "phishing_copying_legitimate"},
    {"text": "Hello world", "label": 0, "category": "short_text"},
    {"text": "Este sitio ofrece servicios seguros y acceso a la cuenta del cliente con autenticación.", "label": 0, "category": "multilingual_benign"},
    {"text": "Alerta urgente: verifique su cuenta ahora para evitar el cierre del acceso.", "label": 1, "category": "multilingual_phishing"},
    {"text": "Verify", "label": 0, "category": "very_short_text"},
]


@lru_cache(maxsize=1)
def get_reference_cache():
    real_vecs = model.encode(REFERENCE_BENIGN, convert_to_tensor=True, normalize_embeddings=True)
    fake_vecs = model.encode(REFERENCE_PHISHING, convert_to_tensor=True, normalize_embeddings=True)
    return real_vecs, fake_vecs


def predict_max_similarity(text: str) -> int:
    result = compare_page_to_references(text, REFERENCE_BENIGN, REFERENCE_PHISHING)
    if result["verdict"] == "fake":
        return 1
    return 0


def predict_mean_similarity(text: str) -> int:
    candidate_vec = model.encode(text, convert_to_tensor=True, normalize_embeddings=True)
    real_vecs, fake_vecs = get_reference_cache()

    real_scores = util.cos_sim(candidate_vec, real_vecs)[0]
    fake_scores = util.cos_sim(candidate_vec, fake_vecs)[0]

    real_mean = float(real_scores.mean())
    fake_mean = float(fake_scores.mean())
    return 1 if fake_mean > real_mean else 0


def predict_threshold(text: str, threshold: float = 0.02) -> int:
    result = compare_page_to_references(text, REFERENCE_BENIGN, REFERENCE_PHISHING)
    if result["verdict"] == "unknown":
        return 0
    return 1 if result["verdict"] == "fake" else 0


def decision_from_delta(delta: float, threshold: float = 0.02) -> int:
    return 1 if delta > threshold else 0


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


def evaluate_predictions(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have the same length")

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0
    false_negative_rate = fn / (fn + tp) if (fn + tp) else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
    }


def test_evaluate_binary_predictions_excludes_abstentions_and_reports_coverage():
    metrics = evaluate_binary_predictions([1, 0, 1], [1, None, 1])
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["coverage"] == 2 / 3
    assert metrics["answered_count"] == 2
    assert metrics["abstentions"] == 1


def run_evaluation() -> Dict[str, Dict[str, float]]:
    methods = {
        "max_similarity": predict_max_similarity,
        "mean_similarity": predict_mean_similarity,
        "thresholded": lambda text: predict_threshold(text, threshold=0.02),
    }

    results: Dict[str, Dict[str, float]] = {}

    for method_name, predictor in methods.items():
        labels = [item["label"] for item in TEST_CASES]
        predictions = [predictor(item["text"]) for item in TEST_CASES]
        results[method_name] = evaluate_predictions(labels, predictions)

    return results


def run_category_breakdown(method_name: str | None = "max_similarity") -> Dict[str, Dict[str, float]]:
    methods = {
        "max_similarity": predict_max_similarity,
        "mean_similarity": predict_mean_similarity,
        "thresholded": lambda text: predict_threshold(text, threshold=0.02),
    }

    selected_methods = methods if method_name is None else {method_name: methods[method_name]}

    grouped = {
        "overall": TEST_CASES,
        "legitimate_login": [case for case in TEST_CASES if case["category"] == "legitimate_login"],
        "short_text": [case for case in TEST_CASES if case["category"] in {"short_text", "very_short_text"}],
        "multilingual": [case for case in TEST_CASES if "multilingual" in case["category"]],
        "phishing_copying_legitimate": [case for case in TEST_CASES if case["category"] == "phishing_copying_legitimate"],
    }

    results: Dict[str, Dict[str, float]] = {}
    for method_key, predictor in selected_methods.items():
        for category_name, cases in grouped.items():
            labels = [case["label"] for case in cases]
            predictions = [predictor(case["text"]) for case in cases]
            results[f"{method_key}:{category_name}"] = evaluate_predictions(labels, predictions)
    return results


def test_reference_sets_are_separate():
    overlap = set(REFERENCE_BENIGN) & set(REFERENCE_PHISHING)
    assert not overlap


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


def test_chunk_text_splits_long_inputs():
    text = " ".join([f"word{i}" for i in range(1, 251)])
    chunks = chunk_text(text, chunk_size=50, overlap=10)
    assert len(chunks) >= 2
    assert all(len(chunk.split()) <= 50 for chunk in chunks)


def test_compare_page_to_references_returns_unknown_for_short_text():
    result = compare_page_to_references("Hello world", REFERENCE_BENIGN, REFERENCE_PHISHING)
    assert result["verdict"] == "unknown"


def test_threshold_boundary_behaviour():
    assert decision_from_delta(-0.01, threshold=0.02) == 0
    assert decision_from_delta(0.02, threshold=0.02) == 0
    assert decision_from_delta(0.03, threshold=0.02) == 1

    phishing_text = "Urgent security alert: your account has been suspended. Verify your credentials to continue."
    benign_text = "We provide secure online banking with account login and transaction monitoring."

    assert predict_threshold(phishing_text, threshold=0.02) == 1
    assert predict_threshold(benign_text, threshold=0.02) == 0


def test_eval_has_expected_keys():
    metrics = evaluate_predictions([1, 0, 1], [1, 0, 0])
    assert set(metrics) == {
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "false_negative_rate",
    }


def test_evaluate_predictions_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        evaluate_predictions([1, 0, 1], [1, 0])


def test_current_pipeline_evaluation_runs():
    results = run_evaluation()
    assert set(results) == {"max_similarity", "mean_similarity", "thresholded"}
    for metrics in results.values():
        for key in ["precision", "recall", "f1", "false_positive_rate", "false_negative_rate"]:
            assert 0.0 <= metrics[key] <= 1.0


def test_category_breakdown_is_reported():
    breakdown = run_category_breakdown(method_name=None)
    keys = set(breakdown)
    assert "max_similarity:overall" in keys
    assert "mean_similarity:short_text" in keys
    assert "thresholded:multilingual" in keys
    for metrics in breakdown.values():
        assert set(metrics) == {"precision", "recall", "f1", "false_positive_rate", "false_negative_rate"}


if __name__ == "__main__":
    for name, metrics in run_evaluation().items():
        print(f"{name}: {metrics}")
    print("category_breakdown:", run_category_breakdown())
