import hashlib
import random
from typing import Any, Dict, List, Optional
import math

from .scoring import (
    DEFAULT_SIMILARITY_THRESHOLD,
    UNKNOWN_MARGIN,
    compare_page_to_references,
    decide_similarity_verdict,
    score_text_against_references,
    decide_symmetric_verdict,
)


def assign_domain_split(domain: str, validation_ratio: float = 0.2, test_ratio: float = 0.2, salt: str = "security-scanner") -> str:
    normalized = (domain or "").strip().lower()
    if not normalized:
        return "train"

    bucket = int(hashlib.sha256(f"{salt}:{normalized}".encode("utf-8")).hexdigest(), 16) / float(1 << 256)
    if bucket < validation_ratio:
        return "validation"
    if bucket < validation_ratio + test_ratio:
        return "test"
    return "train"


def split_reference_texts(texts: List[str], validation_ratio: float = 0.2, seed: int = 0):
    if not texts:
        return [], []

    if not 0 < validation_ratio < 1:
        raise ValueError("validation_ratio must be between 0 and 1")

    rng = random.Random(seed)
    shuffled = list(texts)
    rng.shuffle(shuffled)

    validation_count = max(1, int(round(len(shuffled) * validation_ratio)))
    validation_count = min(validation_count, len(shuffled) - 1)

    validation = shuffled[:validation_count]
    train = shuffled[validation_count:]
    return train, validation


def split_labeled_examples(
    examples: List[Dict[str, Any]],
    validation_ratio: float = 0.2,
    test_ratio: float = 0.2,
    seed: int = 0,
):
    if not examples:
        return [], [], []

    if validation_ratio + test_ratio >= 1:
        raise ValueError("validation_ratio + test_ratio must be less than 1")

    rng = random.Random(seed)
    shuffled = list(examples)
    rng.shuffle(shuffled)

    total = len(shuffled)
    validation_count = int(round(total * validation_ratio))
    test_count = int(round(total * test_ratio))

    if validation_count == 0 and total > 1:
        validation_count = 1
    if test_count == 0 and total > 2:
        test_count = 1

    if total - validation_count - test_count <= 0:
        raise ValueError("Not enough examples to create non-empty train, validation, and test sets")

    validation = shuffled[:validation_count]
    test = shuffled[validation_count : validation_count + test_count]
    train = shuffled[validation_count + test_count :]

    return train, validation, test


def normalize_label_value(label_value):
    if isinstance(label_value, str):
        normalized = label_value.strip().lower()
        if normalized in {"fake", "phishing", "phish", "malicious"}:
            return 1
        if normalized in {"real", "benign", "safe", "legitimate"}:
            return 0
        raise ValueError(f"Unsupported string label: {label_value}")

    if label_value in {0, 1}:
        return int(label_value)

    raise ValueError(f"Unsupported label value: {label_value}")


def evaluate_binary_predictions(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have the same length")

    answered = [(t, p) for t, p in zip(y_true, y_pred) if p is not None]
    answered_count = len(answered)
    total = len(y_true)
    abstentions = total - answered_count

    if not answered:
        return {
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
            "coverage": 0.0,
            "answered_count": 0,
            "abstentions": abstentions,
        }

    tp = sum(1 for t, p in answered if t == 1 and p == 1)
    fp = sum(1 for t, p in answered if t == 0 and p == 1)
    tn = sum(1 for t, p in answered if t == 0 and p == 0)
    fn = sum(1 for t, p in answered if t == 1 and p == 0)

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
        "coverage": answered_count / total if total else 0.0,
        "answered_count": answered_count,
        "abstentions": abstentions,
    }


def tune_similarity_threshold(
    validation_examples: List[Dict[str, Any]],
    real_reference_texts: List[str],
    fake_reference_texts: List[str],
    thresholds: Optional[List[float]] = None,
    unknown_margin: float = UNKNOWN_MARGIN,
):
    if not validation_examples:
        return DEFAULT_SIMILARITY_THRESHOLD

    from .scoring import score_text_against_references

    scored = []
    for example in validation_examples:
        label = normalize_label_value(example["label"])
        score_result = score_text_against_references(example["text"], real_reference_texts, fake_reference_texts)
        if score_result.get("reason"):
            scored.append({
                "label": label,
                "fake_score": 0.0,
                "real_score": 0.0,
                "margin": 0.0,
                "verdict": "unknown",
            })
            continue

        fake_score = score_result["fake_score"]
        real_score = score_result["real_score"]
        margin = fake_score - real_score
        verdict = "unknown" if abs(margin) <= unknown_margin else ("fake" if margin > 0 else "real")
        scored.append({
            "label": label,
            "fake_score": fake_score,
            "real_score": real_score,
            "margin": margin,
            "verdict": verdict,
        })

    candidate_thresholds = thresholds or [0.02, 0.03, 0.04, 0.05, 0.08, 0.1]
    candidate_thresholds = sorted(set(float(th) for th in candidate_thresholds if th >= 0.0))

    best_threshold = DEFAULT_SIMILARITY_THRESHOLD
    best_metrics = None

    for threshold in candidate_thresholds:
        predictions = []
        labels = []

        for item in scored:
            if item["verdict"] == "unknown":
                predictions.append(None)
            else:
                prediction = 1 if item["margin"] > threshold else 0
                predictions.append(prediction)
            labels.append(item["label"])

        metrics = evaluate_binary_predictions(labels, predictions)
        if best_metrics is None or metrics["f1"] > best_metrics["f1"]:
            best_threshold = threshold
            best_metrics = metrics

    return best_threshold


def evaluate_threshold_on_examples(
    examples: List[Dict[str, Any]],
    threshold: float,
    real_reference_texts: List[str],
    fake_reference_texts: List[str],
    unknown_margin: float = UNKNOWN_MARGIN,
):
    if not examples:
        return {
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
            "coverage": 0.0,
            "answered_count": 0,
            "abstentions": 0,
        }

    labels = []
    predictions = []

    for example in examples:
        text = example["text"]
        label = normalize_label_value(example["label"])
        result = compare_page_to_references(
            text,
            real_reference_texts,
            fake_reference_texts,
            threshold=threshold,
        )
        prediction = None if result["verdict"] == "unknown" else (1 if result["verdict"] == "fake" else 0)
        labels.append(label)
        predictions.append(prediction)

    return evaluate_binary_predictions(labels, predictions)

def score_examples(examples: List[Dict[str, Any]], index, exclude_self: bool = True) -> List[Dict[str, Any]]:
    """Score every example once against a prebuilt reference index. The rows serve any dead zone."""
    rows = []
    for example in examples:
        scored = score_text_against_references(example["text"], index=index, exclude_self=exclude_self)
        rows.append(
            {
                "label": normalize_label_value(example["label"]),
                "text_hash": example.get("text_hash"),
                "domain": example.get("domain"),
                "word_count": example.get("word_count", len(example["text"].split())),
                "real_score": scored["real_score"],
                "fake_score": scored["fake_score"],
                "max_similarity": scored.get("max_similarity"),
                "reason": scored.get("reason"),
            }
        )
    return rows


def predictions_at(rows: List[Dict[str, Any]], dead_zone: float):
    """Apply the production decision rule to cached scores. Returns (labels, predictions); None means abstain."""
    labels, predictions = [], []
    for row in rows:
        labels.append(row["label"])
        if row["reason"]:
            predictions.append(None)
            continue
        verdict = decide_symmetric_verdict(row["fake_score"], row["real_score"], dead_zone=dead_zone)["verdict"]
        predictions.append(None if verdict == "unknown" else (1 if verdict == "fake" else 0))
    return labels, predictions

MAX_FALSE_POSITIVE_RATE = 0.05
MIN_COVERAGE = 0.70
DEFAULT_DEAD_ZONES = [round(i * 0.005, 3) for i in range(17)]  # 0.0 to 0.08


def summarize(labels: List[int], predictions: List[Optional[int]]) -> Dict[str, Any]:
    """Counts and rates. A prediction of None means the system abstained."""
    tp = sum(1 for t, p in zip(labels, predictions) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(labels, predictions) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(labels, predictions) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(labels, predictions) if t == 1 and p == 0)
    n_pos = sum(1 for t in labels if t == 1)
    n_neg = len(labels) - n_pos
    answered_pos = tp + fn
    answered_neg = fp + tn
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "n_pos": n_pos, "n_neg": n_neg,
        "coverage": (answered_pos + answered_neg) / len(labels) if labels else 0.0,
        "coverage_pos": answered_pos / n_pos if n_pos else 0.0,
        "coverage_neg": answered_neg / n_neg if n_neg else 0.0,
        "precision": tp / (tp + fp) if (tp + fp) else None,
        "recall_answered": tp / answered_pos if answered_pos else None,
        "recall_all": tp / n_pos if n_pos else 0.0,  # abstained phishing pages count as missed
        "fpr_answered": fp / answered_neg if answered_neg else None,
    }


def reason_counts(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in rows:
        key = row["reason"] or "scored"
        counts[key] = counts.get(key, 0) + 1
    return counts


def _require_both_classes(rows: List[Dict[str, Any]]) -> None:
    labels = {row["label"] for row in rows}
    if 1 not in labels or 0 not in labels:
        raise ValueError("need at least one phishing and one benign row to tune")


def sweep_dead_zones(rows: List[Dict[str, Any]], dead_zones: Optional[List[float]] = None) -> List[Dict[str, Any]]:
    """One table entry per dead zone, all computed from the cached scores through the production rule."""
    _require_both_classes(rows)
    table = []
    for dead_zone in dead_zones or DEFAULT_DEAD_ZONES:
        labels, predictions = predictions_at(rows, dead_zone)
        entry = summarize(labels, predictions)
        entry["dead_zone"] = dead_zone
        table.append(entry)
    return table


def choose_dead_zone(table, max_fpr: float = MAX_FALSE_POSITIVE_RATE, min_coverage: float = MIN_COVERAGE):
    """Highest recall among feasible entries, ties to higher coverage. Returns None when nothing qualifies."""
    feasible = [
        e for e in table
        if e["fpr_answered"] is not None and e["fpr_answered"] <= max_fpr and e["coverage"] >= min_coverage
    ]
    if not feasible:
        return None
    return max(feasible, key=lambda e: (e["recall_all"], e["coverage"]))


def wordcount_table(rows: List[Dict[str, Any]], cutoffs: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """Baseline: predict phishing when a page has fewer words than the cutoff. It never abstains."""
    _require_both_classes(rows)
    if cutoffs is None:
        cutoffs = [0] + [count + 1 for count in sorted({row["word_count"] for row in rows})]
    labels = [row["label"] for row in rows]
    table = []
    for cutoff in cutoffs:
        predictions = [1 if row["word_count"] < cutoff else 0 for row in rows]
        entry = summarize(labels, predictions)
        entry["cutoff"] = cutoff
        table.append(entry)
    return table


def choose_wordcount_cutoff(table, max_fpr: float = MAX_FALSE_POSITIVE_RATE):
    """Highest recall within the same false-positive limit. Ties go to the smaller cutoff."""
    feasible = [e for e in table if e["fpr_answered"] is not None and e["fpr_answered"] <= max_fpr]
    return max(feasible, key=lambda e: e["recall_all"]) if feasible else None


def near_duplicates(rows: List[Dict[str, Any]], cutoff: float = 0.98) -> List[Dict[str, Any]]:
    """Pages whose best chunk similarity to a reference is at or above the cutoff (kit clones, leakage)."""
    return [
        {"text_hash": r["text_hash"], "domain": r["domain"], "label": r["label"], "max_similarity": r["max_similarity"]}
        for r in rows
        if r["max_similarity"] is not None and r["max_similarity"] >= cutoff
    ]


DEFAULT_THRESHOLDS = [round(-0.1 + i * 0.005, 3) for i in range(81)]  # -0.1 to 0.3


def wilson_interval(successes: int, n: int, z: float = 1.96):
    """95% Wilson score interval for a proportion. None when n is 0."""
    if n == 0:
        return None
    p = successes / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return max(0.0, centre - half), min(1.0, centre + half)


def predictions_onesided(rows: List[Dict[str, Any]], threshold: float):
    """fake if margin > threshold, otherwise real. None only for pages the scorer could not read."""
    labels, predictions = [], []
    for row in rows:
        labels.append(row["label"])
        if row["reason"]:
            predictions.append(None)
        else:
            verdict = decide_similarity_verdict(row["fake_score"], row["real_score"], threshold=threshold)["verdict"]
            predictions.append(1 if verdict == "fake" else 0)
    return labels, predictions


def sweep_thresholds(rows: List[Dict[str, Any]], thresholds: Optional[List[float]] = None) -> List[Dict[str, Any]]:
    _require_both_classes(rows)
    table = []
    for threshold in thresholds or DEFAULT_THRESHOLDS:
        labels, predictions = predictions_onesided(rows, threshold)
        entry = summarize(labels, predictions)
        entry["threshold"] = threshold
        table.append(entry)
    return table