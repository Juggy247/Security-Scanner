from __future__ import annotations

import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ai.evaluation import (
    choose_dead_zone,
    choose_wordcount_cutoff,
    evaluate_binary_predictions,
    near_duplicates,
    normalize_label_value,
    summarize,
    sweep_thresholds,
    wilson_interval,
    wordcount_table,
)
from ai.text_processing import chunk_text


def test_evaluate_binary_predictions_exact_counts():
    #            tp  tp  fn  fp  tn  tn  abstain  abstain
    y_true = [1, 1, 1, 0, 0, 0, 0, 1]
    y_pred = [1, 1, 0, 1, 0, 0, None, None]
    m = evaluate_binary_predictions(y_true, y_pred)
    assert m["precision"] == pytest.approx(2 / 3)
    assert m["recall"] == pytest.approx(2 / 3)
    assert m["f1"] == pytest.approx(2 / 3)
    assert m["false_positive_rate"] == pytest.approx(1 / 3)
    assert m["false_negative_rate"] == pytest.approx(1 / 3)
    assert m["coverage"] == 0.75
    assert m["answered_count"] == 6
    assert m["abstentions"] == 2


def test_evaluate_binary_predictions_when_everything_abstains():
    m = evaluate_binary_predictions([1, 0], [None, None])
    assert m["coverage"] == 0.0
    assert m["answered_count"] == 0
    assert m["abstentions"] == 2
    assert m["precision"] == 0.0 and m["recall"] == 0.0


def test_evaluate_binary_predictions_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        evaluate_binary_predictions([1, 0, 1], [1, 0])


def test_normalize_label_value_accepts_known_labels():
    assert [normalize_label_value(v) for v in ("phishing", " FAKE ", "phish", "malicious")] == [1, 1, 1, 1]
    assert [normalize_label_value(v) for v in ("benign", "Real", "safe", "legitimate")] == [0, 0, 0, 0]
    assert normalize_label_value(0) == 0 and normalize_label_value(1) == 1


def test_normalize_label_value_rejects_unknown():
    for bad in ("unknown", "", "maybe", 2, None):
        with pytest.raises(ValueError):
            normalize_label_value(bad)


def test_summarize_counts_abstained_phishing_as_missed():
    labels = [1, 1, 0, 0]
    predictions = [1, None, 0, 1]
    s = summarize(labels, predictions)
    assert (s["tp"], s["fp"], s["tn"], s["fn"]) == (1, 1, 1, 0)
    assert s["coverage"] == 0.75
    assert s["coverage_pos"] == 0.5 and s["coverage_neg"] == 1.0
    assert s["recall_answered"] == 1.0
    assert s["recall_all"] == 0.5          # the abstained phishing page counts as missed
    assert s["fpr_answered"] == 0.5
    assert s["precision"] == 0.5


def test_wilson_interval_matches_known_values():
    known = {
        (5, 100): (0.02154336145631356, 0.11175196527208817),
        (65, 100): (0.5525426042919797, 0.7363589534652197),
        (19, 20): (0.7638641064874331, 0.9911187805671268),
    }
    for (k, n), (low, high) in known.items():
        got_low, got_high = wilson_interval(k, n)
        assert got_low == pytest.approx(low, abs=1e-9)
        assert got_high == pytest.approx(high, abs=1e-9)


def test_wilson_interval_edges():
    assert wilson_interval(0, 0) is None
    low, high = wilson_interval(0, 100)
    assert low == pytest.approx(0.0, abs=1e-12)
    assert high == pytest.approx(0.03699480747600191, abs=1e-9)
    low, high = wilson_interval(100, 100)
    assert high == pytest.approx(1.0, abs=1e-12) and low < 1.0
    narrow, wide = wilson_interval(10, 100), wilson_interval(5, 50)
    assert (wide[1] - wide[0]) > (narrow[1] - narrow[0])   # same rate, less data, wider interval


def test_near_duplicates_includes_the_cutoff():
    rows = [
        {"text_hash": "a", "domain": "x.test", "label": 1, "max_similarity": 0.99},
        {"text_hash": "b", "domain": "y.test", "label": 0, "max_similarity": 0.98},
        {"text_hash": "c", "domain": "z.test", "label": 0, "max_similarity": 0.97},
        {"text_hash": "d", "domain": "w.test", "label": 1, "max_similarity": None},
    ]
    assert [r["text_hash"] for r in near_duplicates(rows)] == ["a", "b"]   # exactly 0.98 counts
    assert [r["text_hash"] for r in near_duplicates(rows, cutoff=0.985)] == ["a"]


def test_sweep_thresholds_exact_counts_and_unreadable_pages():
    rows = [
        {"label": 1, "fake_score": 0.75, "real_score": 0.25, "reason": None},    # margin 0.5
        {"label": 1, "fake_score": 0.5, "real_score": 0.25, "reason": None},     # 0.25
        {"label": 0, "fake_score": 0.5, "real_score": 0.5, "reason": None},      # 0.0
        {"label": 0, "fake_score": 0.25, "real_score": 0.5, "reason": None},     # -0.25
        {"label": 0, "fake_score": 0.625, "real_score": 0.5, "reason": None},    # 0.125
    ]
    table = sweep_thresholds(rows, [0.0, 0.125, 0.375])
    assert [(e["tp"], e["fp"], e["tn"], e["fn"]) for e in table] == [(2, 1, 2, 0), (2, 0, 3, 0), (1, 0, 3, 1)]
    assert [e["threshold"] for e in table] == [0.0, 0.125, 0.375]
    assert all(e["coverage"] == 1.0 for e in table)   # readable pages always get an answer
    assert table[2]["recall_all"] == 0.5

    unreadable = rows + [{"label": 1, "fake_score": 0.0, "real_score": 0.0, "reason": "short_text"}]
    entry = sweep_thresholds(unreadable, [0.125])[0]
    assert entry["coverage"] == pytest.approx(5 / 6)
    assert entry["recall_all"] == pytest.approx(2 / 3)   # the unreadable phishing page counts as missed


def test_sweep_requires_both_classes():
    only_phishing = [{"label": 1, "fake_score": 0.5, "real_score": 0.25, "reason": None}]
    only_benign = [{"label": 0, "fake_score": 0.5, "real_score": 0.25, "reason": None}]
    for rows in (only_phishing, only_benign):
        with pytest.raises(ValueError):
            sweep_thresholds(rows)


def test_choose_dead_zone_picks_best_feasible_and_never_invents_one():
    def entry(dead_zone, fpr, coverage, recall):
        return {"dead_zone": dead_zone, "fpr_answered": fpr, "coverage": coverage, "recall_all": recall}

    table = [
        entry(0.00, 0.30, 1.00, 0.90),   # false-positive rate too high
        entry(0.05, 0.05, 0.80, 0.60),   # feasible, exactly at the limit
        entry(0.06, 0.04, 0.75, 0.60),   # feasible, same recall, lower coverage
        entry(0.08, 0.00, 0.50, 0.50),   # coverage too low
        entry(0.09, None, 0.90, 0.90),   # no answered benign pages: not feasible
    ]
    assert choose_dead_zone(table)["dead_zone"] == 0.05
    assert choose_dead_zone(table[:1]) is None
    assert choose_dead_zone([]) is None


def test_choose_wordcount_cutoff_respects_the_false_positive_limit():
    rows = [{"label": 1, "word_count": w} for w in (10, 20, 30, 500)]
    rows += [{"label": 0, "word_count": w} for w in (40, 60, 80, 600, 700)]
    chosen = choose_wordcount_cutoff(wordcount_table(rows))
    # cutoff 31 catches the three short phishing pages with no benign page below it.
    # cutoff 41 would also flag the 40-word benign page (1 of 5 = 0.2 > 0.05), so it is not feasible.
    assert chosen["cutoff"] == 31
    assert (chosen["tp"], chosen["fp"]) == (3, 0)
    assert chosen["recall_all"] == 0.75


def test_chunk_text_windows_are_exact():
    text = " ".join(f"word{i}" for i in range(1, 251))
    chunks = chunk_text(text, chunk_size=50, overlap=10)
    assert len(chunks) == 6
    assert [c.split()[0] for c in chunks] == ["word1", "word41", "word81", "word121", "word161", "word201"]
    assert all(len(c.split()) == 50 for c in chunks)
    assert chunks[-1].split()[-1] == "word250"
    assert chunks[0].split()[-10:] == chunks[1].split()[:10]   # consecutive chunks overlap by 10 words


def test_chunk_text_defaults_and_edges():
    text = " ".join(f"word{i}" for i in range(1, 401))
    chunks = chunk_text(text)
    assert len(chunks) == 3
    assert len(chunks[0].split()) == 180
    assert chunks[1].split()[0] == "word151"            # step = 180 - 30 = 150
    assert len(chunks[2].split()) == 100 and chunks[2].split()[-1] == "word400"

    assert chunk_text("a   b\n c") == ["a b c"]
    assert chunk_text("") == [] and chunk_text("   ") == []
    assert len(chunk_text(" ".join(["w"] * 180))) == 1      # exactly one full window
    assert len(chunk_text(" ".join(["w"] * 181))) == 2
