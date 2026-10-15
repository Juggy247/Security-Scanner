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
from ai.evaluation import (
    choose_dead_zone,
    choose_wordcount_cutoff,
    predictions_at,
    reason_counts,
    score_examples,
    sweep_dead_zones,
    wordcount_table,
)
from ai.scoring import build_reference_index

PHISH_A = " ".join(["verify your account now urgent password suspended confirm identity restore access security alert"] * 3)
PHISH_B = " ".join(["login update billing payment expired closure lockout verify account"] * 3)   # shares only 2 words with A
BENIGN = " ".join(["welcome to our recipe blog where we share dinner ideas garden tips travel notes and hiking photos"] * 3)


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


@pytest.fixture(autouse=True)
def fake_pipeline(monkeypatch):
    monkeypatch.setattr(scoring, "encode_texts", fake_encode)
    monkeypatch.setattr(scoring, "detect_language", lambda text: "en")


def test_a_stored_page_does_not_match_its_own_copy():
    index = build_reference_index([BENIGN], [PHISH_A, PHISH_B])
    example = {"text": PHISH_A, "label": "phishing"}

    with_self = score_examples([example], index, exclude_self=False)[0]
    without_self = score_examples([example], index, exclude_self=True)[0]
    by_default = score_examples([example], index)[0]

    assert with_self["fake_score"] == pytest.approx(1.0, abs=1e-5)       # it finds itself
    assert with_self["max_similarity"] == pytest.approx(1.0, abs=1e-5)
    assert without_self["fake_score"] < 0.6                              # only page B is left, and it is mostly different
    assert without_self["max_similarity"] < 0.6
    assert without_self["reason"] is None
    assert by_default["fake_score"] == without_self["fake_score"]        # excluding itself is the default


def test_page_that_is_the_only_reference_of_its_class_gets_no_references():
    index = build_reference_index([BENIGN], [PHISH_A])
    row = score_examples([{"text": PHISH_A, "label": "phishing"}], index)[0]
    assert row["reason"] == "no_references"
    assert (row["fake_score"], row["real_score"], row["max_similarity"]) == (0.0, 0.0, None)


def test_score_examples_row_fields_and_unreadable_pages():
    index = build_reference_index([BENIGN], [PHISH_A, PHISH_B])
    examples = [
        {"text": PHISH_B, "label": "phishing", "text_hash": "h1", "domain": "a.test", "word_count": 27},
        {"text": "too short", "label": 0},
    ]
    first, second = score_examples(examples, index)

    assert (first["label"], first["text_hash"], first["domain"], first["word_count"]) == (1, "h1", "a.test", 27)
    assert first["reason"] is None

    assert second["label"] == 0                       # labels are normalised to 0 and 1
    assert second["reason"] == "short_text"
    assert (second["real_score"], second["fake_score"], second["max_similarity"]) == (0.0, 0.0, None)
    assert second["word_count"] == 2                  # computed from the text when the example has none
    assert second["text_hash"] is None


def test_reason_counts_names_scored_pages():
    rows = [{"reason": None}, {"reason": None}, {"reason": "short_text"}]
    assert reason_counts(rows) == {"scored": 2, "short_text": 1}


SWEEP_ROWS = [
    {"label": 1, "fake_score": 0.75, "real_score": 0.25, "reason": None},    # margin +0.5
    {"label": 1, "fake_score": 0.625, "real_score": 0.5, "reason": None},    # margin +0.125
    {"label": 0, "fake_score": 0.25, "real_score": 0.75, "reason": None},    # margin -0.5
    {"label": 0, "fake_score": 0.5, "real_score": 0.625, "reason": None},    # margin -0.125
    {"label": 0, "fake_score": 0.5, "real_score": 0.5, "reason": None},      # margin 0
]


def test_predictions_at_abstains_inside_the_dead_zone():
    rows = SWEEP_ROWS[:4] + [{"label": 0, "fake_score": 0.75, "real_score": 0.25, "reason": "short_text"}]
    labels, predictions = predictions_at(rows, 0.125)
    assert labels == [1, 1, 0, 0, 0]
    assert predictions == [1, None, 0, None, None]   # the edges (+/-0.125) and the unreadable page abstain


def test_sweep_dead_zones_exact_counts_and_monotonic_coverage():
    table = sweep_dead_zones(SWEEP_ROWS, [0.0, 0.125, 0.5])
    assert [(e["tp"], e["fp"], e["tn"], e["fn"]) for e in table] == [(2, 0, 2, 0), (1, 0, 1, 0), (0, 0, 0, 0)]
    coverages = [e["coverage"] for e in table]
    assert coverages == pytest.approx([0.8, 0.4, 0.0])    # the margin-0 page abstains even at dead zone 0
    assert coverages == sorted(coverages, reverse=True)   # a wider dead zone never answers more pages
    assert table[1]["recall_all"] == 0.5
    assert table[2]["fpr_answered"] is None               # nothing answered, so no rate
    assert choose_dead_zone(table)["dead_zone"] == 0.0    # the only entry within coverage >= 0.7


def test_choose_wordcount_cutoff_accepts_a_false_positive_rate_exactly_at_the_limit():
    rows = [{"label": 1, "word_count": w} for w in (50, 80, 150)]
    rows += [{"label": 0, "word_count": 100}] + [{"label": 0, "word_count": 1000} for _ in range(19)]
    chosen = choose_wordcount_cutoff(wordcount_table(rows))
    # cutoff 151 flags all three phishing pages and one of the 20 benign pages: 1/20 = 0.05, exactly the limit
    assert chosen["cutoff"] == 151
    assert (chosen["tp"], chosen["fp"]) == (3, 1)
    assert chosen["recall_all"] == 1.0
