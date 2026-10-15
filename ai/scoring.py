from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from sentence_transformers import SentenceTransformer, util

from mongo_dataset import PageRecordStore
from .fetcher import fetch_page
from dataclasses import dataclass, field
from .records import MIN_LANGUAGE_PROBABILITY, MIN_WORDS, REQUIRED_LANGUAGE
from .text_processing import (
    chunk_text,
    clean_text,
    detect_language,
    detect_language_with_confidence,
    extract_page,
    extract_page_text,
    hash_text,
    quality_flags,
)

# Production rule, pre-registered before the test run: fake if margin > threshold, otherwise real.
# On the held-out test split this gave recall 0.42 at a false-positive rate of 0.04 (see EXPERIMENTS.md).
DEFAULT_THRESHOLD = 0.10
# Symmetric rule with abstention, kept for experiments only.
DEFAULT_DEAD_ZONE = 0.02
# Legacy names, still imported by ai/__init__.py and dataset_collector.py. Remove during package cleanup.
DEFAULT_SIMILARITY_THRESHOLD = DEFAULT_THRESHOLD
UNKNOWN_MARGIN = 0.01  # unused
MAX_REFERENCE_CHUNKS = 4   # chunks kept per reference page, so a long article can't outweigh a short login page
TOP_K = 3                  # candidate chunks that count toward each class score
MAX_CANDIDATE_CHUNKS = 10  # bounds run time on very long pages

MODEL_NAME = "all-MiniLM-L6-v2"


class LazySentenceTransformer:
    def __init__(self) -> None:
        self._model = None
        self._lock = threading.Lock()

    def _load(self):
        if self._model is None:
            with self._lock:
                if self._model is None:
                    self._model = SentenceTransformer(MODEL_NAME)
        return self._model

    def __getattr__(self, name):
        return getattr(self._load(), name)

    def __call__(self, *args, **kwargs):
        return self._load()(*args, **kwargs)


model = LazySentenceTransformer()


def get_model():
    return model._load()


def encode_texts(texts):
    if not texts:
        return []
    return get_model().encode(texts, convert_to_tensor=True, normalize_embeddings=True)

@dataclass
class ReferenceIndex:
    real_vecs: Any = None
    fake_vecs: Any = None
    real_hashes: List[str] = field(default_factory=list)   # source-page hash of every chunk
    fake_hashes: List[str] = field(default_factory=list)


def _embed_references(texts):
    chunks: List[str] = []
    hashes: List[str] = []
    for text in texts or []:
        cleaned = clean_text(text)
        if not cleaned:
            continue
        page_hash = hash_text(cleaned)
        for chunk in chunk_text(cleaned)[:MAX_REFERENCE_CHUNKS]:
            chunks.append(chunk)
            hashes.append(page_hash)
    if not chunks:
        return None, []
    return encode_texts(chunks), hashes


def build_reference_index(real_reference_texts, fake_reference_texts) -> ReferenceIndex:
    real_vecs, real_hashes = _embed_references(real_reference_texts)
    fake_vecs, fake_hashes = _embed_references(fake_reference_texts)
    return ReferenceIndex(real_vecs, fake_vecs, real_hashes, fake_hashes)


def _top_k_mean(sims, keep_idx, k: int = TOP_K) -> float:
    """sims: candidate chunks x reference chunks. Take the best kept reference per candidate chunk, then average the k best chunks."""
    best = sims[:, keep_idx].max(dim=1).values.tolist()
    top = sorted(best, reverse=True)[:k]
    return sum(top) / len(top)


def _failed_score(reason: str):
    return {"real_score": 0.0, "fake_score": 0.0, "reason": reason}


def decide_symmetric_verdict(
    fake_score: float,
    real_score: float,
    dead_zone: float = DEFAULT_DEAD_ZONE,
):
    """Experimental rule with abstention: inside [-dead_zone, +dead_zone], edges included, say unknown."""
    margin = fake_score - real_score

    if margin > dead_zone:
        verdict, reason = "fake", "decided"
    elif margin < -dead_zone:
        verdict, reason = "real", "decided"
    else:
        verdict, reason = "unknown", "low_margin"

    return {
        "real_score": real_score,
        "fake_score": fake_score,
        "margin": margin,
        "verdict": verdict,
        "confidence": abs(margin),
        "reason": reason,
    }


def decide_similarity_verdict(
    fake_score: float,
    real_score: float,
    threshold: float = DEFAULT_THRESHOLD,
):
    """Production rule: fake if margin > threshold, otherwise real. "real" means not flagged, not verified legitimate."""
    margin = fake_score - real_score
    return {
        "real_score": real_score,
        "fake_score": fake_score,
        "margin": margin,
        "verdict": "fake" if margin > threshold else "real",
        "confidence": abs(margin),  # a raw similarity gap, not a probability
        "reason": "decided",
        "rule": "onesided",
        "threshold": threshold,
    }

def score_text_against_references(
    candidate_text,
    real_reference_texts=None,
    fake_reference_texts=None,
    index: Optional[ReferenceIndex] = None,
    exclude_self: bool = True,
):
    cleaned = clean_text(candidate_text)
    if not cleaned or len(cleaned.split()) < 10:
        return _failed_score("short_text")

    if detect_language(cleaned) != "en":
        return _failed_score("unsupported_language")

    if index is None:
        index = build_reference_index(real_reference_texts, fake_reference_texts)

    # A stored page must not match its own copy among the references.
    own_hash = hash_text(cleaned) if exclude_self else None
    real_keep = [i for i, h in enumerate(index.real_hashes) if h != own_hash]
    fake_keep = [i for i, h in enumerate(index.fake_hashes) if h != own_hash]
    if not real_keep or not fake_keep:
        return _failed_score("no_references")

    chunks = chunk_text(cleaned)[:MAX_CANDIDATE_CHUNKS]
    candidate_vecs = encode_texts(chunks)
    real_sims = util.cos_sim(candidate_vecs, index.real_vecs)
    fake_sims = util.cos_sim(candidate_vecs, index.fake_vecs)

    return {
        "real_score": _top_k_mean(real_sims, real_keep),
        "fake_score": _top_k_mean(fake_sims, fake_keep),
        "max_similarity": float(max(real_sims[:, real_keep].max(), fake_sims[:, fake_keep].max())),
        "reason": None,
    }


def compare_page_to_references(
    candidate_text,
    real_reference_texts=None,
    fake_reference_texts=None,
    threshold: float = DEFAULT_THRESHOLD,
    index: Optional[ReferenceIndex] = None,
    exclude_self: bool = True,
):
    scored = score_text_against_references(
        candidate_text,
        real_reference_texts,
        fake_reference_texts,
        index=index,
        exclude_self=exclude_self,
    )
    if scored.get("reason"):
        return {
            "real_score": scored["real_score"],
            "fake_score": scored["fake_score"],
            "margin": 0.0,
            "verdict": "unknown",
            "confidence": 0.0,
            "reason": scored["reason"],
        }

    return decide_similarity_verdict(scored["fake_score"], scored["real_score"], threshold=threshold)

def load_reference_texts(label_name: str, limit: Optional[int] = None, split: str = "train"):
    """Texts of ready, English pages of one class in one split, in a stable order. limit=None means all."""
    store = PageRecordStore()
    try:
        docs = store.find_references(label_name, split=split, limit=limit)
    finally:
        store.close()

    texts = []
    for doc in docs:
        text = clean_text(doc.get("content", {}).get("text") or "")
        if text:
            texts.append(text)
    return texts


def score_candidate_page(
    candidate_url: str,
    real_limit: Optional[int] = None,
    fake_limit: Optional[int] = None,
    threshold: float = DEFAULT_THRESHOLD,
    split: str = "train",
):
    success, fetch_data, payload = fetch_page(candidate_url)

    if not success:
        return {
            "status": "failed",
            "reason": payload,
            "real_score": 0.0,
            "fake_score": 0.0,
            "margin": 0.0,
            "verdict": "unknown",
            "confidence": 0.0,
        }

    page_text = extract_page_text(payload)
    page_text = clean_text(page_text)

    if not page_text or len(page_text.split()) < 10:
        return {
            "status": "failed",
            "reason": "text too short for reliable comparison",
            "real_score": 0.0,
            "fake_score": 0.0,
            "margin": 0.0,
            "verdict": "unknown",
            "confidence": 0.0,
        }

    real_texts = load_reference_texts("benign", limit=real_limit, split=split)
    fake_texts = load_reference_texts("phishing", limit=fake_limit, split=split)

    if not real_texts or not fake_texts:
        return {
            "status": "failed",
            "reason": "missing reference data",
            "real_score": 0.0,
            "fake_score": 0.0,
            "margin": 0.0,
            "verdict": "unknown",
            "confidence": 0.0,
        }

    result = compare_page_to_references(page_text, real_texts, fake_texts, threshold=threshold)
    
    return {
        "status": "ok",
        "url": candidate_url,
        "final_url": fetch_data.get("final_url"),
        "real_score": result["real_score"],
        "fake_score": result["fake_score"],
        "margin": result["margin"],
        "verdict": result["verdict"],
        "confidence": result["confidence"],
        "reason": result.get("reason"),
    }


# ---- Scoring HTML the caller already fetched (used by the scanner) ----

_INDEX_LOCK = threading.Lock()
_INDEX_CACHE: Dict[str, Optional[ReferenceIndex]] = {}


def get_reference_index(split: str = "train", refresh: bool = False) -> Optional[ReferenceIndex]:
    """Build the reference index once per split. None when a class has no references.
    Raises if MongoDB is unreachable, and then caches nothing, so the next call retries."""
    with _INDEX_LOCK:
        if refresh or split not in _INDEX_CACHE:
            real_texts = load_reference_texts("benign", split=split)
            fake_texts = load_reference_texts("phishing", split=split)
            _INDEX_CACHE[split] = build_reference_index(real_texts, fake_texts) if real_texts and fake_texts else None
        return _INDEX_CACHE[split]


def reference_counts(index: Optional[ReferenceIndex]) -> Dict[str, int]:
    if index is None:
        return {"benign": 0, "phishing": 0}
    return {"benign": len(set(index.real_hashes)), "phishing": len(set(index.fake_hashes))}


def _html_result(status: str, reason: str, verdict: str = "unknown", **extra) -> Dict[str, Any]:
    result = {
        "status": status,            # ok | skipped | error
        "verdict": verdict,          # fake | real | unknown. "real" means not flagged, not verified legitimate.
        "reason": reason,
        "real_score": None,
        "fake_score": None,
        "margin": None,
        "threshold": None,
        "flags": [],
        "word_count": None,
        "language": None,
        "language_confidence": None,
        "model": MODEL_NAME,
    }
    result.update(extra)
    return result


def _score_html(html, index, threshold, exclude_self) -> Dict[str, Any]:
    if index is None:
        return _html_result("skipped", "no_references")

    _, text = extract_page(html)
    text = clean_text(text)
    word_count = len(text.split())
    info: Dict[str, Any] = {"word_count": word_count, "reference_pages": reference_counts(index)}

    # The same gates, in the same order, as a page gets when it is stored as a reference.
    if word_count < MIN_WORDS:
        return _html_result("skipped", "short_text", **info)

    language, probability = detect_language_with_confidence(text)
    info.update(language=language, language_confidence=probability)
    if language != REQUIRED_LANGUAGE:
        return _html_result("skipped", "non_english", **info)
    if probability < MIN_LANGUAGE_PROBABILITY:
        return _html_result("skipped", "low_language_confidence", **info)

    flags = quality_flags(text, html)
    if flags:
        return _html_result("skipped", "flagged", flags=flags, **info)

    scored = score_text_against_references(text, index=index, exclude_self=exclude_self)
    if scored.get("reason"):
        return _html_result("skipped", scored["reason"], **info)

    decision = decide_similarity_verdict(scored["fake_score"], scored["real_score"], threshold=threshold)
    return _html_result(
        "ok",
        "decided",
        verdict=decision["verdict"],
        real_score=decision["real_score"],
        fake_score=decision["fake_score"],
        margin=decision["margin"],
        threshold=threshold,
        max_similarity=scored["max_similarity"],
        **info,
    )


def score_html(html, index, threshold: float = DEFAULT_THRESHOLD, exclude_self: bool = False) -> Dict[str, Any]:
    """Score HTML the caller already fetched. Pass response.content (bytes) so the page's own charset is honoured.
    Never raises: a failure in this step must not break a scan."""
    try:
        return _score_html(html, index, threshold, exclude_self)
    except Exception as exc:
        return _html_result("error", "error", error=f"{type(exc).__name__}: {exc}"[:200])
