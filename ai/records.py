from __future__ import annotations

import hashlib
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from dataset_schema import (
    ContentInfo,
    FetchInfo,
    LabelInfo,
    OriginInfo,
    PageRecord,
    ProcessingInfo,
    utc_now,
)
from .fetcher import ACCEPT_LANGUAGE, USER_AGENT, FetchResult, fetch
from .text_processing import (
    EXTRACTOR_VERSION,
    clean_text,
    detect_language_with_confidence,
    extract_page,
    hash_text,
    quality_flags,
)

MIN_WORDS = 20
MIN_LANGUAGE_PROBABILITY = 0.9
REQUIRED_LANGUAGE = "en"


def get_domain(url: str) -> str:
    candidate = url if "://" in url else f"http://{url}"
    return (urlparse(candidate).hostname or "").lower()


def _assemble(
    url: str,
    label: LabelInfo,
    result: FetchResult,
    content: ContentInfo,
    processing: ProcessingInfo,
    origin: Optional[OriginInfo] = None,
    fetched_with: Optional[dict] = None,
) -> PageRecord:
    if fetched_with is None:
        fetched_with = {"accept_language": ACCEPT_LANGUAGE, "user_agent": USER_AGENT}

    return PageRecord(
        url=url,
        domain=get_domain(url),
        captured_at=utc_now(),
        label=label,
        fetch=FetchInfo(
            final_url=result.final_url or url,
            status_code=result.status_code,
            content_type=result.content_type,
            redirect_count=result.redirect_count,
            redirect_chain=result.redirect_chain,
            fetched_with=fetched_with,
        ),
        content=content,
        origin=origin,
        processing=processing,
    )


def _process_html(
    url: str,
    label: LabelInfo,
    result: FetchResult,
    origin: Optional[OriginInfo] = None,
    fetched_with: Optional[dict] = None,
) -> Tuple[PageRecord, Optional[bytes]]:
    """Extract, gate and build a record from HTML bytes in result.body."""
    raw_hash = "sha256:" + hashlib.sha256(result.body).hexdigest()
    title, text = extract_page(result.body, charset=result.charset)
    text = clean_text(text)

    if not text:
        content = ContentInfo(extractor_version=EXTRACTOR_VERSION, raw_html_hash=raw_hash)
        processing = ProcessingInfo(status="rejected", error="empty extracted text", error_code="empty_text")
        return _assemble(url, label, result, content, processing, origin, fetched_with), result.body

    language, probability = detect_language_with_confidence(text)
    word_count = len(text.split())
    flags: List[str] = quality_flags(text, result.body)

    content = ContentInfo(
        title=title or None,
        text=text,
        text_hash=hash_text(text),
        language=language,
        language_confidence=probability,
        word_count=word_count,
        extractor_version=EXTRACTOR_VERSION,
        raw_html_hash=raw_hash,
    )

    if word_count < MIN_WORDS:
        processing = ProcessingInfo(
            status="rejected", error=f"{word_count} words, minimum {MIN_WORDS}", error_code="short_text", flags=flags
        )
    elif language != REQUIRED_LANGUAGE:
        processing = ProcessingInfo(
            status="rejected",
            error=f"language {language} at probability {probability:.2f}",
            error_code="non_english",
            flags=flags,
        )
    elif probability < MIN_LANGUAGE_PROBABILITY:
        processing = ProcessingInfo(
            status="rejected",
            error=f"language en at probability {probability:.2f}, minimum {MIN_LANGUAGE_PROBABILITY}",
            error_code="low_language_confidence",
            flags=flags,
        )
    elif flags:
        processing = ProcessingInfo(status="rejected", error=", ".join(flags), error_code="flagged", flags=flags)
    else:
        processing = ProcessingInfo(status="ready")

    return _assemble(url, label, result, content, processing, origin, fetched_with), result.body


def build_record_with_raw(
    url: str,
    label_value: str,
    source: str,
    evidence: str,
) -> Tuple[PageRecord, Optional[bytes]]:
    """Return (record, raw_html_bytes). raw is None when the fetch failed."""
    label = LabelInfo(value=label_value, source=source, evidence=evidence)
    result = fetch(url)

    if not result.ok:
        processing = ProcessingInfo(
            status="failed",
            error=(result.detail or "")[:200],
            error_code=result.error_code,
        )
        return _assemble(url, label, result, ContentInfo(extractor_version=EXTRACTOR_VERSION), processing), None

    return _process_html(url, label, result)


def build_record_from_html(
    url: str,
    html: str,
    label_value: str,
    source: str,
    evidence: str,
    origin: Optional[OriginInfo] = None,
) -> Tuple[PageRecord, Optional[bytes]]:
    """Build a record from HTML we were given (dataset ingestion), without fetching."""
    label = LabelInfo(value=label_value, source=source, evidence=evidence)
    body = html.encode("utf-8", errors="replace")
    # We just encoded to UTF-8, so tell the extractor that. Otherwise it may trust a
    # <meta charset> in the page that describes the original bytes, not ours.
    result = FetchResult(ok=True, body=body, final_url=url, charset="utf-8")
    return _process_html(url, label, result, origin=origin, fetched_with={"source": "dataset_html"})


def build_record(url: str, label_value: str, source: str, evidence: str) -> PageRecord:
    """Backward-compatible wrapper."""
    record, _ = build_record_with_raw(url, label_value, source, evidence)
    return record