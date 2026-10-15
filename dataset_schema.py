from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

SCHEMA_VERSION = 4
ALLOWED_SOURCES = {
    "openphish",
    "phishtank",
    "tranco",
    "manual_benign",
    "synthetic_test",
    "phreshphish",
}

LabelValue = Literal["phishing", "benign", "unknown"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class LabelInfo:
    value: LabelValue
    source: str
    evidence: str
    reviewed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if self.source not in ALLOWED_SOURCES:
            raise ValueError(f"label source must be one of {sorted(ALLOWED_SOURCES)}, got {self.source!r}")
        if not (self.evidence or "").strip():
            raise ValueError("label evidence is required (feed URL plus listing timestamp, or a note)")


@dataclass
class FetchInfo:
    final_url: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    redirect_count: int = 0
    redirect_chain: List[str] = field(default_factory=list)
    fetched_with: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContentInfo:
    title: Optional[str] = None
    text: Optional[str] = None
    text_hash: Optional[str] = None
    language: Optional[str] = None
    language_confidence: Optional[float] = None
    word_count: int = 0
    extractor_version: str = "v2"
    raw_html_ref: Optional[str] = None
    raw_html_hash: Optional[str] = None


@dataclass
class OriginInfo:
    # Where a record came from when it was not fetched by us (dataset ingestion).
    dataset: str
    version: str
    split: str  # the dataset's own split: "train" or "test"
    sha256: Optional[str] = None
    date: Optional[str] = None  # ISO string, because pymongo cannot store datetime.date
    target: Optional[str] = None  # impersonated brand, phishing pages only
    bucket: Optional[str] = None  # sampling bucket: phishing, benign_hard or benign_regular


@dataclass
class ProcessingInfo:
    # pending | ready | failed (fetch problem) | rejected (fetched, but unusable)
    status: str = "pending"
    error: Optional[str] = None
    error_code: Optional[str] = None
    flags: List[str] = field(default_factory=list)


@dataclass
class PageRecord:
    url: str
    domain: str
    captured_at: datetime
    label: LabelInfo
    fetch: FetchInfo
    content: ContentInfo
    split: Optional[str] = None
    origin: Optional[OriginInfo] = None
    processing: ProcessingInfo = field(default_factory=ProcessingInfo)
    schema_version: int = SCHEMA_VERSION

    def to_mongo_dict(self) -> Dict[str, Any]:
        origin = None
        if self.origin is not None:
            origin = {
                "dataset": self.origin.dataset,
                "version": self.origin.version,
                "split": self.origin.split,
                "sha256": self.origin.sha256,
                "date": self.origin.date,
                "target": self.origin.target,
                "bucket": self.origin.bucket,
            }

        return {
            "url": self.url,
            "domain": self.domain,
            "split": self.split,
            "origin": origin,
            "captured_at": self.captured_at,
            "label": {
                "value": self.label.value,
                "source": self.label.source,
                "evidence": self.label.evidence,
                "reviewed_at": self.label.reviewed_at,
            },
            "fetch": {
                "final_url": self.fetch.final_url,
                "status_code": self.fetch.status_code,
                "content_type": self.fetch.content_type,
                "redirect_count": self.fetch.redirect_count,
                "redirect_chain": self.fetch.redirect_chain,
                "fetched_with": self.fetch.fetched_with,
            },
            "content": {
                "title": self.content.title,
                "text": self.content.text,
                "text_hash": self.content.text_hash,
                "language": self.content.language,
                "language_confidence": self.content.language_confidence,
                "word_count": self.content.word_count,
                "extractor_version": self.content.extractor_version,
                "raw_html_ref": self.content.raw_html_ref,
                "raw_html_hash": self.content.raw_html_hash,
            },
            "processing": {
                "status": self.processing.status,
                "error": self.processing.error,
                "error_code": self.processing.error_code,
                "flags": self.processing.flags,
            },
            "schema_version": self.schema_version,
        }