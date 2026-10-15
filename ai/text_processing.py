import hashlib
import re
from typing import List, Optional, Tuple, Union

from bs4 import BeautifulSoup, FeatureNotFound
from langdetect import DetectorFactory, LangDetectException, detect, detect_langs

DetectorFactory.seed = 0

EXTRACTOR_VERSION = "v3"
REMOVED_TAGS = ["script", "style", "noscript", "svg", "iframe", "nav", "header", "footer", "aside"]
MIN_MAIN_WORDS = 40
SHORT_PAGE_WORDS = 150
HEAD_WORDS = 80

_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"
)

HIDDEN_SELECTORS = [
    "[hidden]",
    "[role='navigation']",
    "[role='banner']",
    "[role='contentinfo']",
]

# Review this list with real data. Phrases are deliberately specific, because
# phishing copy itself says "suspended" and "verify".
FLAG_PHRASES = {
    "parked_domain": (
        "this domain is for sale",
        "domain may be for sale",
        "buy this domain",
        "this domain is parked",
        "domain parking",
        "this domain name has been registered",
    ),
    "hosting_default": (
        "welcome to nginx",
        "apache2 ubuntu default page",
        "apache2 debian default page",
        "index of /",
        "default web site page",
    ),
    "takedown_or_warning": (
        "deceptive site ahead",
        "suspected phishing page",
        "this site has been suspended",
        "this website has been suspended",
        "has been reported as unsafe",
        "this account has been suspended by",
    ),
    "js_challenge": (
        "checking your browser before accessing",
        "enable javascript and cookies to continue",
        "just a moment...",
        "please enable javascript to view",
        "security checkpoint",
        "verifying your browser",
        "javascript isn't enabled in your browser",
        "browser settings must allow scripts to run",
    ),
    "error_page": (
        "that url doesn't exist",
        "page not found",
        "404 not found",
        "this page does not exist",
        "this page isn't available",
        "web server is down",
        "error code 52",
    ),
    "cms_default": (
        "this is an example page",
        "just another wordpress site",
        "hello world! welcome to wordpress",
    ),
    "viewer_artifact": (
        "document outline attachments layers",
    ),
}


def hash_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def clean_text(text: str) -> str:
    if not text:
        return ""

    cleaned = re.sub(r"\s+", " ", text)
    return cleaned.strip()


def detect_language(text: str) -> Optional[str]:
    if not text:
        return None

    cleaned = clean_text(text)
    if len(cleaned.split()) < 10:
        return None

    try:
        return detect(cleaned)
    except LangDetectException:
        return None


def detect_language_with_confidence(text: str) -> Tuple[Optional[str], float]:
    cleaned = clean_text(text)
    if len(cleaned.split()) < 10:
        return None, 0.0

    try:
        ranked = detect_langs(cleaned)
    except LangDetectException:
        return None, 0.0

    if not ranked:
        return None, 0.0
    return ranked[0].lang, float(ranked[0].prob)


def _make_soup(html: Union[str, bytes], charset: Optional[str] = None) -> BeautifulSoup:
    kwargs = {}
    if isinstance(html, bytes) and charset:
        kwargs["from_encoding"] = charset
    try:
        return BeautifulSoup(html, "lxml", **kwargs)
    except FeatureNotFound:
        return BeautifulSoup(html, "html.parser", **kwargs)


def _attribute_text(soup: BeautifulSoup) -> str:
    parts: List[str] = []
    for tag in soup.find_all("input"):
        input_type = (tag.get("type") or "text").lower()
        if input_type in {"submit", "button"}:
            value = tag.get("value")
            if value:
                parts.append(value)
        elif input_type in {"text", "email", "password", "tel", "search"}:
            placeholder = tag.get("placeholder")
            if placeholder:
                parts.append(placeholder)
    for tag in soup.find_all("img"):
        alt = tag.get("alt")
        if alt:
            parts.append(alt)
    return " ".join(parts)


def extract_page(html: Union[str, bytes], charset: Optional[str] = None) -> Tuple[str, str]:
    """Return (title, cleaned_text)."""
    soup = _make_soup(html, charset)

    for tag in soup(REMOVED_TAGS):
        for selector in HIDDEN_SELECTORS:
            for tag in soup.select(selector):
                if not getattr(tag, "decomposed", False):
                    tag.decompose()

    title = soup.title.get_text(" ", strip=True) if soup.title else ""

    root = soup.find("main") or soup.find("article")
    body = root.get_text(" ", strip=True) if root else ""
    if len(body.split()) < MIN_MAIN_WORDS:
        body = soup.get_text(" ", strip=True)

    if title and title in body:
        body = body.replace(title, "", 1)

    merged = " ".join(part for part in [title, body, _attribute_text(soup)] if part)
    return title, clean_text(merged)


def extract_page_text(html: Union[str, bytes], charset: Optional[str] = None) -> str:
    return extract_page(html, charset)[1]


def quality_flags(text: str, raw_html: Union[str, bytes, None] = None) -> List[str]:
    lowered = clean_text(text).lower().replace("\u2019", "'")
    words = lowered.split()
    word_count = len(words)
    flags: List[str] = []

    # Error and takedown messages sit at the start of a page. Long articles may mention
    # these phrases deep in the text, so long pages are only searched near the start.
    scope = lowered if word_count < SHORT_PAGE_WORDS else " ".join(words[:HEAD_WORDS])
    for flag, phrases in FLAG_PHRASES.items():
        if any(phrase in scope for phrase in phrases):
            flags.append(flag)

    if word_count < SHORT_PAGE_WORDS:
        if _PRIVATE_IP_RE.search(lowered):
            flags.append("private_address_in_text")

        if raw_html is not None:
            # (keep your existing meta-refresh block here, unchanged)
            html_text = raw_html if isinstance(raw_html, str) else raw_html.decode("utf-8", errors="ignore")
            html_lower = html_text.lower()
            if (
                'http-equiv="refresh"' in html_lower
                or "http-equiv='refresh'" in html_lower
            ):
                flags.append("client_side_redirect")

    return flags


def chunk_text(text: str, chunk_size: int = 180, overlap: int = 30) -> List[str]:
    cleaned = clean_text(text)
    if not cleaned:
        return []

    words = cleaned.split()
    if len(words) <= chunk_size:
        return [cleaned]

    step = max(1, chunk_size - overlap)
    chunks: List[str] = []
    start = 0

    while start < len(words):
        end = min(start + chunk_size, len(words))
        part = " ".join(words[start:end])
        chunk = clean_text(part)
        if chunk:
            chunks.append(chunk)
        if end == len(words):
            break
        start += step

    return chunks