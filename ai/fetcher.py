from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
TOTAL_DEADLINE_SECONDS = 30
CONNECT_READ_TIMEOUT = (5, 10)
ALLOWED_MEDIA_TYPES = {"text/html", "application/xhtml+xml"}
USER_AGENT = "Mozilla/5.0"
ACCEPT_LANGUAGE = "en-US,en;q=0.9"

_CHARSET_RE = re.compile(r"charset=([\w\-]+)", re.IGNORECASE)
_DNS_MARKERS = (
    "NameResolutionError",
    "nodename nor servname",
    "Name or service not known",
    "getaddrinfo failed",
    "Temporary failure in name resolution",
)


@dataclass
class FetchResult:
    ok: bool
    body: bytes = b""
    error_code: Optional[str] = None
    detail: Optional[str] = None
    final_url: str = ""
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    redirect_count: int = 0
    redirect_chain: List[str] = field(default_factory=list)
    charset: Optional[str] = None


def fetch(url: str) -> FetchResult:
    started = time.monotonic()
    meta: Dict[str, Any] = {
        "final_url": url,
        "status_code": None,
        "content_type": None,
        "redirect_count": 0,
        "redirect_chain": [],
    }

    try:
        with requests.Session() as session:
            session.max_redirects = MAX_REDIRECTS
            session.headers.update({"User-Agent": USER_AGENT, "Accept-Language": ACCEPT_LANGUAGE})

            with session.get(url, timeout=CONNECT_READ_TIMEOUT, allow_redirects=True, stream=True) as response:
                content_type = response.headers.get("Content-Type", "")
                meta.update(
                    final_url=response.url,
                    status_code=response.status_code,
                    content_type=content_type,
                    redirect_count=len(response.history),
                    redirect_chain=[r.url for r in response.history],
                )

                if response.status_code >= 400:
                    return FetchResult(ok=False, error_code="http_error", detail=f"HTTP {response.status_code}", **meta)

                media_type = content_type.split(";", 1)[0].strip().lower()
                if media_type not in ALLOWED_MEDIA_TYPES:
                    return FetchResult(
                        ok=False,
                        error_code="unsupported_content_type",
                        detail=f"Unsupported content type: {content_type or 'missing'}",
                        **meta,
                    )

                match = _CHARSET_RE.search(content_type)
                charset = match.group(1) if match else None

                body = bytearray()
                for chunk in response.iter_content(chunk_size=16384):
                    body.extend(chunk)
                    if len(body) > MAX_BYTES:
                        return FetchResult(ok=False, error_code="too_large", detail=f"over {MAX_BYTES} bytes", **meta)
                    if time.monotonic() - started > TOTAL_DEADLINE_SECONDS:
                        return FetchResult(ok=False, error_code="timeout", detail="total deadline exceeded", **meta)

                return FetchResult(ok=True, body=bytes(body), charset=charset, **meta)

    except requests.exceptions.TooManyRedirects as exc:
        return FetchResult(ok=False, error_code="too_many_redirects", detail=str(exc)[:200], **meta)
    except requests.exceptions.SSLError as exc:
        return FetchResult(ok=False, error_code="tls_error", detail=str(exc)[:200], **meta)
    except requests.exceptions.Timeout as exc:
        return FetchResult(ok=False, error_code="timeout", detail=str(exc)[:200], **meta)
    except requests.exceptions.ConnectionError as exc:
        text = str(exc)
        code = "dns_failure" if any(marker in text for marker in _DNS_MARKERS) else "network_error"
        return FetchResult(ok=False, error_code=code, detail=text[:200], **meta)
    except requests.exceptions.RequestException as exc:
        return FetchResult(ok=False, error_code="network_error", detail=str(exc)[:200], **meta)


def decode_body(body: bytes, charset: Optional[str] = None) -> str:
    for encoding in (charset, "utf-8"):
        if not encoding:
            continue
        try:
            return body.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("utf-8", errors="replace")


def fetch_page(url: str) -> Tuple[bool, Dict[str, Any], str]:
    """Backward-compatible wrapper: same tuple shape as before."""
    result = fetch(url)
    meta = {
        "final_url": result.final_url,
        "status_code": result.status_code,
        "content_type": result.content_type,
        "redirect_count": result.redirect_count,
    }
    if not result.ok:
        return False, meta, result.detail or result.error_code or "fetch failed"
    return True, meta, decode_body(result.body, result.charset)