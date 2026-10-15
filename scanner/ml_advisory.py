"""Advisory ML signal for the scanner.

Display only: nothing here changes the rule-based verdict. The `ai` package (and torch) is imported inside the
function, so importing the scanner stays cheap, and a missing ML dependency only turns this step into status "error".
"""
from __future__ import annotations

from typing import Any, Dict, Optional

HTML_TYPES = {"text/html", "application/xhtml+xml"}

# Small fields only: the whole scan result is stored in a Flask session cookie (about 4 KB limit).
KEEP = (
    "status", "verdict", "reason", "real_score", "fake_score", "margin", "threshold",
    "flags", "word_count", "language", "language_confidence", "model", "reference_pages", "error",
)


def _advisory(status: str, reason: str, **extra) -> Dict[str, Any]:
    result = {"status": status, "verdict": "unknown", "reason": reason}
    result.update(extra)
    return result


def run_ml_advisory(content: bytes, status_code: Optional[int] = None, content_type: Optional[str] = None) -> Dict[str, Any]:
    """Score page bytes the scanner already fetched. Never raises. Returns a small JSON-safe dict."""
    try:
        if status_code is not None and status_code >= 400:
            return _advisory("skipped", "http_error", http_status=status_code)

        media_type = (content_type or "").split(";", 1)[0].strip().lower()
        if media_type and media_type not in HTML_TYPES:
            return _advisory("skipped", "not_html", content_type=media_type)

        if not content:
            return _advisory("skipped", "empty_body")

        from ai.scoring import get_reference_index, score_html  # lazy: torch loads only when this step runs

        result = score_html(content, get_reference_index())
        return {
            key: round(result[key], 4) if isinstance(result[key], float) else result[key]
            for key in KEEP
            if key in result
        }
    except Exception as exc:
        return _advisory("error", "error", error=f"{type(exc).__name__}: {exc}"[:200])