from __future__ import annotations

import io
import os
import socket
import sys

import pytest
import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanner.netguard import GuardedSession, UnsafeUrlError, is_safe_url
from scanner.utils import fetch_url, session_get


class ExplodingAdapter(requests.adapters.BaseAdapter):
    """Fails the test if anything tries to connect."""

    def send(self, request, **kwargs):
        raise AssertionError(f"connected to {request.url}")

    def close(self):
        pass


class FailingAdapter(requests.adapters.BaseAdapter):
    def send(self, request, **kwargs):
        raise requests.exceptions.ConnectionError("boom")

    def close(self):
        pass


class OkAdapter(requests.adapters.BaseAdapter):
    def send(self, request, **kwargs):
        response = requests.Response()
        response.status_code = 200
        response.url = request.url
        response.request = request
        response._content = b"ok"
        response._content_consumed = True
        response.raw = io.BytesIO(b"")
        return response

    def close(self):
        pass


def test_session_get_returns_a_guarded_session_with_the_scanner_user_agent():
    session = session_get()
    assert isinstance(session, GuardedSession)
    assert session.headers["User-Agent"] == "SecurityScanner/1.0 (Educational)"


def test_fetch_url_refuses_private_targets_before_connecting():
    session = session_get()
    session.mount("http://", ExplodingAdapter())
    for url in ("http://127.0.0.1:9/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/"):
        with pytest.raises(UnsafeUrlError):
            fetch_url(session, url)


def test_fetch_url_still_returns_none_for_ordinary_failures():
    session = session_get()
    session.mount("http://", FailingAdapter())
    assert fetch_url(session, "http://8.8.8.8/") is None


def test_fetch_url_passes_a_public_response_through():
    session = session_get()
    session.mount("http://", OkAdapter())
    response = fetch_url(session, "http://8.8.8.8/")
    assert response.status_code == 200 and response.content == b"ok"


@pytest.mark.parametrize(
    "url, allowed",
    [
        ("https://8.8.8.8/", True),
        ("http://127.0.0.1:5000/", False),
        ("http://169.254.169.254/", False),
        ("ftp://8.8.8.8/", False),
    ],
)
def test_is_safe_url_allows_public_and_blocks_private(url, allowed):
    assert is_safe_url(url)[0] is allowed


def test_is_safe_url_keeps_unresolved_names_allowed_with_an_empty_reason():
    def unresolved(host, port):
        raise socket.gaierror(socket.EAI_NONAME, "unknown host")

    assert is_safe_url("http://dead-phishing.test/", unresolved) == (True, "")


def test_is_safe_url_explains_why_it_blocked():
    allowed, reason = is_safe_url("http://127.0.0.1/")
    assert allowed is False
    assert "private" in reason
