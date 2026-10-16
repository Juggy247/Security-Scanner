from __future__ import annotations

import io
import os
import sys

import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanner import utils
from scanner.utils import CHUNK_SIZE, fetch_url, session_get

URL = "http://8.8.8.8/"


class StreamAdapter(requests.adapters.BaseAdapter):
    def __init__(self, raw, encoding=None, headers=None):
        super().__init__()
        self.raw, self.encoding, self.headers = raw, encoding, headers or {}

    def send(self, request, **kwargs):
        response = requests.Response()
        response.status_code = 200
        response.url = request.url
        response.request = request
        response.raw = self.raw                       # not consumed: the response is still streaming
        response.encoding = self.encoding
        response.headers.update(self.headers)
        return response

    def close(self):
        pass


class EndlessRaw:
    """Never ends. Fails loudly instead of hanging if the code reads far past any sensible cap."""

    def __init__(self, on_read=None):
        self.total_read, self.reads, self.closed, self.on_read = 0, 0, False, on_read

    def read(self, amt=None):
        self.reads += 1
        if self.on_read:
            self.on_read()
        self.total_read += amt
        if self.total_read > 10_000_000:
            raise AssertionError("the endless stream was read far past the cap")
        return b"x" * amt

    def close(self):
        self.closed = True


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def fetched(raw, **kwargs):
    session = session_get()
    session.mount("http://", StreamAdapter(raw, **kwargs.pop("adapter", {})))
    return fetch_url(session, URL, **kwargs)


def test_a_body_over_the_cap_is_cut_off():
    response = fetched(io.BytesIO(b"a" * 100_000), max_bytes=1000)
    assert response.content == b"a" * 1000
    assert response.truncated is True


def test_a_body_under_the_cap_is_returned_whole():
    response = fetched(io.BytesIO(b"hello"), max_bytes=1000)
    assert response.content == b"hello"
    assert response.truncated is False


def test_a_body_exactly_at_the_cap_is_not_marked_truncated():
    response = fetched(io.BytesIO(b"a" * 1000), max_bytes=1000)
    assert len(response.content) == 1000
    assert response.truncated is False


def test_an_endless_stream_stops_at_the_cap_and_is_closed():
    raw = EndlessRaw()
    response = fetched(raw, max_bytes=50_000)
    assert len(response.content) == 50_000
    assert response.truncated is True
    assert raw.total_read <= 50_000 + CHUNK_SIZE      # at most one chunk past the cap
    assert raw.closed is True


def test_the_deadline_stops_a_slow_stream(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(utils, "_now", clock)
    raw = EndlessRaw(on_read=lambda: setattr(clock, "t", clock.t + 10))   # every read takes 10 "seconds"
    response = fetched(raw, deadline_seconds=25)
    assert raw.reads == 3                              # reads end at t=10, 20 and 30, and 30 is past 25
    assert len(response.content) == 3 * CHUNK_SIZE
    assert response.truncated is True
    assert raw.closed is True


def test_status_url_headers_and_text_survive_streaming():
    response = fetched(
        io.BytesIO("héllo".encode("utf-8")),
        adapter={"encoding": "utf-8", "headers": {"Content-Type": "text/html; charset=utf-8"}},
    )
    assert response.status_code == 200
    assert response.url == URL
    assert response.headers["Content-Type"] == "text/html; charset=utf-8"
    assert response.text == "héllo"


class LoopAdapter(requests.adapters.BaseAdapter):
    def __init__(self):
        super().__init__()
        self.calls = 0

    def send(self, request, **kwargs):
        self.calls += 1
        response = requests.Response()
        response.status_code = 302
        response.url = request.url
        response.request = request
        response.raw = io.BytesIO(b"")
        response.headers["Location"] = f"http://8.8.8.8/hop{self.calls}"
        return response

    def close(self):
        pass


def test_a_redirect_loop_stops_early_and_is_reported_as_a_failed_fetch():
    session = session_get()
    adapter = LoopAdapter()
    session.mount("http://", adapter)
    assert fetch_url(session, URL) is None
    assert adapter.calls < 20                          # requests' default limit is 30


def test_the_session_limits_redirects_to_ten():
    assert session_get().max_redirects == 10
