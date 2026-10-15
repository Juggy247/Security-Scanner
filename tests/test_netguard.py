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

from scanner.netguard import GuardedSession, UnsafeUrlError, check_public_url, is_public_address

HOSTS = {
    "example.test": ["8.8.8.8"],
    "other.test": ["1.1.1.1"],
    "internal.test": ["10.0.0.5"],
    "loop.test": ["127.0.0.1"],
    "metadata.test": ["169.254.169.254"],
    "cgnat.test": ["100.64.0.1"],
    "mapped.test": ["::ffff:127.0.0.1"],
    "mapped-public.test": ["::ffff:8.8.8.8"],
    "mixed.test": ["8.8.8.8", "10.0.0.5"],
    "v6-public.test": ["2606:4700:4700::1111"],
    "2130706433": ["127.0.0.1"],   # what an OS resolver typically returns for the decimal form of 127.0.0.1
    "0x7f.1": ["127.0.0.1"],
}


def resolver(host, port):
    if host in HOSTS:
        return HOSTS[host]
    raise socket.gaierror(socket.EAI_NONAME, "unknown host")


@pytest.mark.parametrize(
    "url",
    ["ftp://example.test/", "file:///etc/passwd", "gopher://example.test/", "javascript:alert(1)", "example.test", "http://", ""],
)
def test_non_http_and_malformed_urls_are_rejected(url):
    assert check_public_url(url, resolver)[0] is False


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/", "http://LOCALHOST./", "http://app.localhost:8080/", "http://127.0.0.1/",
        "http://127.0.0.1:5000/admin", "http://[::1]:8080/", "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/", "http://10.1.2.3/", "http://192.168.0.1/",
        "http://172.16.0.9/", "http://100.64.0.1/", "http://[::ffff:127.0.0.1]/",
    ],
)
def test_private_and_local_literals_are_blocked(url):
    assert check_public_url(url, resolver)[0] is False


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test/", "https://example.test:8443/login?x=1", "https://8.8.8.8/",
        "https://[2606:4700:4700::1111]/", "http://mapped-public.test/", "http://v6-public.test/",
    ],
)
def test_public_urls_are_allowed(url):
    assert check_public_url(url, resolver) == (True, "")


@pytest.mark.parametrize(
    "host", ["internal.test", "loop.test", "metadata.test", "cgnat.test", "mapped.test", "mixed.test", "2130706433", "0x7f.1"]
)
def test_names_that_resolve_to_non_public_addresses_are_blocked(host):
    allowed, reason = check_public_url(f"http://{host}/", resolver)
    assert allowed is False
    assert "private" in reason          # a single private answer among public ones is enough (mixed.test)


def test_unresolvable_names_are_allowed_so_offline_mode_keeps_working():
    assert check_public_url("http://dead-phishing.test/", resolver) == (True, "unresolved")


def test_unexpected_resolver_errors_fail_closed():
    def broken(host, port):
        raise RuntimeError("resolver exploded")

    allowed, reason = check_public_url("http://example.test/", broken)
    assert allowed is False
    assert "RuntimeError" in reason


def test_userinfo_does_not_hide_the_real_host():
    assert check_public_url("http://example.test@127.0.0.1/", resolver)[0] is False
    assert check_public_url("http://127.0.0.1@example.test/", resolver)[0] is True   # the host is example.test


def test_the_resolver_gets_the_right_default_ports():
    seen = []

    def recording(host, port):
        seen.append((host, port))
        return ["8.8.8.8"]

    for url in ("http://a.test/", "https://b.test/", "http://c.test:8080/"):
        check_public_url(url, recording)
    assert seen == [("a.test", 80), ("b.test", 443), ("c.test", 8080)]


@pytest.mark.parametrize(
    "address, public",
    [
        ("8.8.8.8", True), ("1.1.1.1", True), ("2606:4700:4700::1111", True), ("::ffff:8.8.8.8", True),
        ("10.0.0.1", False), ("172.16.5.5", False), ("192.168.1.1", False), ("127.0.0.1", False),
        ("169.254.1.1", False), ("100.64.0.1", False), ("0.0.0.0", False), ("224.0.0.1", False),
        ("240.0.0.1", False), ("::1", False), ("fe80::1", False), ("fe80::1%en0", False),
        ("fc00::1", False), ("::", False), ("::ffff:10.0.0.1", False), ("::ffff:127.0.0.1", False),
    ],
)
def test_is_public_address(address, public):
    assert is_public_address(address) is public


class ScriptedAdapter(requests.adapters.BaseAdapter):
    """Answers from a script and records every URL it is asked to fetch. No network."""

    def __init__(self, script):
        super().__init__()
        self.script = script      # url -> (status code, Location header or None)
        self.requested = []

    def send(self, request, **kwargs):
        self.requested.append(request.url)
        status, location = self.script[request.url]
        response = requests.Response()
        response.status_code = status
        response.url = request.url
        response.request = request
        response._content = b"ok" if status == 200 else b""
        response._content_consumed = True
        response.raw = io.BytesIO(b"")
        if location:
            response.headers["Location"] = location
        return response

    def close(self):
        pass


def guarded(script):
    session = GuardedSession(resolver=resolver)
    adapter = ScriptedAdapter(script)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session, adapter


def test_redirect_to_a_private_literal_is_blocked_before_connecting():
    session, adapter = guarded({"http://example.test/": (302, "http://169.254.169.254/latest/meta-data/")})
    with pytest.raises(UnsafeUrlError):
        session.get("http://example.test/")
    assert adapter.requested == ["http://example.test/"]    # the second hop never reached the adapter


def test_redirect_to_a_name_that_resolves_privately_is_blocked():
    session, adapter = guarded({"http://example.test/": (301, "http://loop.test/admin")})
    with pytest.raises(UnsafeUrlError):
        session.get("http://example.test/")
    assert adapter.requested == ["http://example.test/"]


def test_a_private_first_url_is_never_requested():
    session, adapter = guarded({})
    with pytest.raises(UnsafeUrlError):
        session.get("http://internal.test/")
    assert adapter.requested == []


def test_public_redirect_chains_still_work_and_keep_their_history():
    session, adapter = guarded(
        {"http://example.test/": (301, "https://other.test/landing"), "https://other.test/landing": (200, None)}
    )
    response = session.get("http://example.test/")
    assert response.status_code == 200
    assert response.url == "https://other.test/landing"
    assert [r.url for r in response.history] == ["http://example.test/"]
    assert adapter.requested == ["http://example.test/", "https://other.test/landing"]


def test_unresolved_hosts_pass_through_so_offline_mode_keeps_working():
    session, adapter = guarded({"http://dead-phishing.test/": (200, None)})
    assert session.get("http://dead-phishing.test/").status_code == 200
    assert adapter.requested == ["http://dead-phishing.test/"]


def test_unsafe_url_error_is_a_request_exception():
    # fetch_url already catches requests.RequestException, so a blocked URL becomes "fetch failed", not a crash
    assert issubclass(UnsafeUrlError, requests.exceptions.RequestException)
