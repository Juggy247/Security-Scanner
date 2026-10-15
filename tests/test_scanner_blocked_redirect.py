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

import scanner.core as core
from scanner.core import ScanReport, SecurityScanner
from scanner.netguard import GuardedSession, UnsafeUrlError

PAGE = b"<html><head><title>T</title></head><body>hi</body></html>"
PRIVATE = "Scanning private or internal addresses is not allowed"
HOSTS = {"example.test": ["8.8.8.8"], "other.test": ["1.1.1.1"]}


def resolver(host, port):
    if host in HOSTS:
        return HOSTS[host]
    raise socket.gaierror(socket.EAI_NONAME, "unknown host")


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
        response._content = PAGE if status == 200 else b""
        response._content_consumed = True
        response.raw = io.BytesIO(b"")
        if location:
            response.headers["Location"] = location
        return response

    def close(self):
        pass


def scripted_scanner(script):
    scanner = SecurityScanner()
    session = GuardedSession(resolver=resolver)
    adapter = ScriptedAdapter(script)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    scanner.session = session
    return scanner, adapter


def raising(url, reason=PRIVATE):
    def fake_fetch(session, requested, **kwargs):
        raise UnsafeUrlError(f"{reason}: {url}", url=url, reason=reason)

    return fake_fetch


@pytest.fixture
def quiet(monkeypatch):
    """No network and no database: robots, the online checks and the domain checks are stubbed."""
    calls = {"domain_only": []}
    monkeypatch.setattr(core, "scan_check", lambda url, session: True)
    monkeypatch.setattr(SecurityScanner, "_run_online_checks", lambda self, report, response, soup: None)
    monkeypatch.setattr(SecurityScanner, "_run_domain_checks", lambda self, report, domain, title: None)
    monkeypatch.setattr(
        SecurityScanner, "_run_domain_checks_only", lambda self, report, domain, url: calls["domain_only"].append((domain, url))
    )
    return calls


def test_a_blocked_redirect_hop_becomes_a_critical_finding(monkeypatch, quiet):
    monkeypatch.setattr(core, "fetch_url", raising("http://169.254.169.254/latest/meta-data/"))
    report = SecurityScanner().scan("https://example.test/")

    assert report.success is False
    assert report.blocked_redirect == {"target": "http://169.254.169.254/latest/meta-data/", "reason": PRIVATE}
    verdict = report.get_verdict()
    assert verdict["verdict"] == "SUSPICIOUS"
    assert verdict["issue_counts"]["critical"] == 1
    assert verdict["issues"]["critical"][0]["type"] == "Redirect to a Private or Internal Address"
    assert quiet["domain_only"] == [("example.test", "https://example.test/")]   # the offline fallback still runs


def test_blocking_the_submitted_host_itself_is_not_reported_as_a_redirect(monkeypatch, quiet):
    monkeypatch.setattr(core, "fetch_url", raising("https://example.test/"))
    report = SecurityScanner().scan("https://example.test/")

    assert report.blocked_redirect is None
    assert "private" in report.error
    assert report.get_verdict()["issue_counts"]["critical"] == 0
    assert quiet["domain_only"] == [("example.test", "https://example.test/")]


def test_blocked_redirect_survives_the_session_round_trip():
    blocked = {"target": "http://10.0.0.5/", "reason": "private"}
    data = ScanReport(url="https://example.test", success=False, blocked_redirect=blocked).to_dict()
    assert data["blocked_redirect"] == blocked
    assert ScanReport(**data).blocked_redirect == blocked          # the exact call app.py makes at /report
    assert ScanReport(**data).get_verdict()["issue_counts"]["critical"] == 1


def test_old_session_data_without_the_key_still_loads():
    data = ScanReport(url="https://example.test", success=True).to_dict()
    del data["blocked_redirect"]
    assert ScanReport(**data).blocked_redirect is None


def test_the_recorded_target_is_truncated_for_the_session_cookie(monkeypatch, quiet):
    monkeypatch.setattr(core, "fetch_url", raising("http://evil.test/" + "a" * 500))
    report = SecurityScanner().scan("https://example.test/")
    assert len(report.blocked_redirect["target"]) == 200


def test_public_page_redirecting_to_the_metadata_address_is_flagged_end_to_end(quiet):
    scanner, adapter = scripted_scanner({"https://example.test/": (302, "http://169.254.169.254/latest/meta-data/")})
    report = scanner.scan("https://example.test/")

    assert adapter.requested == ["https://example.test/"]           # the metadata address was never requested
    assert report.blocked_redirect["target"] == "http://169.254.169.254/latest/meta-data/"
    assert report.get_verdict()["verdict"] == "SUSPICIOUS"


def test_a_public_redirect_chain_is_scanned_normally(quiet):
    scanner, adapter = scripted_scanner(
        {"https://example.test/": (301, "https://other.test/landing"), "https://other.test/landing": (200, None)}
    )
    report = scanner.scan("https://example.test/")

    assert report.success is True
    assert report.blocked_redirect is None
    assert report.title == "T"
    assert adapter.requested == ["https://example.test/", "https://other.test/landing"]


def test_the_guard_error_carries_the_blocked_url_and_reason():
    session = GuardedSession(resolver=resolver)
    with pytest.raises(UnsafeUrlError) as caught:
        session.get("http://127.0.0.1/admin")
    assert caught.value.url == "http://127.0.0.1/admin"
    assert "private" in caught.value.reason
