from __future__ import annotations

import os
import subprocess
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import scanner.core as core
from scanner.core import ScanReport, SecurityScanner

ML = {"status": "ok", "verdict": "fake", "reason": "decided", "margin": 0.2}


def test_ml_analysis_survives_the_session_round_trip():
    data = ScanReport(url="https://example.com", success=True, ml_analysis=ML).to_dict()
    assert data["ml_analysis"] == ML
    assert ScanReport(**data).ml_analysis == ML  # the exact call app.py makes at /report


def test_old_session_data_without_ml_analysis_still_loads():
    data = ScanReport(url="https://example.com", success=True).to_dict()
    del data["ml_analysis"]
    assert ScanReport(**data).ml_analysis is None


def test_ml_analysis_never_changes_the_rule_based_verdict():
    plain = ScanReport(url="https://example.com", success=True)
    flagged = ScanReport(url="https://example.com", success=True, ml_analysis=ML)
    assert plain.get_verdict() == flagged.get_verdict()


def test_ml_is_off_by_default():
    assert SecurityScanner().enable_ml is False
    assert SecurityScanner(enable_ml=True).enable_ml is True


def test_importing_the_scanner_does_not_load_torch():
    code = "import sys; import scanner.core; print('torch' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=PROJECT_ROOT)
    assert out.stdout.strip() == "False", out.stderr[-300:]


PAGE = b"<html><head><title>T</title></head><body>hi</body></html>"


class FakeResponse:
    def __init__(self, content=PAGE, status_code=200, content_type="text/html"):
        self.content = content
        self.status_code = status_code
        self.headers = {"Content-Type": content_type}
        self.url = "https://example.com/"


@pytest.fixture
def quiet_scanner(monkeypatch):
    """No network: robots, the online checks and the domain checks are stubbed out."""
    monkeypatch.setattr(core, "scan_check", lambda url, session: True)
    monkeypatch.setattr(SecurityScanner, "_run_online_checks", lambda self, report, response, soup: None)
    monkeypatch.setattr(SecurityScanner, "_run_domain_checks", lambda self, report, domain, title: None)
    monkeypatch.setattr(SecurityScanner, "_run_domain_checks_only", lambda self, report, domain, url: None)


def test_scan_hands_the_fetched_page_to_the_advisory_when_enabled(monkeypatch, quiet_scanner):
    calls = []
    monkeypatch.setattr(core, "fetch_url", lambda session, url, **kw: FakeResponse())
    monkeypatch.setattr(core, "run_ml_advisory", lambda content, status, ctype: calls.append((content, status, ctype)) or ML)

    report = SecurityScanner(enable_ml=True).scan("https://example.com")

    assert report.success is True
    assert report.ml_analysis == ML
    assert calls == [(PAGE, 200, "text/html")]  # the bytes the scanner already fetched, no second request


def test_scan_does_not_call_the_advisory_by_default(monkeypatch, quiet_scanner):
    calls = []
    monkeypatch.setattr(core, "fetch_url", lambda session, url, **kw: FakeResponse())
    monkeypatch.setattr(core, "run_ml_advisory", lambda *args: calls.append(args) or ML)

    report = SecurityScanner().scan("https://example.com")

    assert report.success is True
    assert report.ml_analysis is None
    assert calls == []


def test_unreachable_site_gets_no_ml_analysis(monkeypatch, quiet_scanner):
    calls = []
    monkeypatch.setattr(core, "fetch_url", lambda session, url, **kw: None)
    monkeypatch.setattr(core, "run_ml_advisory", lambda *args: calls.append(args) or ML)

    report = SecurityScanner(enable_ml=True).scan("https://example.com")

    assert report.success is False
    assert report.ml_analysis is None
    assert calls == []


def test_domain_checks_still_run_when_the_main_scan_fails(monkeypatch):
    calls = []

    def explode(self, report, response, soup):
        raise RuntimeError("parse failed")

    monkeypatch.setattr(core, "scan_check", lambda url, session: True)
    monkeypatch.setattr(core, "fetch_url", lambda session, url, **kw: FakeResponse())
    monkeypatch.setattr(SecurityScanner, "_run_online_checks", explode)
    monkeypatch.setattr(SecurityScanner, "_run_domain_checks_only", lambda self, report, domain, url: calls.append(domain))

    report = SecurityScanner().scan("https://example.com")

    assert report.success is False
    assert "parse failed" in report.error
    assert calls == ["example.com"]  # the fallback must run
