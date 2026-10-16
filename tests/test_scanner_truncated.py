from __future__ import annotations

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

import scanner.core as core
from scanner.core import ScanReport, SecurityScanner

PAGE = b"<html><head><title>T</title></head><body>hi</body></html>"


class FakeResponse:
    def __init__(self, truncated=None):
        self.content = PAGE
        self.status_code = 200
        self.headers = {"Content-Type": "text/html"}
        self.url = "https://example.test/"
        if truncated is not None:
            self.truncated = truncated


@pytest.fixture
def quiet(monkeypatch):
    monkeypatch.setattr(core, "scan_check", lambda url, session: True)
    monkeypatch.setattr(SecurityScanner, "_run_online_checks", lambda self, report, response, soup: None)
    monkeypatch.setattr(SecurityScanner, "_run_domain_checks", lambda self, report, domain, title: None)


def test_a_cut_off_page_becomes_a_medium_finding(monkeypatch, quiet):
    monkeypatch.setattr(core, "fetch_url", lambda session, url, **kw: FakeResponse(truncated=True))
    report = SecurityScanner().scan("https://example.test/")
    assert report.response_truncated is True
    verdict = report.get_verdict()
    assert verdict["issue_counts"]["medium"] == 1
    assert verdict["issues"]["medium"][0]["type"] == "Page Larger Than the Scanner Reads"


def test_a_complete_page_has_no_finding(monkeypatch, quiet):
    monkeypatch.setattr(core, "fetch_url", lambda session, url, **kw: FakeResponse(truncated=False))
    report = SecurityScanner().scan("https://example.test/")
    assert report.response_truncated is False
    assert all(i["type"] != "Page Larger Than the Scanner Reads" for i in report.get_verdict()["issues"]["medium"])


def test_responses_without_the_attribute_count_as_complete(monkeypatch, quiet):
    monkeypatch.setattr(core, "fetch_url", lambda session, url, **kw: FakeResponse())
    assert SecurityScanner().scan("https://example.test/").response_truncated is False


def test_the_flag_survives_the_session_round_trip():
    data = ScanReport(url="https://example.test", success=True, response_truncated=True).to_dict()
    assert data["response_truncated"] is True
    assert ScanReport(**data).response_truncated is True


def test_old_session_data_without_the_key_still_loads():
    data = ScanReport(url="https://example.test", success=True).to_dict()
    del data["response_truncated"]
    assert ScanReport(**data).response_truncated is False
