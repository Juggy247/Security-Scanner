from __future__ import annotations

import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import scanner.core as core
from scanner.core import SecurityScanner


class Stop(BaseException):
    """Not an Exception: stands in for KeyboardInterrupt or SystemExit."""


@pytest.fixture
def offline(monkeypatch):
    """No network: the page fetch fails, so scan() returns right after the robots step."""
    monkeypatch.setattr(core, "fetch_url", lambda session, url, **kw: None)
    monkeypatch.setattr(SecurityScanner, "_run_domain_checks_only", lambda self, report, domain, url: None)


def test_a_failing_robots_check_defaults_to_allowed(monkeypatch, offline):
    def broken(url, session):
        raise RuntimeError("robots lookup broke")

    monkeypatch.setattr(core, "scan_check", broken)
    report = SecurityScanner().scan("https://example.test/")
    assert report.robots_allowed is True
    assert report.robots_bypassed is False
    assert "Failed to fetch URL" in report.error       # the scan carried on to the page fetch


def test_interrupts_are_not_swallowed_by_the_robots_check(monkeypatch, offline):
    def interrupted(url, session):
        raise Stop()

    monkeypatch.setattr(core, "scan_check", interrupted)
    with pytest.raises(Stop):
        SecurityScanner().scan("https://example.test/")


def test_disallowed_robots_are_bypassed_by_default(monkeypatch, offline):
    monkeypatch.setattr(core, "scan_check", lambda url, session: False)
    report = SecurityScanner().scan("https://example.test/")
    assert report.robots_allowed is False
    assert report.robots_bypassed is True


def test_disallowed_robots_stop_the_scan_when_bypass_is_off(monkeypatch, offline):
    monkeypatch.setattr(core, "scan_check", lambda url, session: False)
    report = SecurityScanner(bypass_robots=False).scan("https://example.test/")
    assert report.error == "Scanning not allowed by robots.txt"
    assert report.success is False
