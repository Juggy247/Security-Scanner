from __future__ import annotations

import os
import socket
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import scanner.security as security
from scanner.security import check_ssl


class Stop(Exception):
    pass


@pytest.fixture
def connections(monkeypatch):
    calls = []

    def fake_create_connection(address, timeout=None, **kwargs):
        calls.append(address)
        raise Stop("stop here, no network")

    monkeypatch.setattr(security.socket, "create_connection", fake_create_connection)
    return calls


def answers(*addresses):
    return lambda host, port: list(addresses)


@pytest.mark.parametrize(
    "addresses",
    [["10.0.0.5"], ["127.0.0.1"], ["169.254.169.254"], ["100.64.0.1"], ["8.8.8.8", "10.0.0.5"]],
)
def test_private_answers_are_refused_without_connecting(connections, addresses):
    result = check_ssl("example.test", answers(*addresses))
    assert result["valid"] is False
    assert "private" in result["error"]
    assert connections == []


def test_a_public_answer_connects_to_the_checked_address_not_the_name(connections):
    result = check_ssl("example.test", answers("8.8.8.8", "1.1.1.1"))
    assert connections == [("8.8.8.8", 443)]
    assert result == {"valid": False, "error": "stop here, no network"}


def test_an_unresolvable_host_is_reported_not_raised(connections):
    def gone(host, port):
        raise socket.gaierror(socket.EAI_NONAME, "unknown host")

    result = check_ssl("dead.test", gone)
    assert result["valid"] is False
    assert connections == []


def test_an_empty_answer_is_reported(connections):
    result = check_ssl("example.test", answers())
    assert result == {"valid": False, "error": "Host did not resolve"}
    assert connections == []
