"""Network guard: refuse to fetch URLs that point at private, loopback or link-local addresses.

The hostname is resolved with the OS resolver and every returned address is checked, so alternative spellings of an
address (decimal, hex) are judged by what they resolve to, not by how they are written. URLs are parsed with urllib3's
parser, the one requests uses to connect, so the host that is checked is the host that is contacted.

Known limit: the check and the connection resolve the name separately (DNS rebinding). Run the app where internal
services are not reachable.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Callable, List, Tuple

import requests
from urllib3.exceptions import LocationParseError
from urllib3.util import parse_url

Resolver = Callable[[str, int], List[str]]

PRIVATE_MESSAGE = "Scanning private or internal addresses is not allowed"


class UnsafeUrlError(requests.exceptions.RequestException):
    """Raised before connecting when a URL, or a redirect hop, points at a non-public address."""


def default_resolver(host: str, port: int) -> List[str]:
    return [info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]


def is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])   # drop an IPv6 zone id such as fe80::1%en0
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped                                # ::ffff:127.0.0.1 is judged as 127.0.0.1
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False
    return ip.is_global                                    # also rejects shared space such as 100.64.0.0/10


def check_public_url(url: str, resolver: Resolver = default_resolver) -> Tuple[bool, str]:
    """Return (allowed, reason). Unresolvable names are allowed: there is nothing to connect to, and the scanner
    still analyses the domain itself. Anything else that cannot be checked is refused."""
    try:
        parsed = parse_url(url)
    except LocationParseError:
        return False, "Invalid URL"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, "Only HTTP and HTTPS URLs are allowed"

    host = (parsed.host or "").strip("[]").rstrip(".").lower()
    if not host:
        return False, "Invalid URL"
    if host == "localhost" or host.endswith(".localhost"):
        return False, "Scanning localhost is not allowed"

    port = parsed.port or (443 if scheme == "https" else 80)

    try:
        ipaddress.ip_address(host)
        addresses = [host]                                  # an IP literal needs no lookup
    except ValueError:
        try:
            addresses = resolver(host, port)
        except socket.gaierror:
            return True, "unresolved"
        except Exception as exc:
            return False, f"Could not check host: {type(exc).__name__}"

    if not addresses:
        return True, "unresolved"
    try:
        if all(is_public_address(address) for address in addresses):   # one private answer blocks the URL
            return True, ""
    except ValueError:
        return False, "Could not check host: invalid address"
    return False, PRIVATE_MESSAGE


class GuardedSession(requests.Session):
    """A Session that checks every request, redirect hops included, before connecting."""

    def __init__(self, resolver: Resolver = default_resolver):
        super().__init__()
        self._resolver = resolver

    def send(self, request, **kwargs):
        allowed, reason = check_public_url(request.url, self._resolver)
        if not allowed:
            raise UnsafeUrlError(f"{reason}: {request.url}")
        return super().send(request, **kwargs)


def is_safe_url(url: str, resolver: Resolver = default_resolver) -> Tuple[bool, str]:
    """(allowed, reason) for callers that only need a yes or no. The reason is empty when the URL is allowed."""
    allowed, reason = check_public_url(url, resolver)
    return allowed, ("" if allowed else reason)
