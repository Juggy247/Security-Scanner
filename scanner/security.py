from bs4 import BeautifulSoup
import ssl
import socket
from typing import Dict, Any
from urllib.parse import urlparse, urljoin

from .netguard import PRIVATE_MESSAGE, default_resolver, is_public_address

def check_https_final(url: str, response) -> Dict[str, Any]:
    final_url = response.url
    final_scheme = urlparse(final_url).scheme
    return {
        "https_enforced": final_scheme == "https",
        "redirected_to_https": urlparse(url).scheme == "http" and final_scheme == "https"
    }

def _issuer_name(cert: dict) -> str:
    """The issuer's organisation name, falling back to the common name. getpeercert() returns the issuer as a
    sequence of relative distinguished names, each a tuple of (key, value) pairs."""
    fields = {}
    for rdn in cert.get('issuer', ()):
        for item in rdn:
            if isinstance(item, tuple) and len(item) == 2:
                fields.setdefault(item[0], item[1])
    return fields.get('organizationName') or fields.get('commonName') or "Unknown"


def check_ssl(domain: str, resolver=default_resolver) -> dict:
    try:
        addresses = resolver(domain, 443)
        if not addresses:
            return {"valid": False, "error": "Host did not resolve"}
        if any(not is_public_address(address) for address in addresses):
            return {"valid": False, "error": PRIVATE_MESSAGE}

        context = ssl.create_default_context()
        # Connect to the address that was just checked, not to the name: the name could resolve differently a second time.
        with socket.create_connection((addresses[0], 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssocks:
                cert = ssocks.getpeercert()
                issuer = _issuer_name(cert)

                return {
                    "valid": True,
                    "expires": cert.get('notAfter'),
                    "issuer": issuer
                }
    except Exception as e:
        return {
            "valid": False,
            "error": str(e)
        }
    
def check_headers(response) -> dict:
    headers = response.headers

    important = [
        'Strict-Transport-Security',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Content-Security-Policy',
        'Referrer-Policy'
    ]

    present = [h for h in important if h in headers]
    missing = [h for h in important if h not in headers]

    return {"present": present, "missing": missing}

def check_forms(soup: BeautifulSoup, base_url: str) -> list:
    forms = soup.find_all('form')
    issues = []
    page_scheme = urlparse(base_url).scheme

    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'get').upper()
        action_url = urljoin(base_url, action)
        action_scheme = urlparse(action_url).scheme
        if method == 'POST':
            if page_scheme != 'https':
                reason = "from on  HTTP Page"
            elif action_scheme != 'https':
                reason = "action over HTTP"
            else:
                continue
            issues.append({
                "type": "insecure_post",
                "action": action_url,
                "reason":reason
            })

    return issues