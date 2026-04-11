from bs4 import BeautifulSoup
import ssl
import socket
from typing import Dict, Any
from urllib.parse import urlparse, urljoin

def check_https_final(url: str, response) -> Dict[str, Any]:
    final_url = response.url
    final_scheme = urlparse(final_url).scheme
    return {
        "https_enforced": final_scheme == "https",
        "redirected_to_https": urlparse(url).scheme == "http" and final_scheme == "https"
    }

def check_ssl(domain: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssocks:
                cert = ssocks.getpeercert()
                issuer = "Unknown"
                for item in cert.get('issuer', []):
                    if isinstance(item, tuple) and len(item) == 2:
                        key, value = item
                        if key == 'organizationName':
                            issuer = value
                            break

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