import time

import requests

from .netguard import GuardedSession, UnsafeUrlError

MAX_BYTES = 2 * 1024 * 1024       # a larger body is cut off: the scanner reads the first 2 MB
BODY_DEADLINE_SECONDS = 30        # time allowed to read a body (plus at most one read timeout)
MAX_REDIRECTS = 10                # requests' default is 30
CHUNK_SIZE = 16384

_now = time.monotonic             # a module-level name, so tests can replace the clock


def session_get() -> requests.Session:
    session = GuardedSession()
    session.max_redirects = MAX_REDIRECTS
    session.headers.update({
        'User-Agent': 'SecurityScanner/1.0 (Educational)'
    })
    return session


def _read_capped(response, max_bytes, deadline):
    """Read the body in chunks. Stop at the size cap or the deadline. Returns (body, truncated)."""
    body = bytearray()
    truncated = False
    try:
        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
            body.extend(chunk)
            if len(body) > max_bytes:
                truncated = True
                break
            if _now() > deadline:
                truncated = True
                break
    finally:
        response.close()
    return bytes(body[:max_bytes]), truncated


def fetch_url(session, url, timeout=10, allow_redirects=True, verify=False,
              max_bytes=MAX_BYTES, deadline_seconds=BODY_DEADLINE_SECONDS):
    """ verify=False: don't enforce SSL certificate validation
        allow_redirects=True: follow redirects (HTTP 301/302)
        The body is read in chunks and cut off at max_bytes or deadline_seconds; response.truncated says whether
        that happened. Everything else about the response is unchanged."""
    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            stream=True
        )
        body, truncated = _read_capped(response, max_bytes, _now() + deadline_seconds)
        response._content = body
        response._content_consumed = True
        response.truncated = truncated
        if truncated:
            print(f" Response from {url} cut off at {max_bytes} bytes or {deadline_seconds} s")
        return response
    except UnsafeUrlError:
        raise   # a blocked target is not an ordinary fetch failure: let the caller report it
    except requests.exceptions.Timeout:
        print(f" Timeout fetching {url}")
        return None
    except requests.exceptions.ConnectionError:
        print(f" Connection error to {url}")
        return None
    except requests.exceptions.SSLError:
        print(" SSL error occured.")
        return None
    except requests.RequestException as e:
        print(f" Error fetching {url}: {e}")
        return None
