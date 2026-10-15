import requests

from .netguard import GuardedSession, UnsafeUrlError


def session_get() -> requests.Session:
    session = GuardedSession()
    session.headers.update({
        'User-Agent': 'SecurityScanner/1.0 (Educational)'
    })
    return session

def fetch_url(session, url, timeout=10, allow_redirects = True, verify=False):
        """ verify=False: don’t enforce SSL certificate validation 
            allow_redirects=True: follow redirects (HTTP 301/302)    """
        
        try: 
            response = session.get(
                 url,
                 timeout=timeout,
                 allow_redirects=allow_redirects,
                 verify=verify
            )
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
            