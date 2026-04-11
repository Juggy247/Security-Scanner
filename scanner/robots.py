from urllib.robotparser import RobotFileParser
from urllib.parse import urlparse, urljoin
import requests
from .utils import fetch_url

def scan_check(url: str, session: requests.Session) -> bool:
    """
        To check if the scanning is allowed or not
    """
    parsed_url = urlparse(url)
    robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"

    try:
        rp = RobotFileParser()
        response = fetch_url(session,robots_url, timeout=5, allow_redirects=True)

        if response and response.status_code == 200:
            rp.parse(response.text.splitlines())
        else:

            """ getattr(response, 'status_code', 'No response'): 
                Gets status code if response exists, otherwise "No response"
                Default to allowing the scan (polite assumption: if no robots.txt, scanning is okay)
                Return True """
            
            print(f"robots.txt not found ({getattr(response, 'status_code', 'No response')}) -> allowing scan")
    except Exception as e:
        print(f"robot.txt check failed ({e}) -> allowing scan")
        return True
    
    allowed = rp.can_fetch('*', url)    # "*" means "any bot"
    print(f"robots.txt: {'ALLOW' if allowed else 'DISALLOW'}")
    return allowed