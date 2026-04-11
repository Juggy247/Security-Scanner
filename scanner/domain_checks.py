import whois    #look up domain registration info
from datetime import datetime
from urllib.parse import urlparse # break URL into parts(scheme,domain,path)
from typing import Dict, Any, List, Optional #type hints
import re                       # regular expression to match pattern like "a" = a 
from bs4 import BeautifulSoup   #parse Html to inspect the contents
from .config import MongoDbConfig   #mongo config database
from tldextract import extract


_db_config = None   # to hold a single database connection that can be shared by all functions in the module.

def get_db_config() -> MongoDbConfig:
    """
        create Database connection only once and reuse it everytime after
    """
    global _db_config   #global mean we are using _db_config = None from above
    if _db_config is None:
        _db_config = MongoDbConfig()
    return _db_config

def check_domain_age(domain: str) -> Dict[str, Any]:       #domain: str - type hint argument, Dict[str, Any] type hint for return

    try:
        if domain.startswith('www.'):
            domain = domain[4:]         # slice the string start from index 4 which is after www.

        if ':' in domain:
            domain = domain.split(':')[0] #split the string into list at every ':' and [0] - take index 0 inside list(which is before ':') 
        print(f" Looking up WHOIS for: {domain}")

        w = whois.whois(domain)     #first whois is module and second is function

        creation_date = w.creation_date 
        if isinstance(creation_date, list):     #check if value is a list 
            creation_date = creation_date[0] if creation_date else None
        
        #Handling Missing Date
        if not creation_date:
            print(f"No creation date is found! ")
            return {
                "avaliable": False,
                "error": "Creation Date not found.",
                "note": "Domain may use WHOIS privacy protection."
            }
        
        #Calculating Domain age

        age = datetime.now() - creation_date
        days_old = age.days

        is_new = days_old < 180
        is_very_new = days_old < 30

        print(f"Doamin age: {days_old} days.")

        return {
            "available": True,
            "creation_date": str(creation_date),
            "days_old": days_old,
            "years_old": round(days_old / 365.25, 1),
            "is_new": is_new,
            "is_very_new": is_very_new,
            "age_category": (
                "Very New (High Risk)" if is_very_new
                else "New (Medium Risk)" if is_new
                else "Established (Low Risk)"
            )
        }
    
    except whois.parser.PywhoisError as e:
        print(f"WHOIS parsing error: {str(e)[:50]}")
        return{
            "available": False,
            "error": f"WHOIS parsing error: {str(e)[:100]}",
            "note": "Unable to parse WHOIS data for this domain"
        }
    
    except Exception as e:
        error_msg = str(e)
        print(f"WHOIS lookup failed: {error_msg[:50]}")

    if "time out" in error_msg.lower():
        return {
            "available": False,
            "error": "WHOIS server timeout",
            "note": "Try again or WHOIS server may be temporarily unavailable"
        }
    
    elif "no match" in error_msg.lower():
        return {
            "available": False,
            "error": "Domain not found in WHOIS",
            "note": "Domain may not be registered or uses non-standard WHOIS"
        }

    else:
        return {
            "available": False,
            "error": f"WHOIS lookup failed: {error_msg[:100]}",
            "note": "Check network connection or domain validity"
        }

#Check Domain blacklisted 

def check_blacklist(domain: str) -> Dict[str,Any]:

    try:
        db = get_db_config()
        is_blacklisted = db.is_blacklisted(domain)  #return true

        return {
            "is_blacklisted": is_blacklisted,   
            "blacklist_sources": ["mongo_database"] if is_blacklisted else []
        }
    
    except Exception as e:
        print(f"Blacklist check failed. {e}")
        return {
            "is_blacklisted": False,
            "blacklist_sources": [],
            "error": str(e)             
        }

# Check for homograph attack

def check_homograph_attack(domain: str) -> Dict[str,Any]:
    ## Detects domains using characters that look like other characters to trick users

    suspicious_patterns = []

    lookalike_pairs = {
        'rn': 'm',   # 'rn' looks like 'm'
        'vv': 'w',   # 'vv' looks like 'w'
        'cl': 'd',   # 'cl' looks like 'd'
        '0': 'o',    # Zero looks like letter O
        '1': 'l',    # One looks like letter L
    }   

    for fake, real in lookalike_pairs.items():  #item() access dicts elements
        if fake in domain.lower():
            suspicious_patterns.append(f"Contains '{fake}' (looks like '{real}')")

    has_cyrillic = bool(re.search(r'[а-яА-Я]', domain))  # True if any Cyrillic letters found
    has_latin = bool(re.search(r'[a-zA-Z]', domain))      # # True if any Latin letters found

    if has_cyrillic and has_latin:
        suspicious_patterns.append("Mixed Latin and Cyrillic characters")

    #hyphen check
    hyphen_count = domain.count('-')
    if hyphen_count > 3:
        suspicious_patterns.append(f"Excessive hyphens ({hyphen_count})")

    #Isascii letter check
    if not domain.isascii():
        suspicious_patterns.append("Contains non-ASCII characters ")

    return {
        "is_suspicious": len(suspicious_patterns) > 0,  # True if we found ANY suspicious patterns
        "patterns_found": suspicious_patterns,           # List of all findings
        "domain": domain                                 
    }

#Check if domain name appear in page title

def check_domain_in_title(domain: str, title: str) -> Dict[str,Any]:
    # Checks if the website's <title> tag contains the domain name
    # Mismatch can indicate phishing

    if not title:
        return {
            "domain_in_title": False,
            "reason": "No title found"   # Return early with explanation
        }
    
    domain_parts = domain.split('.')
    main_domain = domain_parts[0] if len(domain_parts) > 1 else domain 

    if main_domain in ['www', 'www2', 'mail', 'ftp', 'webmail']:
        # If first part is a generic subdomain like the list array, use the second part instead
        main_domain = domain_parts[1] if len(domain_parts) > 2 else domain 
    
    domain_in_title = main_domain.lower() in title.lower()

    return {
        "domain_in_title": domain_in_title,   # True or False
        "domain_checked": main_domain,         # Which part of domain was checked
        "title": title        
    }

#check if form submit to external domain(redirect)
def check_form_redirects(soup: BeautifulSoup, base_url: str) -> List[Dict[str,Any]]:
    # Scans all HTML forms on the page

    from urllib.parse import urljoin #import locally (but probably bad idea)

    base_domain = urlparse(base_url).netloc
    #extract domain from full base url 
    #netloc -  filter domain name like ("google.com")

    forms = soup.find_all('form')   #Check <form> element in html
    suspicious_forms = []

    for i, form in enumerate(forms):
        action = form.get('action', '') #action attribute redirect)

        method = form.get('method', 'get').upper()  #request protocols like GET POST

        action_url = urljoin(base_url, action )
        action_domain = urlparse(action_url).netloc #to check if redirect has same domain name

        if action_domain and action_domain != base_domain:

            suspicious_forms.append({           # ...add this form to our suspicious list
                "form_index": i,                # Which form on the page (0 = first)
                "method": method,               
                "action": action_url,           # Full URL the form submits to
                "redirects_external": True,     # Flag that confirms external redirect
                "external_domain": action_domain,  # The suspicious external domain
                "base_domain": base_domain         
            })
    return suspicious_forms

#Check domain name length

def check_domain_length(domain: str) -> Dict[str,Any]:

    domain_without_tld = '.'.join(domain.split('.')[:-1])
    # Split by dots → remove last part (TLD) → rejoin remaining parts
    # Example: 'secure-paypal-login.com' → ['secure-paypal-login', 'com'] → [:-1] → 'secure-paypal-login'
    # [:-1] - python slicing 

    length = len(domain_without_tld) 

    if length > 40:              # Very long domains are almost always suspicious
        risk_level = "very_high"
        is_suspicious = True
    elif length > 30:            # Long domains are often suspicious
        risk_level = "high"
        is_suspicious = True
    elif length > 20:            # Medium length — worth noting but not alarming
        risk_level = "medium"
        is_suspicious = False
    else:                        # Short domain — normal and low risk
        risk_level = "low"
        is_suspicious = False

    return {
        "length": length,                       # Length without TLD
        "full_domain_length": len(domain),      # Total length including TLD
        "is_suspicious": is_suspicious,         # Boolean risk flag
        "risk_level": risk_level                # String: 'low', 'medium', 'high', 'very_high'
    }


# Check for Suspicious top level domain 

def check_suspicious_tld(domain: str) -> Dict[str, Any]:
    # Checks if the domain uses a TLD commonly associated with phishing (.xyz, .tk, .top, etc.)

    tld = domain.split('.')[-1].lower()
    # Split by dots, take the LAST part ([-1] = last item), lowercase it

    try: 
        db = get_db_config()
        suspicious_tlds = db.get_suspicious_tlds()
        
        is_suspicious = tld in suspicious_tlds

        details = None
        if is_suspicious:
            details = db.get_tld_details(tld)

        return {
            "tld": tld,                                           # The TLD that was checked
            "is_suspicious": is_suspicious,                       # True or False
            "reason": details.get('reason') if details else None, # Why it's suspicious (if available)
            "risk_level": details.get('risk_level') if details else None  # Risk level (if available)
        }
    
    except Exception as e:
        print(f"TLD check failed: {e}")

        return {
            "tld": tld,
            "is_suspicious": False,  
            "error": str(e)
        }

#Check subdomain depth 

def check_subdomain_depth(domain: str) -> Dict[str,Any]:
     # Counts how many levels of subdomains are stacked

     parts = domain.split(".")

     depth = len(parts) - 2 #Subtract 2 to exclude the main domain and TLD

     is_suspicious = depth > 2

     return {
            "depth": depth,             # Number of subdomain levels
            "parts": parts,             # All parts of the domain as a list
            "is_suspicious": is_suspicious,  # Boolean risk flag
            "full_domain": domain       # The original domain that was checked
    }

#Check for Brand impersonation

def check_brand_impersonation(domain: str) -> Dict[str, Any]:
    # Detects if a domain pretends to be a known brand

    try: 
        domain_lower = domain.lower()

        db = get_db_config()

        brands = db.get_brands()
        #ext = extract(domain_lower)
        #sld = ext.domain 
        #found_brands = [b for b in brands if b == sld or b in sld]
        domain_parts = domain_lower.replace('-',' ').replace('.',' ').split()
        found_brands = [b for b in brands if any(b in part for part in  domain_parts)]

        if not found_brands:
            return {
                "potential_impersonation": False
            }

        keywords = db.get_suspicious_keywords()
        found_suspicious = [kw for kw in keywords if kw in domain_lower]
        # keeps keywords that appear in the domain

        potential_impersonation = len(found_brands) > 0 and len(found_suspicious) > 0
        #flag as impersonation if BOTH a brand AND a suspicious keyword are present

        return {
            "potential_impersonation": potential_impersonation,         # True or False
            "suspected_brand": found_brands[0] if found_brands else None,  # First matched brand
            "suspicious_keywords": found_suspicious,                    # All matched keywords
            "domain": domain                                            # Original domain checked
        }
    
    except Exception as e:
        print(f"Brand impersonation check failed: {e}")   # Log the error
        return {
            "potential_impersonation": False,   # Fail safe — assume not impersonation
            "error": str(e)
        }


def close_db_connection():

    global _db_config
    if _db_config is not None:
        _db_config.close()
        _db_config = None
        print("MongoDB connection closed")