# 🔒 Security Scanner

A web-based phishing and security scanner built with Python and Flask. It analyzes URLs using a combination of real-time HTTP checks and domain-level heuristics to detect suspicious or malicious websites — even when the target site is offline.

[github.com/juggy247](https://github.com/juggy247)

---

## 📌 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the App](#running-the-app)
- [Admin CLI](#admin-cli)
- [API Reference](#api-reference)
- [Test Results](#test-results)
- [Future Plans](#future-plans)
- [Tech Stack](#tech-stack)

---

## Overview

Security Scanner is an educational tool that scans a given URL and returns a verdict — `SAFE`, `POTENTIALLY SUSPICIOUS`, or `SUSPICIOUS` — based on multiple layered security checks. It is designed to mimic the core logic behind real-world phishing detection systems.

The scanner works in two modes:

- **Online mode** — fetches the page and runs full HTTP, SSL, header, and form checks alongside domain checks
- **Offline mode** — if the site is unreachable, it falls back to domain-only checks (WHOIS, TLD, brand impersonation, homograph detection, etc.), which means suspicious domains are still caught even if they are taken down

---

## Features

### 🌐 Online Checks (requires site to be reachable)
- **HTTPS enforcement** — detects if site runs on HTTP only
- **SSL certificate validation** — checks validity, expiry, and issuer
- **Security headers analysis** — checks for `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`
- **Insecure form detection** — flags POST forms submitted over HTTP
- **External form redirect detection** — detects forms that submit data to external domains

### 🔍 Domain Checks (work even when site is offline)
- **WHOIS domain age** — flags newly registered domains (under 180 days)
- **Blacklist lookup** — checks domain against a MongoDB blacklist database
- **Homograph attack detection** — detects lookalike characters (`0` vs `o`, `rn` vs `m`, Cyrillic mixed with Latin)
- **Brand impersonation** — checks if the domain contains known brand names combined with suspicious keywords
- **Suspicious TLD detection** — flags high-risk TLDs (`.tk`, `.ml`, `.cf`, `.xyz`, etc.)
- **Domain length analysis** — unusually long domains are a common phishing indicator
- **Subdomain depth analysis** — deep nesting like `login.secure.paypal.verify.com` is flagged
- **Domain vs page title mismatch** — detects when the domain name doesn't appear in the page title

### 🛡️ SSRF Protection
- Blocks scanning of `localhost`, `127.0.0.1`, `::1`
- Blocks private IP ranges (`192.168.x.x`, `10.x.x.x`, etc.)
- Only allows `http://` and `https://` schemes

### 📊 Verdict System
Issues are categorized by severity and combined into a final verdict:

| Verdict | Condition |
|---|---|
| `SUSPICIOUS` | Any critical issue, or 2+ high issues |
| `POTENTIALLY SUSPICIOUS` | 1 high issue, or 3+ medium issues |
| `SAFE (with minor issues)` | Only medium/low issues |
| `SAFE` | No issues detected |

---

## How It Works

```
User submits URL
       │
       ▼
 SSRF Validation
       │
       ▼
 robots.txt Check ──► Bypass if enabled
       │
       ▼
 Fetch Page (timeout 15s)
       │
  ┌────┴────┐
Online    Offline
  │           │
  ▼           ▼
HTTP checks  Domain-only checks
SSL checks
Header checks
Form checks
  │
  └────┬────┘
       │
       ▼
  Domain Checks (both paths)
  WHOIS / Blacklist / Homograph
  TLD / Brand / Length / Subdomain
       │
       ▼
  Issue Collection & Scoring
       │
       ▼
  Verdict Generation
```

---

## Project Structure

```
Security_Scanner/
├── scanner/                    # Core backend package
│   ├── __init__.py
│   ├── core.py                 # SecurityScanner + ScanReport (main orchestrator)
│   ├── security.py             # HTTPS, SSL, headers, forms checks
│   ├── domain_checks.py        # WHOIS, blacklist, homograph, TLD, brand checks
│   ├── robots.py               # robots.txt compliance check
│   ├── config.py               # MongoDB configuration and data access
│   ├── utils.py                # Shared HTTP session and fetch utilities
│   ├── admin.py                # AdminCLI class for database management
│   ├── admin_main.py           # CLI entry point (argparse)
│   └── test_scanner.py         # Test suite with predefined test cases
│
├── templates/                  # Jinja2 HTML templates
│   ├── home.html               # Scan form
│   ├── report.html             # Scan results page
│   ├── detailed_report.html
│   └── admin/                  # Admin panel templates
│       ├── dashboard.html
│       ├── blacklist_list.html
│       ├── brands_list.html
│       ├── keywords_list.html
│       ├── tlds_list.html
│       └── ...
│
├── app.py                      # Flask application entry point
├── admin_bp.py                 # Admin Blueprint (web admin panel)
├── requirements.txt
├── .env                        # Environment variables (not committed)
├── .gitignore
└── README.md
```

---

## Installation

### Prerequisites
- Python 3.11+
- MongoDB running locally on port `27017`
- `pip` and `venv`

### Steps

**1. Clone the repository**
```bash
git clone https://github.com/juggy247/Security_Scanner.git
cd Security_Scanner
```

**2. Create and activate a virtual environment**
```bash
python -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Set up environment variables**

Create a `.env` file in the project root:
```
SECRET_KEY=your-random-secret-key-here
MONGO_URI=mongodb://localhost:27017/
```

To generate a secure secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

**5. Make sure MongoDB is running**
```bash
# macOS with Homebrew
brew services start mongodb-community

# Linux
sudo systemctl start mongod
```

**6. Seed the database**

The scanner requires initial data in MongoDB to function correctly. Use the Admin CLI to import your seed data:
```bash
cd scanner
python admin_main.py import ../test/test.json
```

Or add entries manually:
```bash
python admin_main.py add-tld tk --risk high --reason "Common phishing TLD"
python admin_main.py add-tld ml --risk high --reason "Free TLD used in phishing"
python admin_main.py add-brand paypal --category financial
python admin_main.py add-brand microsoft --category technology
python admin_main.py add-keyword verify --category action_words
python admin_main.py add-keyword secure --category action_words
python admin_main.py add-keyword login --category action_words
```

---

## Configuration

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | Flask session secret key | Required |
| `MONGO_URI` | MongoDB connection string | `mongodb://localhost:27017/` |

---

## Running the App

```bash
python app.py
```

The app runs on `http://localhost:5000` by default.

- **Home / Scan form** → `http://localhost:5000/`
- **Scan report** → `http://localhost:5000/report`
- **API docs (Swagger)** → `http://localhost:5000/apidocs/`
- **Admin panel** → `http://localhost:5000/admin/`

---

## Admin CLI

The scanner includes a command-line tool for managing the MongoDB database directly.

```bash
cd scanner
python admin_main.py --help
```

### Available Commands

**TLDs**
```bash
python admin_main.py add-tld tk --risk high --reason "Common phishing TLD"
python admin_main.py list-tlds
python admin_main.py update-tld tk --risk critical
python admin_main.py deactivate-tld tk
python admin_main.py remove-tld tk
```

**Brands**
```bash
python admin_main.py add-brand paypal --category financial
python admin_main.py list-brands
python admin_main.py remove-brand paypal
```

**Blacklist**
```bash
python admin_main.py add-blacklist evil-site.com --reason "Known phishing site"
python admin_main.py list-blacklist
python admin_main.py search-blacklist paypal
python admin_main.py remove-blacklist evil-site.com
```

**Keywords**
```bash
python admin_main.py add-keyword verify --category action_words --risk medium
python admin_main.py list-keywords
python admin_main.py remove-keyword verify
```

**Data Management**
```bash
python admin_main.py stats
python admin_main.py export data/backup.json
python admin_main.py import data/threats.json
```

---

## API Reference

### `POST /api/scan`

Scan a URL and return a JSON verdict.

**Request**
```json
{
  "url": "https://example.com"
}
```

**Response**
```json
{
  "url": "https://example.com",
  "verdict": {
    "verdict": "SAFE",
    "verdict_emoji": "✅",
    "verdict_message": "This website appears to be legitimate and secure",
    "total_issues": 1,
    "issue_counts": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 1
    },
    "issues": {
      "critical": [],
      "high": [],
      "medium": [],
      "low": [
        {
          "type": "Missing Security Headers",
          "description": "Missing 1 security header(s): Referrer-Policy",
          "risk": "Reduced protection against attacks"
        }
      ]
    }
  },
  "scan_data": { ... }
}
```

Full API documentation is available via Swagger UI at `/apidocs/`.

---

## Test Results

The scanner was tested against a range of legitimate sites, phishing patterns, and edge cases:

| URL | Expected | Result | Status |
|---|---|---|---|
| `https://www.google.com` | SAFE | SAFE (minor) | ✅ |
| `https://github.com` | SAFE | SAFE | ✅ |
| `https://www.amazon.com` | SAFE | SAFE (minor) | ✅ |
| `http://paypal-secure-verify-account.ml` | SUSPICIOUS | SUSPICIOUS | ✅ |
| `http://amaz0n-security-alert.cf` | SUSPICIOUS | SUSPICIOUS | ✅ |
| `http://microsoft-login-verify.tk` | SUSPICIOUS | SUSPICIOUS | ✅ |
| `https://login.secure.paypal.verify.com` | SUSPICIOUS | SUSPICIOUS | ✅ |
| `http://evil-phishing-site.com` (blacklisted) | SUSPICIOUS | SUSPICIOUS | ✅ |
| `http://example.com` (HTTP only) | SUSPICIOUS | SUSPICIOUS | ✅ |

### Sample Output — Phishing Detection
```
URL: http://paypal-secure-verify-account.ml
Verdict: SUSPICIOUS

[HIGH] Potential Brand Impersonation: Domain contains 'paypal'
       with suspicious keywords: verify, secure, account
[HIGH] Suspicious TLD: Domain uses high-risk TLD: .ml
[MEDIUM] Domain Age Unknown: Cannot verify when domain was registered
[MEDIUM] Website Offline or Unreachable: Cannot connect to this website
```

---

## Future Plans

### ML-Based Content Similarity Detection

The next major feature planned is a machine learning layer that analyzes the **text content** of a webpage — not just its URL or domain — to detect phishing based on semantic similarity.

The concept: phishing websites often share patterns in their wording and content structure that are distinct from legitimate sites. By computing **sentence embeddings** (using `sentence-transformers` / SBERT) of page text and comparing them against a labeled dataset of known phishing and legitimate pages, the scanner can make a content-aware judgment.

**Planned approach:**
1. Collect and label ~200 phishing and ~200 legitimate website text samples
2. Compute embeddings using a pretrained SBERT model
3. Store embeddings in MongoDB
4. At scan time, compute the embedding of the target page and find its nearest neighbors in the database using cosine similarity
5. Return a similarity-based risk score alongside the existing rule-based verdict

This approach is inspired by real-world semantic search and anomaly detection systems and would make the scanner significantly more robust against novel phishing sites that don't match known patterns.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, Flask |
| Database | MongoDB (via PyMongo) |
| HTTP | requests, urllib3 |
| HTML Parsing | BeautifulSoup4 |
| Domain Analysis | python-whois, tldextract, dnspython |
| SSL | Python ssl, socket |
| API Docs | Flasgger (Swagger UI) |
| Frontend | Jinja2, HTML/CSS |

---

## Requirements

```
flask==3.0.0
beautifulsoup4==4.12.2
requests==2.31.0
pymongo==4.6.0
dnspython==2.4.2
python-whois==0.8.0
flask-limiter==3.5.0
flask-cors==4.0.0
flasgger==0.9.7.1
tldextract
python-dotenv
tabulate
```

---

## Disclaimer

This tool is built for **educational purposes**.

---

*Built with Python 🐍 | [github.com/juggy247](https://github.com/juggy247)*
