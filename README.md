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
- [Experimental: Text-Similarity Signal](#experimental-text-similarity-signal)
- [Future Plans](#future-plans)
- [Tech Stack](#tech-stack)

---

## Overview

Security Scanner is an educational tool that scans a given URL and returns a verdict — `SAFE`, `POTENTIALLY SUSPICIOUS`, or `SUSPICIOUS` — based on multiple layered security checks. It is designed to mimic the core logic behind real-world phishing detection systems.

The scanner works in two modes:

- **Online mode** — fetches the page and runs full HTTP, SSL, header, and form checks alongside domain checks
- **Offline mode** — if the site is unreachable, it falls back to domain-only checks (WHOIS, TLD, brand impersonation, homograph detection, etc.), which means suspicious domains are still caught even if they are taken down

An optional, experimental text-similarity signal (off by default) can show an advisory card next to the verdict. It never changes the verdict. See [Experimental: Text-Similarity Signal](#experimental-text-similarity-signal).

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
- Blocks scanning of `localhost`, `127.0.0.1`, `::1` and IP addresses given as literals in private, loopback or reserved ranges
- Only allows `http://` and `https://` schemes
- Known limit: hostnames that resolve to private addresses, and redirects to them, are not blocked. Do not expose the app to untrusted users without fixing this.

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
  Optional: text-similarity signal (ENABLE_ML=1, display only, not part of the verdict)
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
│   └── ml_advisory.py          # Adapter between the scanner and ai/
│
├── templates/                  # Jinja2 HTML templates
│   ├── home.html               # Scan form
│   ├── report.html             # Scan results page
│   ├── detailed_report.html
│   ├── _ml_card.html           # Advisory card
│   └── admin/                  # Admin panel templates
│       ├── dashboard.html
│       ├── blacklist_list.html
│       ├── brands_list.html
│       ├── keywords_list.html
│       ├── tlds_list.html
│       └── ...
│
├── ai/                         # Text-similarity pipeline (experimental)
│   ├── fetcher.py, text_processing.py, records.py
│   └── scoring.py, evaluation.py
│
├── app.py                      # Flask application entry point
├── admin_bp.py                 # Admin Blueprint (web admin panel)
├── dataset_schema.py, mongo_dataset.py, dataset_collector.py
├── ingest_phreshphish.py       # Capped sample ingestion from PhreshPhish
├── evaluate_split.py           # Evaluation report per split
├── EXPERIMENTS.md              # Experiment log, results and the pre-registration
├── tests/                      # Unit, integration and ML tests
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

The scanner needs initial data in MongoDB (TLDs, brands, keywords, blacklist). Add entries with the Admin CLI, or import your own JSON file with `python admin_main.py import <file>` (see [Admin CLI](#admin-cli)). A minimal starting set:
```bash
cd scanner
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
| `MONGO_URI` | Currently unused: the code connects to `mongodb://localhost:27017/` directly | `mongodb://localhost:27017/` |
| `ENABLE_ML` | Set to `1` to show the experimental text-similarity card. Needs MongoDB and the reference pages | off |

---

## Running the App

```bash
python app.py
```

The app runs on `http://localhost:5000` by default.

To show the experimental text-similarity card: `ENABLE_ML=1 python app.py`. The first scan builds the reference index (about 6 seconds).

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

`scan_data` also contains `ml_analysis` (`null` when `ENABLE_ML` is off).

Full API documentation is available via Swagger UI at `/apidocs/`.

---

## Test Results

### Manual results (original test harness, since removed; see git history)

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

### Automated tests

| File | Tests | Needs |
|---|---|---|
| `tests/test_units.py` | 61 | nothing external |
| `tests/test_ai_evaluation.py` | 19 | the MiniLM model (downloads once) |
| `tests/test_score_html.py`, `test_ml_advisory.py`, `test_scanner_ml.py`, `test_ml_card.py` | 11, 10, 9, 18 | nothing external (fake encoder) |
| `tests/test_integration.py` | 42 | live sites and MongoDB, slow |

Run with `pytest tests/ -q --ignore=tests/test_integration.py`. The integration tests fetch real websites and were not re-run after the ML change.

---

## Experimental: Text-Similarity Signal

An optional, display-only check that compares a page's text with known phishing and benign pages. It never changes the
rule-based verdict, and it is off by default (`ENABLE_ML=1` turns it on).

### How it works
1. The scanner fetches the page as usual. If ML is on, the same page bytes go to `scanner/ml_advisory.py` (no second request).
2. Text is extracted, and the page is only scored if it has at least 20 words, is English (probability 0.9 or higher) and
   shows no error, parked-domain, challenge or default-page markers.
3. Page chunks and reference chunks are embedded with `all-MiniLM-L6-v2`. A page's score for each class is the mean of its
   three best chunk similarities. The page is flagged if (phishing score minus benign score) is above 0.10.
4. References: 101 phishing and 100 benign pages from the train split of PhreshPhish, stored in MongoDB (`page_records`).

The card says "Flagged: text resembles known phishing pages", "Not flagged" or "Not scored: <reason>". "Not flagged" does not
mean a page is safe.

### Measured results
| | Phishing pages caught | Benign pages flagged |
|---|---|---|
| Held-out test, run once with parameters fixed beforehand (100 + 100 pages) | 42/100 (95% CI 0.33 to 0.52) | 4/100 (95% CI 0.02 to 0.10) |
| Word-count baseline on the same test (fewer than 60 words) | 17/100 | 8/100 |
| Validation, a development set where the threshold was chosen (100 + 100 pages) | 65/100 | 5/100 |

Recall dropped from validation to test. The test pages are later in time (September to December 2025) and their score margins
sit lower, so drift is the likely cause. Tuning optimism, near-duplicate phishing kits on validation and label noise are not
separated from it. The full log, including the failures and the pre-registration, is in `EXPERIMENTS.md`.

### Limitations
- The test set is half phishing. Real traffic contains far less, so most flags would be false alarms.
- Hand-read samples show label noise and scrape failures among the "phishing" pages, and families of near-identical kits.
- English only. Short, non-English, JavaScript-only and error pages are not scored.
- The reference pages were captured with a real browser, while the scanner fetches with `requests`.
- Similarity to a fixed set of references decays as campaigns change. Nothing here updates the references.
- The held-out test split has been used for reported numbers and one diagnostic. It cannot support new claims.
- This is a concept prototype, not a security product.

### Reproduce
```bash
pip install -r requirements.txt            # MongoDB must be running on localhost
python3 ingest_phreshphish.py --role train --phishing 20 --benign-hard 5 --benign-regular 15 --write
python3 ingest_phreshphish.py --role train --append --phishing 81 --benign-hard 20 --benign-regular 60 --max-per-brand 4 --other-cap 12 --write
python3 ingest_phreshphish.py --role validation --phishing 100 --benign-hard 25 --benign-regular 75 --max-per-brand 5 --other-cap 15 --scan-limit 6000 --write
python3 evaluate_split.py --split validation --rule onesided
ENABLE_ML=1 python3 app.py                 # the first scan builds the reference index (about 6 seconds)
```
The ingest streams a capped sample of the dataset and stores each page with its raw HTML in GridFS. Each command is a dry
run until `--write` is added. The test split was read once and should not be read again for new claims. The ingest sequence
above was run as listed, but was not re-run from an empty database for this README.

### Data and citation
Pages come from PhreshPhish (Dalton et al., 2025), dataset `phreshphish/phreshphish` v1.0.1 on Hugging Face, licensed
CC BY 4.0 and intended for anti-phishing research only. No OpenPhish or PhishTank data is included in this repository.

```bibtex
@article{dalton2025phreshphish,
    title        = {PhreshPhish: A Real-World, High-Quality, Large-Scale Phishing Website Dataset and Benchmark},
    author       = {Thomas Dalton and Hemanth Gowda and Girish Rao and Sachin Pargi and Alireza Hadj Khodabakhshi and Joseph Rombs and Stephan Jou and Manish Marwah},
    year         = 2025,
    journal      = {arXiv preprint},
    url          = {https://arxiv.org/abs/2507.10854},
    eprint       = {2507.10854}
}
```

---

## Future Plans

- Refresh and grow the reference set, and re-measure on a new split (similarity to a fixed set decays as campaigns change)
- Close the SSRF gap (resolve hostnames, re-check redirects)
- Package cleanup in `ai/` (lazy torch import, remove the compatibility shim)
- Rewrite the weaker assertions in `tests/test_ai_evaluation.py`

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
| Text similarity (experimental) | sentence-transformers (MiniLM embeddings) |
| Dataset ingestion (experimental) | datasets (ingestion only) |
| Language detection | langdetect |

---

## Requirements

See `requirements.txt`. Install with `pip install -r requirements.txt`.

---

## Disclaimer

<<<<<<< HEAD
This tool is built for **educational purposes**.
=======
This tool is built for **educational purposes**. Always obtain permission before scanning websites you do not own. The scanner respects `robots.txt` by default and includes an optional bypass for research use only. Scanning live malicious sites should be done from an isolated environment, not a personal machine.
>>>>>>> c3bff46 (Update README, AGENT.md and experiment log for the advisory ML signal)

---

*Built with Python 🐍 | [github.com/juggy247](https://github.com/juggy247)*
