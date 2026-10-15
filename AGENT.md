# AGENT.md

Portfolio project: a rule-based website scanner (`scanner/`, Flask `app.py`) plus an AI text-similarity module (`ai/`) that
compares a page's text to known phishing and benign pages. It is a concept prototype, not a production security product.

## Role: collaborator (propose, do not write)

The owner applies all changes and runs the tests. The assistant:
- does not create, edit, rename, move or delete files (including tests, config, docs and this file)
- does not write to MongoDB or GridFS, does not run scripts that write to the database or fetch live URLs
- does not install or upgrade dependencies
- treats "just fix it" as a request to show the code in chat

The assistant may read any file, run read-only commands (grep, sed -n, ls, git diff, git log, find, pip list), run read-only
MongoDB queries, and run pytest on the owner's request.

How to propose changes: one file at a time, say where in the file, show complete code for the changed function, explain
why in a few sentences, give a check with the expected output labelled as an expectation. Compare the owner's pasted
output with the expectation and say plainly where it differs. Do not guess about files that were not shown. One step at a
time: wait for the owner's output before continuing.

## Data and safety rules

- Records with source `synthetic_test` and the pipeline-check pages are test data and never appear in reported numbers.
- Never open stored phishing HTML in a browser. Stored pages are parsed as text only.
- Reports in `reports/` contain counts and settings only: no page text, URLs, hashes or domains. `reports/` is git-ignored.
- Do not commit or publish OpenPhish or PhishTank data (OpenPhish terms forbid sharing). `images/training_urls.csv` and
  `DataCollections/` are git-ignored for this reason.
- Live phishing URLs are fetched only from an isolated VM or container on a clean network. The scanner visits any URL a
  user submits, so demos with real phishing URLs belong in such an environment too.
- PhreshPhish is CC BY 4.0 and "only for anti-phishing research". Cite arXiv 2507.10854 and the dataset in the README.

## Layout

| Path | Role |
|---|---|
| `scanner/`, `app.py`, `admin_bp.py`, `templates/` | The rule-based scanner (Phase 1, done) |
| `ai/fetcher.py` | `fetch()` returns a `FetchResult` (streamed, 2 MB cap, 5 redirects, 30 s deadline, error codes). `fetch_page()` is a tuple wrapper kept for old callers |
| `ai/text_processing.py` | Cleaning, hashing, language detection, HTML extraction (extractor v3), quality flags, chunking (180 words, 30 overlap) |
| `ai/records.py` | Builds a `PageRecord` from a URL or supplied HTML and applies the gates |
| `ai/scoring.py` | Lazy MiniLM model (with a lock), reference index, scoring, verdict rules, `score_html`, `get_reference_index` |
| `ai/evaluation.py` | Metrics, sweeps, Wilson intervals, baseline, near-duplicates |
| `ai/__init__.py` | Empty by design (docstring only). Import from the submodules |
| `dataset_collector.py` | Collection CLI (CSV input) |
| `dataset_schema.py` | Record dataclasses, schema version 4, allowed label sources |
| `mongo_dataset.py` | `PageRecordStore` (MongoDB, GridFS raw HTML, `find_references`, `find_examples`) |
| `ingest_phreshphish.py` | Capped sample ingestion from PhreshPhish, dry run by default |
| `evaluate_split.py` | Evaluation report per split. The test split needs `--final` and fixed parameters |
| `EXPERIMENTS.md` | Log of every experiment, including failures, and the pre-registration |
| `scanner/ml_advisory.py` | Adapter: `run_ml_advisory(content, status_code, content_type)` scores page bytes the scanner already fetched. Never raises. Imports `ai` lazily |
| `templates/_ml_card.html` | Advisory card, included from `report.html`. Renders nothing when `ml_analysis` is None. Hardcodes the test numbers (recall 42%, false-positive rate 4%) |
| `tests/` | `test_ai_evaluation.py` (7), `test_ai_metrics.py` (15, pure functions, exact counts), `test_ai_scores.py` (7, fake encoder), `test_ai_imports.py` (3), `test_score_html.py` (11), `test_ml_advisory.py` (10), `test_scanner_ml.py` (9), `test_ml_card.py` (18), `test_units.py` (61), `test_integration.py` (42, live sites). 141 tests without `test_integration.py`, 183 with it. Assertions in the new test files were mutation-checked: a temporary change to the code was tried and the matching test failed (not every test, and the runs are not recorded in git) |
| `ML/`, `models/`, `DataCollections/`, `train_ml_model.py`, `test_ml_detector.py` | Legacy ML plan. Nothing in `app.py`, `scanner/` or the tests imports it. The two scripts import a missing `scanner.ml_detector` |

## Data (MongoDB `security_scanner.page_records`, schema version 4)

Source: PhreshPhish v1.0.1 (Hugging Face `phreshphish/phreshphish`). Our `split` field is the role of a record. The
dataset's own split is kept in `origin.split`.

| Our split | Phishing ready | Benign ready | Rejected (phishing / benign) |
|---|---|---|---|
| train (references) | 101 | 100 | 50 / 14 |
| validation (development set) | 100 | 100 | 30 / 7 |
| test (dataset's test split, read once) | 100 | 100 | 26 / 10 |

738 GridFS files, one per record. Sampling: quotas per bucket (phishing, benign with a password input, benign without),
brand cap, one page per site, sites disjoint across splits, same-text pages skipped. "benign_hard" means the static HTML has a
password input, not that the page is a login page.

Record statuses and codes:
- `ready`: at least 20 words, English at probability 0.9 or higher, no quality flags.
- `rejected`: `short_text`, `non_english`, `low_language_confidence`, `flagged`, `empty_text`, `manual_review`
  (written only by a manual update, used once for a PDF-viewer page before the `viewer_artifact` flag existed).
- `failed` (fetch problem): `dns_failure`, `timeout`, `tls_error`, `http_error`, `too_many_redirects`,
  `unsupported_content_type`, `too_large`, `network_error`.
- Flags quarantine and never drop a page: `parked_domain`, `hosting_default`, `takedown_or_warning`, `js_challenge`,
  `error_page`, `cms_default`, `viewer_artifact`, `client_side_redirect` (meta refresh only), `private_address_in_text`.
  Long pages are searched for phrases only in their first 80 words.

Storage: unique index on `url`, partial unique index on `content.text_hash`, `insert_record_checked` never overwrites.

## Scoring (current)

- Model `all-MiniLM-L6-v2`. References: 4 chunks per page, built once and cached. Candidate: at most 10 chunks. Class score
  is the mean of the top 3 chunk similarities.
- Production rule (`decide_similarity_verdict`): `fake` if margin (fake minus real) is above 0.10, otherwise `real`. "Real" means
  not flagged, not verified legitimate. `unknown` only when a page cannot be scored (short, non-English, flagged, no references).
- `decide_symmetric_verdict` (dead zone with abstention) is experimental. It never met the pre-set limits.
- `score_html(html, index)` scores HTML the caller already fetched, with the same gates as collection, never raises, returns
  scores as None when not computed. The old URL-fetching scorer was removed.

## Results (see EXPERIMENTS.md for the full log)

- Validation (development set): symmetric rule, no dead zone reached 5% false positives with 70% coverage. One-sided at
  t=0.10: 65 true positives, 5 false positives out of 100 and 100.
- Held-out test, run once with parameters fixed beforehand (t=0.10, word-count cutoff 60): similarity tp 42, fp 4, tn 96,
  fn 58 (recall 0.42, 95% CI 0.33 to 0.52, false-positive rate 0.04, CI 0.02 to 0.10). Word-count baseline recall 0.17,
  false-positive rate 0.08.
- Diagnostic after the run (scores only): phishing margins on test sit lower than on validation, benign margins did not move.
  Not separated: drift, kit families on validation, tuning optimism, label noise.
- The test split was used once for the reported numbers and then for the margin diagnostic. Do not use `--final` again for a
  new claim. Any new idea is a new experiment with a new split.
- Caveats to state with any number: 50% phishing base rate (real traffic is far lower, so most alerts would be false),
  hand-read samples show label noise and scrape failures among "phishing" pages, kit families repeat, brand labels are
  noisy, HTML comes from a real browser while the scanner fetches with `requests`, English only.

## Known open problems

1. Short-text language detection is unreliable (`langdetect`). A plain English sentence scored 0.86.
2. `requirements.txt` must list `sentence-transformers`, `numpy`, `huggingface-hub>=1.31.0,<2.0` and `datasets`. Verify in a
   fresh virtual environment.
3. The card hardcodes the measured numbers (42% and 4%). If the threshold or references change, update `_ml_card.html` and
   re-measure on a new split.
4. The `scanner.test_scanner` harness was removed.
5. example.com (27 words) is flagged as phishing at margin 0.169, a concrete false positive. A word-count diagnostic on
   validation had too few short pages to say whether short pages are worse.
6. `ai/scoring.py` imports the embedding library at module level, pinned by `tests/test_ai_imports.py`. Making it lazy is
   optional.

## Roadmap

- Done: collection pipeline, PhreshPhish ingestion, evaluation with a held-out test, `score_html`.
- Phase 6, scanner integration (done, display only): `SecurityScanner(enable_ml=False)` by default, switched on with the
  `ENABLE_ML` environment variable in `app.py`. The step runs after the page is parsed, reuses `response.content`, is wrapped
  so a failure gives `status: error`, and never affects `get_verdict()`. The result is stored in `ScanReport.ml_analysis`
  (kept small for the Flask session cookie: about 190 bytes measured, total cookie about 1.4 KB for simple pages).
  The first scan builds the reference index (about 6 s), later scans add about 0.3 s. Card wording: "Flagged: text resembles
  known phishing pages", "Not flagged", "Not scored: <reason>". Never "safe".
- Remaining: update the README, archive the legacy ML folders, package cleanup.