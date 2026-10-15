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
| `ai/__init__.py` | Re-exports names from the modules above (imports torch eagerly) |
| `dataset_collector.py` | Collection CLI (CSV input) plus a compatibility shim re-exporting names from `ai` for old tests |
| `dataset_schema.py` | Record dataclasses, schema version 4, allowed label sources |
| `mongo_dataset.py` | `PageRecordStore` (MongoDB, GridFS raw HTML, `find_references`, `find_examples`) |
| `ingest_phreshphish.py` | Capped sample ingestion from PhreshPhish, dry run by default |
| `evaluate_split.py` | Evaluation report per split. The test split needs `--final` and fixed parameters |
| `EXPERIMENTS.md` | Log of every experiment, including failures, and the pre-registration |
| `tests/` | `test_ai_evaluation.py`, `test_score_html.py` (no model, no MongoDB), `test_units.py`, `test_integration.py` (live sites) |
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
  scores as None when not computed. `score_candidate_page(url)` is superseded: it refetches without URL validation.

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

1. `tests/test_ai_evaluation.py` (as last reviewed): several assertions cannot fail, `predict_mean_similarity` bypasses the
   pipeline, `predict_threshold` ignores its argument, abstentions are scored as benign in the local harness. Needs a rewrite.
2. `ai/__init__.py` imports `scoring`, so any `import ai.x` loads torch. The shim in `dataset_collector.py` exists for
   `test_units.py`. Package cleanup is pending.
3. `tune_similarity_threshold`, `split_reference_texts`, `split_labeled_examples`, `assign_domain_split` in `ai/evaluation.py`
   are legacy (tests still import some). Splits are now assigned by the ingest role.
4. Short-text language detection is unreliable (`langdetect`). A plain English sentence scored 0.86.
5. `score_candidate_page` is unsafe for user input. `scanner/app.py:is_safe_url` does not resolve hostnames or re-check redirects.
6. The scanner's `ScanReport` is rebuilt as `ScanReport(**raw_data)` from the Flask session cookie (about 4 KB limit).
7. `requirements.txt` must list `sentence-transformers`, `numpy`, `huggingface-hub>=1.31.0,<2.0` and `datasets`. Verify in a
   fresh virtual environment.

## Roadmap

- Done: collection pipeline, PhreshPhish ingestion, evaluation with a held-out test, `score_html`.
- Phase 6, scanner integration (display only, ML never changes the rule-based verdict):
  1. Import `ai` lazily inside the ML step, never at the top of `scanner/core.py`.
  2. Add `ml_analysis` to the `ScanReport` dataclass and to `to_dict()` in the same change.
  3. Opt-in `SecurityScanner(enable_ml=False)`. Wrap the whole step so a failure gives `status: error`. Reuse `response.content`.
  4. Build the index lazily on first use (the Flask reloader imports twice). About 6 s once, about 0.3 s per scan.
  5. Report card wording: "flagged", "not flagged", "not scored". Show the measured numbers. Keep Jinja autoescaping on.
  6. Store only small fields in the session (verdict, scores, margin, reason, flags).
- Phase 7: fake-encoder tests for the scanner step, update the README (test counts, ML section, PhreshPhish citation).
- Cleanup: archive the legacy ML folders outside the repo after checking `training_data`, remove the shim and the eager
  imports in `ai/__init__.py`, remove `score_candidate_page`.