# INTEGRATION_REVIEW.md

Read-only review. Do not edit, create or delete any file, and do not write to MongoDB. Follow AGENT.md.
Answer every question below with file and line references. When something is not visible in the code, say "not found" instead of guessing.

## Goal

The owner wants the `ai/` package to replace the planned ML phases 3 to 5 (text extraction, embeddings, similarity scorer) and then be integrated into the existing scanner (`scanner/core.py`) as an advisory `ml_analysis` section. We need to know how feasible and how risky that is.

## What `ai/` is (facts from the owner's testing)

- `ai/text_processing.py`: HTML to text (extractor v3), language detection, quality flags, chunking.
- `ai/records.py`: builds page records and applies gates (at least 20 words, English at probability 0.9 or higher, no quality flags).
- `ai/scoring.py`: MiniLM (all-MiniLM-L6-v2) embeddings. Reference pages are chunked (4 chunks per page) and embedded once into a `ReferenceIndex`. A candidate's chunks (at most 10) are compared to it, and the top-3 mean similarity per class is computed. `decide_similarity_verdict` returns fake, real or unknown using one symmetric dead zone (default 0.02). Reasons: short_text, unsupported_language, no_references, low_margin, decided.
- `score_candidate_page(url)` fetches the URL again, reloads references from MongoDB on every call and re-embeds them. It is slow, and a version that scores already-fetched HTML does not exist yet.
- `ai/__init__.py` imports `scoring`, which imports `sentence_transformers` (torch) at import time.
- Data: MongoDB database `security_scanner`, collection `page_records` (PhreshPhish dataset pages with raw HTML in GridFS). Train 101 phishing and 100 benign ready pages. Validation 100 and 100.
- Measured so far (validation, development set): no dead zone reaches 5% false positives with 70% coverage. At dead zone 0, recall is 0.93 and the false-positive rate is 0.36. The word-count-only baseline catches 21% of phishing pages at 5% false positives. The held-out test split has not been read.
- English only. Non-English, short, and JavaScript-only pages return `unknown`.

## Questions

### A. The scanner
1. In `scanner/core.py`, how does `SecurityScanner.scan` work end to end? List the steps, the network calls, and the time each could take.
2. Which fields does `ScanReport` have, and how is `get_verdict()` computed? Quote the logic.
3. Where is the page HTML fetched, and is the body kept or exposed so a second component could reuse it without a second request?
4. How are user-supplied URLs validated? Are private addresses, localhost and link-local addresses blocked (SSRF)? This matters because adding `ai/` adds another fetch path.

### B. The app
5. How is `app.py` run (dev server, gunicorn, threads or processes)? Where would a model and a reference index be loaded once, and what would loading cost at startup?
6. Is there a request timeout or concurrency limit that a slow embedding step would violate?

### C. Existing ML code
7. What do `ML/`, `models/ai_training/`, `models/db/`, `DataCollections/`, `train_ml_model.py`, `test_ml_detector.py` and `models/*.pkl` do? Is any of it imported by `app.py`, `scanner/` or the tests? Use grep to check.
8. Which MongoDB database and collection do `models/db` and `DataCollections/training_data_db.py` use? Does that overlap with `page_records` or the `security_scanner` database? (Read the code only. Do not query the database.)
9. Which parts would become redundant if `ai/` replaced them, and which are used by something else?

### D. Tests and dependencies
10. How do `tests/test_units.py` and `tests/test_integration.py` mock the network and MongoDB? Would adding an `ml_analysis` field or an `ai` import break any of the 99 tests? Look for assertions on the exact shape of `ScanReport` or its dictionary.
11. Compare `requirements.txt` with what the code imports. Are `sentence-transformers`, `datasets`, `tldextract` and the pin `huggingface-hub>=1.31.0,<2.0` listed? What is the Python version?
12. Can `scanner/` import `ai` cleanly? Check the package name, `sys.path` assumptions, and any import cycle with root-level `mongo_dataset.py` and `dataset_schema.py`.

### E. Verdict design
13. Given how `get_verdict()` works today, propose two or three concrete ways to combine the rule-based verdict with the ML result. Required: the ML result must be allowed to be `unknown`, and it must be shown with the evidence behind it. One option must be "display only, no effect on the final verdict".
14. List everything that would have to change in `scanner/core.py`, `app.py`, the templates and the tests, as a checklist ordered by risk. Do not write the code.

## Output format

1. A one-paragraph summary: feasible or not, and the biggest risk.
2. Answers to A to E, numbered as above.
3. A list of things you could not determine, and which file or command would settle each.
4. Do not propose any edit as already applied.