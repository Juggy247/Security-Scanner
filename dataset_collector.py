from __future__ import annotations
import argparse
import csv
from collections import Counter
from dataset_schema import ALLOWED_SOURCES
from ai.records import build_record_with_raw
from typing import Any, Dict, List, Optional

from mongo_dataset import PageRecordStore


REQUIRED_COLUMNS = {"url", "label", "source", "evidence", "listed_at"}
VALID_LABELS = {"phishing", "benign"}


def read_candidates(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"CSV is missing columns: {sorted(missing)}")
        rows = list(reader)

    cleaned_rows: List[Dict[str, str]] = []
    for line_number, row in enumerate(rows, start=2):
        row = {key: (row.get(key) or "").strip() for key in REQUIRED_COLUMNS}

        if not row["url"].startswith(("http://", "https://")):
            raise SystemExit(f"line {line_number}: url must start with http:// or https://, got {row['url']!r}")
        if row["label"] not in VALID_LABELS:
            raise SystemExit(f"line {line_number}: label must be one of {sorted(VALID_LABELS)}, got {row['label']!r}")
        if row["source"] not in ALLOWED_SOURCES:
            raise SystemExit(f"line {line_number}: source must be one of {sorted(ALLOWED_SOURCES)}, got {row['source']!r}")
        if not row["evidence"]:
            raise SystemExit(f"line {line_number}: evidence is required")
        if not row["listed_at"]:
            raise SystemExit(f"line {line_number}: listed_at is required")

        cleaned_rows.append(row)
    return cleaned_rows


def main(argv: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(description="Collect labeled pages from a candidate CSV.")
    parser.add_argument("csv_path", help="columns: url,label,source,evidence,listed_at")
    parser.add_argument("--retry-failed", action="store_true", help="re-fetch URLs whose stored record has status 'failed'")
    args = parser.parse_args(argv)

    candidates = read_candidates(args.csv_path)
    funnel: Counter = Counter()

    store = PageRecordStore()
    try:
        store.ensure_indexes()

        for item in candidates:
            existing = store.find_by_url(item["url"])
            if existing:
                was_failed = existing.get("processing", {}).get("status") == "failed"
                if args.retry_failed and was_failed:
                    store.delete_failed_by_url(item["url"])
                    funnel["retrying_failed"] += 1
                else:
                    funnel["skipped_existing"] += 1
                    print(f"{'skipped':<15} {'-':<9} {item['url']}")
                    continue

            evidence = f"{item['evidence']} (listed {item['listed_at']})"
            record, raw = build_record_with_raw(item["url"], item["label"], item["source"], evidence)
            outcome, record_id = store.insert_record_checked(record.to_mongo_dict())
            funnel[outcome] += 1

            if outcome == "inserted":
                code = record.processing.error_code or "ok"
                funnel[f"{record.label.value}:{record.processing.status}:{code}"] += 1
                if raw is not None and record_id:
                    store.set_raw_html_ref(record_id, store.save_raw_html(raw, filename=record.url))

            print(f"{outcome:<15} {record.processing.status:<9} {record.url}")
    finally:
        store.close()

    print("\nFunnel:")
    for key, count in sorted(funnel.items()):
        print(f"  {key}: {count}")


if __name__ == "__main__":
    main()
