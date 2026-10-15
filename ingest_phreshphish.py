from __future__ import annotations

import argparse
import re
from collections import Counter
from statistics import median
from typing import Optional

import tldextract

from ai.records import build_record_from_html, get_domain
from dataset_schema import OriginInfo
from mongo_dataset import PageRecordStore

DATASET_ID = "phreshphish/phreshphish"
DATASET_NAME = "phreshphish"      # value stored in label.source and origin.dataset
DATASET_VERSION = "1.0.1"
DATASET_SPLITS = ("train", "test")        # the dataset's own split. We never read its test split here.

MAX_HTML_CHARS = 2_000_000
DEFAULT_SCAN_LIMIT = 3000
DEFAULT_QUOTAS = {"phishing": 20, "benign_hard": 5, "benign_regular": 15}   # counted in ready pages
BRAND_ALIASES = {"facebook": "meta"}   # the dataset uses both labels for one company
MAX_PER_DOMAIN = 1        # ready pages per site, per bucket

LABEL_MAP = {"phish": "phishing", "benign": "benign"}
# "benign_hard" means the static HTML contains a password input, not that the page is a login page.
_PASSWORD_RE = re.compile(r"<input[^>]*type\s*=\s*[\"']?password", re.IGNORECASE)

# Uses only the suffix list bundled with the package. Private suffixes (github.io, blogspot.com) count as suffixes.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def site_key(host: str) -> str:
    """Registrable site of a hostname: example.co.uk, user.github.io. The raw host for localhost and IPs."""
    parts = _EXTRACT(host)
    if hasattr(parts, "top_domain_under_public_suffix"):
        key = parts.top_domain_under_public_suffix
    else:
        key = parts.registered_domain
    return (key or parts.domain or host).lower()


def brand_key(target: Optional[str]) -> Optional[str]:
    if not target:
        return None
    lowered = target.lower()
    return BRAND_ALIASES.get(lowered, lowered)


def pick_bucket(label_value: str, html: str) -> str:
    if label_value == "phishing":
        return "phishing"
    return "benign_hard" if _PASSWORD_RE.search(html) else "benign_regular"


def main(argv: Optional[list] = None):
    parser = argparse.ArgumentParser(description="Ingest a capped sample of PhreshPhish train pages.")
    parser.add_argument("--role", choices=["train", "validation", "test"], default="train",
                        help="our split for stored records. The dataset's own split stays in origin.split")
    parser.add_argument("--dataset-split", choices=list(DATASET_SPLITS), default="train",
                        help="which split of the PhreshPhish dataset to stream")
    parser.add_argument("--allow-test", action="store_true", help="required to stream the held-out test split")
    parser.add_argument("--write", action="store_true", help="store records in MongoDB (default is a dry run)")
    parser.add_argument("--append", action="store_true", help="allow --write when records of this role already exist")
    parser.add_argument("--scan-limit", type=int, default=DEFAULT_SCAN_LIMIT, help="maximum rows to read")
    parser.add_argument("--phishing", type=int, default=DEFAULT_QUOTAS["phishing"], help="ready phishing pages to collect")
    parser.add_argument("--benign-hard", type=int, default=DEFAULT_QUOTAS["benign_hard"], help="ready benign pages with a password input")
    parser.add_argument("--benign-regular", type=int, default=DEFAULT_QUOTAS["benign_regular"], help="ready benign pages without one")
    parser.add_argument("--max-per-brand", type=int, default=3, help="ready phishing pages per impersonated brand")
    parser.add_argument("--other-cap", type=int, default=5, help="cap for the catch-all 'other' brand label")
    parser.add_argument("--show-flagged", action="store_true", help="print title and a text preview for flagged pages")
    args = parser.parse_args(argv)

    if (args.role == "test") != (args.dataset_split == "test"):
        raise SystemExit("--role test goes with --dataset-split test, and no other combination is allowed.")
    if args.dataset_split == "test" and not args.allow_test:
        raise SystemExit("The dataset's test split is held out. Add --allow-test to stream it.")

    quotas = {"phishing": args.phishing, "benign_hard": args.benign_hard, "benign_regular": args.benign_regular}
    brand_caps = {"other": args.other_cap}

    from datasets import load_dataset  # imported here so --help stays fast

    funnel: Counter = Counter()
    ready_counts: Counter = Counter()
    brand_counts: Counter = Counter()
    domain_counts = {bucket: Counter() for bucket in quotas}
    seen_hashes = set()
    low_confidence = []
    ready_dates = []

    # The store is opened for reading even in a dry run. Only --write inserts anything.
    store = PageRecordStore()
    try:
        if args.write:
            store.ensure_indexes()
            existing = store.collection.count_documents({"label.source": DATASET_NAME, "split": args.role})
            if existing and not args.append:
                raise SystemExit(
                    f"{existing} {DATASET_NAME} records already stored in role '{args.role}'. Use --append to add more."
                )

        # Sites that already have a stored record are skipped, so roles never share a site.
        stored_sites = {site_key(d) for d in store.collection.distinct("domain") if d}

        # Brands already stored in this role count toward the caps.
        for doc in store.collection.find(
            {"label.source": DATASET_NAME, "label.value": "phishing", "processing.status": "ready", "split": args.role},
            {"origin.target": 1},
        ):
            brand = brand_key((doc.get("origin") or {}).get("target"))
            if brand:
                brand_counts[brand] += 1

        print(f"role={args.role} dataset_split={args.dataset_split} write={args.write} quotas={quotas} stored sites={len(stored_sites)}")

        stream = load_dataset(DATASET_ID, split=args.dataset_split, streaming=True)

        for row in stream:
            if funnel["rows_scanned"] >= args.scan_limit:
                break
            if all(ready_counts[bucket] >= quota for bucket, quota in quotas.items()):
                break

            funnel["rows_scanned"] += 1
            if funnel["rows_scanned"] % 500 == 0:
                print(f"scanned {funnel['rows_scanned']} rows, ready so far: {dict(ready_counts)}")

            label_value = LABEL_MAP.get(row.get("label"))
            if label_value is None:
                funnel["skip:unknown_label"] += 1
                continue
            if row.get("lang") != "en":
                funnel["skip:dataset_lang_not_en"] += 1
                continue

            html = row.get("html") or ""
            url = row.get("url") or ""
            if not html or not url:
                funnel["skip:missing_html_or_url"] += 1
                continue
            if len(html) > MAX_HTML_CHARS:
                funnel["skip:too_large"] += 1
                continue

            bucket = pick_bucket(label_value, html)
            if ready_counts[bucket] >= quotas[bucket]:
                funnel[f"skip:bucket_full:{bucket}"] += 1
                continue

            domain_key = site_key(get_domain(url))
            if domain_key in stored_sites:
                funnel["skip:site_already_stored"] += 1
                continue
            if domain_counts[bucket][domain_key] >= MAX_PER_DOMAIN:
                funnel["skip:domain_cap"] += 1
                continue

            target = row.get("target")
            brand = brand_key(target)
            if bucket == "phishing" and brand and brand_counts[brand] >= brand_caps.get(brand, args.max_per_brand):
                funnel["skip:brand_cap"] += 1
                continue

            origin = OriginInfo(
                dataset=DATASET_NAME,
                version=DATASET_VERSION,
                split=args.dataset_split,
                sha256=row.get("sha256"),
                date=str(row["date"]) if row.get("date") else None,
                target=target,
                bucket=bucket,
            )
            evidence = f"PhreshPhish v{DATASET_VERSION} {args.dataset_split} sha256={row.get('sha256')}"
            record, raw = build_record_from_html(url, html, label_value, DATASET_NAME, evidence, origin=origin)
            record.split = args.role

            text_hash = record.content.text_hash
            if text_hash and text_hash in seen_hashes:
                funnel["skip:duplicate_text_in_batch"] += 1
                continue
            if text_hash:
                seen_hashes.add(text_hash)

            if args.write:
                outcome, record_id = store.insert_record_checked(record.to_mongo_dict())
                funnel[f"insert:{outcome}"] += 1
                if outcome != "inserted":
                    continue
                if raw is not None and record_id:
                    store.set_raw_html_ref(record_id, store.save_raw_html(raw, filename=record.url))

            status = record.processing.status
            code = record.processing.error_code or "ok"
            funnel[f"{bucket}:{status}:{code}"] += 1
            for flag in record.processing.flags:
                funnel[f"flag:{flag}"] += 1
            if args.show_flagged and code == "flagged":
                preview = (record.content.text or "")[:150]
                print(f"[flagged {bucket} {record.processing.flags}] title={record.content.title!r} text={preview!r}")

            if code == "low_language_confidence":
                low_confidence.append(record.content.language_confidence)

            if status == "ready":
                ready_counts[bucket] += 1
                domain_counts[bucket][domain_key] += 1
                if bucket == "phishing" and brand:
                    brand_counts[brand] += 1
                if origin.date:
                    ready_dates.append(origin.date)
    finally:
        store.close()

    print("\nQuota status (ready pages):")
    for bucket, quota in quotas.items():
        print(f"  {bucket}: {ready_counts[bucket]}/{quota}")

    print("\nReady phishing pages by brand:", dict(brand_counts.most_common()))

    print("\nFunnel:")
    for key, count in sorted(funnel.items()):
        print(f"  {key}: {count}")

    if low_confidence:
        print(
            f"\nlow_language_confidence probabilities: n={len(low_confidence)} "
            f"min={min(low_confidence):.2f} median={median(low_confidence):.2f} max={max(low_confidence):.2f}"
        )
    if ready_dates:
        print(f"\nReady pages date range: {min(ready_dates)} to {max(ready_dates)}")
    if not args.write:
        print("\nDry run: nothing was written. Add --write to store records.")


if __name__ == "__main__":
    main()