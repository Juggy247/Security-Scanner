from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

from ai.evaluation import (
    MAX_FALSE_POSITIVE_RATE,
    MIN_COVERAGE,
    choose_dead_zone,
    choose_wordcount_cutoff,
    near_duplicates,
    predictions_at,
    predictions_onesided,
    reason_counts,
    score_examples,
    summarize,
    sweep_dead_zones,
    sweep_thresholds,
    wilson_interval,
    wordcount_table,
)
from ai.scoring import (
    MAX_CANDIDATE_CHUNKS,
    MAX_REFERENCE_CHUNKS,
    TOP_K,
    build_reference_index,
    load_reference_texts,
)
from mongo_dataset import PageRecordStore


def fmt(value):
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def print_entry(name, e, mark=" "):
    print(
        f"{mark} {name:>8}  tp={e['tp']:>3} fp={e['fp']:>3} tn={e['tn']:>3} fn={e['fn']:>3}  "
        f"coverage={fmt(e['coverage'])}  recall_all={fmt(e['recall_all'])}  fpr_answered={fmt(e['fpr_answered'])}"
    )


def is_feasible(e):
    return e["fpr_answered"] is not None and e["fpr_answered"] <= MAX_FALSE_POSITIVE_RATE and e["coverage"] >= MIN_COVERAGE


def rate_text(count, n):
    if n == 0:
        return "n/a"
    low, high = wilson_interval(count, n)
    return f"{count}/{n} = {count / n:.2f} (95% CI {low:.2f} to {high:.2f})"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate one split against the train references.")
    parser.add_argument("--split", choices=["train", "validation", "test"], default="validation")
    parser.add_argument("--final", action="store_true", help="required to read the held-out test split")
    parser.add_argument("--rule", choices=["symmetric", "onesided"], default="symmetric",
                        help="symmetric: dead zone with abstention. onesided: fake if margin > threshold, never abstains")
    parser.add_argument("--dead-zone", type=float, help="test split, symmetric rule: value chosen on validation")
    parser.add_argument("--threshold", type=float, help="test split, onesided rule: value fixed before the test run")
    parser.add_argument("--wordcount-cutoff", type=int, help="test split: baseline cutoff chosen on validation")
    parser.add_argument("--near-dup-cutoff", type=float, default=0.98)
    parser.add_argument("--reports-dir", default="reports")
    args = parser.parse_args(argv)

    # Guards run before any database access, so the test split cannot be touched by accident.
    fixed = {"--dead-zone": args.dead_zone, "--threshold": args.threshold, "--wordcount-cutoff": args.wordcount_cutoff}
    if args.split == "test":
        if not args.final:
            raise SystemExit("The test split is held out. Add --final to read it, once, after tuning on validation.")
        needed = ["--threshold", "--wordcount-cutoff"] if args.rule == "onesided" else ["--dead-zone", "--wordcount-cutoff"]
        unused = "--dead-zone" if args.rule == "onesided" else "--threshold"
        missing = [name for name in needed if fixed[name] is None]
        if missing:
            raise SystemExit("On test, parameters are fixed from validation. Pass " + " and ".join(missing) + ".")
        if fixed[unused] is not None:
            raise SystemExit(f"{unused} does not apply to the {args.rule} rule.")
    elif any(value is not None for value in fixed.values()):
        raise SystemExit("--dead-zone, --threshold and --wordcount-cutoff apply to the test split only. Other splits sweep them.")

    store = PageRecordStore()
    try:
        examples = store.find_examples(args.split)
    finally:
        store.close()
    real_texts = load_reference_texts("benign", split="train")
    fake_texts = load_reference_texts("phishing", split="train")

    if not examples:
        raise SystemExit(f"No ready English examples in split '{args.split}'.")
    if not real_texts or not fake_texts:
        raise SystemExit("Missing train references for one of the classes.")
    if {e["label"] for e in examples} != {"phishing", "benign"}:
        raise SystemExit(f"Split '{args.split}' needs both classes.")

    index = build_reference_index(real_texts, fake_texts)
    rows = score_examples(examples, index)
    labels = [r["label"] for r in rows]
    n_pos = sum(1 for r in rows if r["label"] == 1)
    dups = near_duplicates(rows, args.near_dup_cutoff)

    report = {
        "split": args.split,
        "rule": args.rule,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "plumbing_only": args.split == "train",
        "settings": {
            "max_reference_chunks": MAX_REFERENCE_CHUNKS,
            "top_k": TOP_K,
            "max_candidate_chunks": MAX_CANDIDATE_CHUNKS,
            "max_false_positive_rate": MAX_FALSE_POSITIVE_RATE,
            "min_coverage": MIN_COVERAGE,
            "near_duplicate_cutoff": args.near_dup_cutoff,
        },
        "reference_pages": {"benign": len(real_texts), "phishing": len(fake_texts)},
        "examples": {"phishing": n_pos, "benign": len(rows) - n_pos},
        "score_reasons": reason_counts(rows),
        "near_duplicates_at_or_above_cutoff": len(dups),
    }

    print(f"split={args.split}  rule={args.rule}  references: {report['reference_pages']}  examples: {report['examples']}")
    if args.split == "train":
        print("PLUMBING ONLY (leave-one-out on the reference pages). Not a reportable result.")
    print("score reasons:", report["score_reasons"], "| near-duplicates:", len(dups))

    if args.split == "test":
        if args.rule == "onesided":
            _, predictions = predictions_onesided(rows, args.threshold)
            params = {"threshold": args.threshold}
        else:
            _, predictions = predictions_at(rows, args.dead_zone)
            params = {"dead_zone": args.dead_zone}
        params["wordcount_cutoff"] = args.wordcount_cutoff
        similarity = summarize(labels, predictions)
        baseline = summarize(labels, [1 if r["word_count"] < args.wordcount_cutoff else 0 for r in rows])
        report["fixed"] = {**params, "similarity": similarity, "wordcount": baseline}

        print(f"\nFixed before this run: {params}")
        for name, e in (("similarity", similarity), ("wordcount", baseline)):
            print(f"\n{name}: tp={e['tp']} fp={e['fp']} tn={e['tn']} fn={e['fn']}  coverage={fmt(e['coverage'])}")
            print("  recall (all phishing pages):", rate_text(e["tp"], e["n_pos"]))
            print("  false-positive rate:        ", rate_text(e["fp"], e["fp"] + e["tn"]))
        print("\nDo not change any parameter after seeing these numbers.")
    elif args.rule == "onesided":
        table = sweep_thresholds(rows)
        base = choose_wordcount_cutoff(wordcount_table(rows))
        report["sweep_onesided"] = table
        report["wordcount_baseline"] = base

        print(f"\nOne-sided sweep (* = fpr <= {MAX_FALSE_POSITIVE_RATE}; every 0.02 shown):")
        for i, e in enumerate(table):
            if i % 4 == 0:
                mark = "*" if e["fpr_answered"] is not None and e["fpr_answered"] <= MAX_FALSE_POSITIVE_RATE else " "
                print_entry(str(e["threshold"]), e, mark)
        if base:
            print_entry(f"wc<{base['cutoff']}", base)
        else:
            print("word-count baseline: no feasible cutoff")
    else:
        table = sweep_dead_zones(rows)
        chosen = choose_dead_zone(table)
        base = choose_wordcount_cutoff(wordcount_table(rows))
        report["sweep"] = table
        report["chosen_dead_zone"] = chosen["dead_zone"] if chosen else None
        report["wordcount_baseline"] = base

        print(f"\nDead-zone sweep (* = within fpr<={MAX_FALSE_POSITIVE_RATE} and coverage>={MIN_COVERAGE}):")
        for e in table:
            print_entry(str(e["dead_zone"]), e, "*" if is_feasible(e) else " ")
        print("chosen dead zone:", chosen["dead_zone"] if chosen else "no feasible dead zone")
        if base:
            print_entry(f"wc<{base['cutoff']}", base)
        else:
            print("word-count baseline: no feasible cutoff")

    os.makedirs(args.reports_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(args.reports_dir, f"report_{args.split}_{stamp}.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print("\nreport written to", path)


if __name__ == "__main__":
    main()