| # | Change | Why | Validation result | Kept? |
|---|---|---|---|---|
| E0 | Pre-registered settings: symmetric dead zone, 4 ref chunks, top-3, 10 candidate chunks | Fixed before seeing validation | No feasible dead zone. FPR 0.36 at dz 0, 0.20 at dz 0.08 (coverage 0.52). Word-count baseline: recall 0.21 at FPR 0.05 | baseline |
| E1 | One-sided threshold, no abstention | Symmetric abstention shrinks the FPR denominator | (fill in) | |
| E1 | One-sided threshold, no abstention | Symmetric abstention shrinks the FPR denominator | Best within FPR 0.05: t=0.095, tp 65, fp 5, recall 0.65 (optimistic, tuned on the same 200 pages) | yes, as the primary rule |

## Pre-registration for the final test run (written before any test page was ingested)
- Rule: one-sided. fake if margin (fake_score - real_score) > t, otherwise real. unknown only for inputs the scorer cannot read.
- t = 0.10. On validation, t = 0.095 and t = 0.10 both give 65 tp / 5 fp (E1). Tie rule chosen in advance: the larger threshold.
- Word-count baseline: phishing if fewer than 60 words (best within FPR <= 0.05 on validation).
- Settings: 4 reference chunks per page, top-3, 10 candidate chunks. References: train split (101 phishing, 100 benign).
- Test data: PhreshPhish dataset test split, same quotas and caps as validation, sites disjoint from train and validation.
- Reported: tp/fp/tn/fn, recall and FPR with 95% Wilson intervals, for both methods. Caveats: label noise, kit families, real-browser HTML. One run, no changes afterwards.

## Final test run (one run, parameters fixed before the run)
- Rule: one-sided, t = 0.10. Word-count baseline: phishing if fewer than 60 words.
- Test split: 100 phishing, 100 benign (dataset's test split, sites disjoint from train and validation). 0 near-duplicates at 0.98.
- Similarity: tp 42, fp 4, tn 96, fn 58. Recall 0.42 (95% CI 0.33 to 0.52). FPR 0.04 (0.02 to 0.10).
- Word-count: tp 17, fp 8, tn 92, fn 83. Recall 0.17 (0.11 to 0.26). FPR 0.08 (0.04 to 0.15).
- Validation to test: recall 0.65 -> 0.42. Causes not separated: tuning optimism, drift, kit-family leakage on validation, label noise.
- Caveats: 50% base rate, label noise (hand-read samples), kit families, HTML from a real browser, English only.
- Order of events: <write exactly what happened: whether this plan was written before the test ingest, before the final run, and when it was committed>.

## Diagnostic after the final run (scores only, no page text read)
- Margin quantiles q10/25/50/75/90. Phishing validation: 0.008 / 0.059 / 0.137 / 0.298 / 0.436. Phishing test: -0.005 / 0.031 / 0.080 / 0.146 / 0.203. Benign validation: -0.153 / -0.098 / -0.038 / 0.019 / 0.060. Benign test: -0.113 / -0.077 / -0.030 / 0.013 / 0.071.
- Reading: phishing margins moved down, benign margins stayed put. Consistent with drift (test pages are later in time) and with validation inflation from kit families. Not separated. No parameter was changed after this.
- Production rule changed to the one-sided threshold 0.10 after the final run, to match what was measured.

The word-count diagnostic (validation only)
Words	Benign pages	Benign false positives	Phishing pages	Phishing caught
20-50	3	1	15	10
50-100	6	0	28	24
100-300	14	1	26	11
300-1000	26	0	21	14
1000+	51	3	10	6
The counts are too small to read much into. The short bands hold 3 and 6 benign pages, so “1 of 3” is not a rate. This doesn’t show that short benign pages are more likely to be false positives, and it doesn’t rule it out either. My guess about example.com’s 27 words stays a guess.
Phishing recall differs by length. Short phishing pages (50-100 words) are caught at 24 of 28, but 100-300 words only 11 of 26. The recall also depends on how many pages from kit families fall in each band, which I can’t see here.
The benign pool is heavily skewed to long pages: 77 of 100 are above 300 words, against 31 of 100 phishing pages. That’s the length confound I flagged before. Similarity beat the word-count baseline on test (recall 0.42 against 0.17, at similar false-positive rates), but a good share of the benign pages are long, so keep that caveat in the write-up.