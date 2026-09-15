"""Score a completed label-review CSV exported from sample_for_review.py.

Reports the empirical label-noise rate for the manually reviewed sample:
what fraction of automatically assigned (CVE-diff-derived) vulnerability
labels a human reviewer confirmed as correct, versus wrong-CWE, not
actually vulnerable, or unclear. This is the number that should be cited
in the thesis wherever the dataset's labels are described, instead of
assuming the commit-derived labels are clean.

    python src/score_label_review.py --csv data/processed/label_review.csv
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="data/processed/label_review.csv")
    args = ap.parse_args()

    path = Path(args.csv)
    if not path.exists():
        raise SystemExit(
            f"No review CSV at {path}. Open data/processed/label_review.html "
            "in a browser, complete the review, and click 'Export CSV' first."
        )

    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    n = len(rows)
    if n == 0:
        raise SystemExit("CSV is empty.")

    verdicts = Counter(r["verdict"] for r in rows)
    unreviewed = verdicts.get("UNREVIEWED", 0)
    reviewed = n - unreviewed
    if reviewed == 0:
        raise SystemExit("No cards have been reviewed yet (all UNREVIEWED).")

    by_lang = defaultdict(Counter)
    by_cwe = defaultdict(Counter)
    for r in rows:
        if r["verdict"] == "UNREVIEWED":
            continue
        by_lang[r["language"]][r["verdict"]] += 1
        by_cwe[r["cwe"]][r["verdict"]] += 1

    correct = verdicts.get("CORRECT", 0)
    wrong_cwe = verdicts.get("WRONG_CWE", 0)
    not_vuln = verdicts.get("NOT_VULNERABLE", 0)
    unclear = verdicts.get("UNCLEAR", 0)

    print(f"Reviewed {reviewed} / {n} sampled vulnerable-label functions\n")
    print(f"  CORRECT (label + CWE both right) : {correct:3d}  ({correct/reviewed:.1%})")
    print(f"  WRONG_CWE (vulnerable, wrong CWE) : {wrong_cwe:3d}  ({wrong_cwe/reviewed:.1%})")
    print(f"  NOT_VULNERABLE (label noise)      : {not_vuln:3d}  ({not_vuln/reviewed:.1%})")
    print(f"  UNCLEAR                           : {unclear:3d}  ({unclear/reviewed:.1%})")
    if unreviewed:
        print(f"  (still UNREVIEWED, excluded)       : {unreviewed:3d}")

    label_noise_rate = not_vuln / reviewed
    cwe_error_rate = (wrong_cwe + not_vuln) / reviewed
    print(f"\nCitable numbers:")
    print(f"  vulnerability-label noise rate : {label_noise_rate:.1%}  "
          f"(sampled function is not actually vulnerable)")
    print(f"  CWE-assignment error rate      : {cwe_error_rate:.1%}  "
          f"(wrong CWE or not vulnerable at all)")
    print(f"  95% Wilson CI needs the 'statsmodels' package or src/stats.py's "
          f"bootstrap_ci() on the 0/1 CORRECT indicator if you want an interval.")

    print("\nBy language:")
    for lang, c in sorted(by_lang.items()):
        tot = sum(c.values())
        print(f"  {lang:12s} n={tot:3d}  correct={c.get('CORRECT',0)}  "
              f"wrong_cwe={c.get('WRONG_CWE',0)}  not_vuln={c.get('NOT_VULNERABLE',0)}  "
              f"unclear={c.get('UNCLEAR',0)}")

    worst_cwes = sorted(
        ((cwe, c) for cwe, c in by_cwe.items() if c.get("CORRECT", 0) < sum(c.values())),
        key=lambda kv: sum(kv[1].values()), reverse=True,
    )
    if worst_cwes:
        print("\nCWEs with at least one non-CORRECT verdict:")
        for cwe, c in worst_cwes[:15]:
            tot = sum(c.values())
            print(f"  {cwe:10s} n={tot:2d}  correct={c.get('CORRECT',0)}  "
                  f"wrong_cwe={c.get('WRONG_CWE',0)}  not_vuln={c.get('NOT_VULNERABLE',0)}  "
                  f"unclear={c.get('UNCLEAR',0)}")


if __name__ == "__main__":
    main()
