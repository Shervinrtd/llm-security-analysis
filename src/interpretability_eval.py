"""Measure explanation quality on a run's predictions.

Reuses whatever `evaluate.py` already produced - the prediction rows store the
model's `reason`, so no extra LLM calls are needed to score interpretability.
Each explanation is joined back to its code by sample_id and scored by the
interpretability rubric, then aggregated per (model, strategy).

Two populations are reported separately, because they mean different things:

    findings        every case the model called vulnerable. This is what a
                    report actually shows a user, so its explanation quality is
                    what "interpretability of results" refers to.
    true positives  findings that were correct. Here the true CWE and the real
                    vulnerable lines are known, so mechanism and location can
                    also be checked - the strongest form of the measurement.

    python src/interpretability_eval.py                    # scores predictions.jsonl
    python src/interpretability_eval.py --pred data/results/predictions.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import interpretability as I

RESULTS = C.DATA / "results"


def load_code_index(*splits: str) -> dict[str, dict]:
    """sample_id -> {code, cwe, lines} from the benchmark splits."""
    idx: dict[str, dict] = {}
    for name in splits:
        p = C.PROCESSED / name
        if not p.exists():
            continue
        for line in p.open(encoding="utf-8"):
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("sample_id"):
                idx[r["sample_id"]] = {
                    "code": r.get("code", ""),
                    "cwe": r.get("cwe_primary"),
                    "lines": r.get("changed_lines_in_func") or [],
                }
    return idx


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", default=str(RESULTS / "predictions.jsonl"))
    ap.add_argument("--out", default=str(RESULTS / "interpretability_summary.json"))
    args = ap.parse_args()

    pred_p = Path(args.pred)
    if not pred_p.exists():
        sys.exit(f"no predictions at {pred_p} - run evaluate.py first")

    rows = [json.loads(l) for l in pred_p.open(encoding="utf-8") if l.strip()]
    code_idx = load_code_index("test.jsonl", "val.jsonl", "train.jsonl")

    # group by (model, strategy)
    groups: dict[tuple, list] = defaultdict(list)
    for r in rows:
        groups[(r.get("model", "?"), r.get("strategy", "?"))].append(r)

    summaries = []
    missing_code = 0
    for (model, strategy), grp in sorted(groups.items()):
        finding_scores, tp_scores = [], []
        for r in grp:
            if r.get("pred_label") != 1:
                continue                    # only explanations of FINDINGS matter here
            meta = code_idx.get(r.get("sample_id"))
            if not meta:
                missing_code += 1
                continue
            correct = r.get("true_label") == 1
            s = I.score_explanation(
                r.get("reason", ""), meta["code"],
                true_cwe=meta["cwe"] if correct else None,
                true_lines=meta["lines"] if correct else None)
            finding_scores.append(s)
            if correct:
                tp_scores.append(s)

        summaries.append({
            "model": model, "strategy": strategy,
            "n_findings": len(finding_scores),
            "findings": I.aggregate(finding_scores),
            "true_positives": I.aggregate(tp_scores),
        })

    out = Path(args.out)
    out.write_text(json.dumps(summaries, indent=1), encoding="utf-8")

    print("=" * 84)
    print("INTERPRETABILITY OF RESULTS  (explanation quality of what the model flagged)")
    print("=" * 84)
    hdr = f"{'model':<20}{'strategy':<12}{'n':>4}{'compos.':>9}{'ground':>8}{'specif':>8}{'mech':>7}{'halluc%':>9}"
    print(hdr)
    print("-" * 84)
    for s in summaries:
        f = s["findings"]
        if not f.get("n"):
            continue
        halluc_pct = (f["explanations_with_hallucination"] / f["n"] * 100) if f["n"] else 0
        mech = f"{f['mechanism']:.2f}" if f.get("mechanism") is not None else "  -"
        print(f"{s['model']:<20}{s['strategy']:<12}{f['n']:>4}"
              f"{f['composite']:>9.3f}{f['grounded']:>8.3f}{f['specific']:>8.3f}"
              f"{mech:>7}{halluc_pct:>8.1f}%")
    print("-" * 84)
    print("composite: 0.5*grounded + 0.2*specific + 0.2*mechanism + 0.1*located (defined dims only)")
    print("grounded : fraction of code-identifiers cited that truly appear in the code")
    print("halluc%  : share of explanations that cite at least one identifier NOT in the code")
    if missing_code:
        print(f"\n(note: {missing_code} finding(s) had no code in the splits and were not scored)")
    print(f"\nsummary -> {out}")


if __name__ == "__main__":
    main()
