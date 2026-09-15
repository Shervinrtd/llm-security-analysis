"""Turn raw prediction files into a publishable statistical report.

Reads one or more prediction JSONLs (whatever evaluate.py wrote), and for every
(model, strategy) produces:

  * headline metrics with bootstrap 95% confidence intervals
  * a PER-LANGUAGE breakdown - the whole reason four languages were chosen
  * pairwise McNemar tests between every model/strategy pair on shared samples,
    with Holm-Bonferroni correction for the many comparisons

The output is both a JSON (for the paper's tables) and a readable console table.

    python src/analyze_results.py --pred data/results/predictions.jsonl
    python src/analyze_results.py --glob "data/results/*predictions*.jsonl"
"""
from __future__ import annotations

import argparse
import glob as globmod
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import stats as S
from research_identity import prediction_index

RESULTS = C.DATA / "results"


def load(paths: list[str]) -> list[dict]:
    rows = []
    for pth in paths:
        p = Path(pth)
        if not p.exists():
            continue
        for line in p.open(encoding="utf-8"):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    return rows


def _as01(v) -> int:
    """A missing/unparseable verdict counts as 'no vulnerability reported' (0).
    That is the honest scoring convention: the model produced no positive finding,
    so it detected nothing on that sample. The parse-failure rate is reported
    separately so this is never hidden."""
    try:
        return 1 if int(v) == 1 else 0
    except (TypeError, ValueError):
        return 0


def _preds_trues(rows: list[dict]):
    preds = [_as01(r.get("pred_label")) for r in rows]
    trues = [_as01(r.get("true_label")) for r in rows]
    return preds, trues


def analyse(rows: list[dict], n_boot: int) -> dict:
    # group by (model, strategy)
    groups: dict[tuple, list] = defaultdict(list)
    for r in rows:
        if "pred_label" not in r or "true_label" not in r:
            continue
        groups[(r.get("model", "?"), r.get("strategy", "?"))].append(r)

    per_group = {}
    for (model, strat), grp in groups.items():
        prediction_index(grp)  # Do not compute metrics on ambiguous repeated IDs.
        preds, trues = _preds_trues(grp)
        n_unparsed = sum(1 for r in grp if r.get("pred_label") is None
                         or r.get("parse_ok") is False)
        entry = {"model": model, "strategy": strat, "n": len(grp),
                 "parse_fail_rate": round(n_unparsed / len(grp), 4) if grp else 0.0}
        for metric in ("f1", "mcc", "balanced_accuracy"):
            entry[metric] = S.bootstrap_ci(preds, trues, metric, n_boot=n_boot)
        # per-language F1
        by_lang = defaultdict(list)
        for r in grp:
            by_lang[r.get("language", "?")].append(r)
        entry["by_language"] = {}
        for lang, lrows in sorted(by_lang.items()):
            lp, lt = _preds_trues(lrows)
            entry["by_language"][lang] = S.bootstrap_ci(lp, lt, "f1", n_boot=max(500, n_boot // 4))
        per_group[f"{model} / {strat}"] = entry

    # pairwise McNemar on shared sample_ids
    keys = list(groups.keys())
    pairwise, pvals = {}, {}
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            a, b = groups[keys[i]], groups[keys[j]]
            ai = prediction_index(a)
            bi = prediction_index(b)
            shared = sorted(set(ai) & set(bi))
            if len(shared) < 10:
                continue
            if any(ai[s]["true_label"] != bi[s]["true_label"] for s in shared):
                raise ValueError("Paired prediction truth labels disagree")
            pa = [_as01(ai[s].get("pred_label")) for s in shared]
            pb = [_as01(bi[s].get("pred_label")) for s in shared]
            tt = [_as01(ai[s].get("true_label")) for s in shared]
            name = f"{keys[i][0]}/{keys[i][1]}  vs  {keys[j][0]}/{keys[j][1]}"
            res = S.mcnemar(pa, pb, tt)
            res["n_shared"] = len(shared)
            pairwise[name] = res
            pvals[name] = res["p_value"]

    corrected = S.holm_bonferroni(pvals) if pvals else {}
    adjusted = S.holm_adjusted(pvals)
    for name, sig in corrected.items():
        pairwise[name]["significant_holm"] = sig
        pairwise[name]["p_holm"] = adjusted[name]

    return {"per_group": per_group, "pairwise": pairwise, "n_rows": len(rows)}


def print_report(report: dict) -> None:
    print("=" * 92)
    print("STATISTICAL RESULTS  (95% bootstrap CIs; McNemar for pairwise significance)")
    print("=" * 92)
    pg = report["per_group"]
    if not pg:
        print("  no scored predictions found.")
        return
    hdr = f"{'model / strategy':<30}{'n':>6}{'F1 [95% CI]':>24}{'MCC':>9}{'bal.acc':>9}{'parse!':>9}"
    print(hdr)
    print("-" * 92)
    for name, e in sorted(pg.items(), key=lambda kv: -kv[1]["f1"]["point"]):
        f = e["f1"]
        ci = f"{f['point']:.3f} [{f['ci_low']:.3f},{f['ci_high']:.3f}]"
        pf = e.get("parse_fail_rate", 0)
        flag = f"{pf*100:.0f}%" + ("!!" if pf > 0.2 else "")
        print(f"{name:<30}{e['n']:>6}{ci:>24}"
              f"{e['mcc']['point']:>9.3f}{e['balanced_accuracy']['point']:>9.3f}{flag:>9}")

    # per-language table (F1 point per language)
    langs = sorted({l for e in pg.values() for l in e["by_language"]})
    if langs:
        print("\nPER-LANGUAGE F1")
        print("-" * 92)
        print(f"{'model / strategy':<30}" + "".join(f"{l:>12}" for l in langs))
        for name, e in sorted(pg.items(), key=lambda kv: -kv[1]["f1"]["point"]):
            cells = ""
            for l in langs:
                bl = e["by_language"].get(l)
                cells += f"{bl['point']:>12.3f}" if bl else f"{'-':>12}"
            print(f"{name:<30}{cells}")

    pw = report["pairwise"]
    if pw:
        print("\nPAIRWISE SIGNIFICANCE (McNemar, Holm-corrected)")
        print("-" * 92)
        for name, r in pw.items():
            sig = r.get("significant_holm", r["significant_at_05"])
            verdict = f"{r['better']} better" if sig else "no significant difference"
            print(f"  p={r['p_value']:<9.4f} {'*' if sig else ' '}  {verdict:<26} {name}")
        print("\n  * = significant after Holm-Bonferroni correction for multiple comparisons")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", nargs="*", default=[str(RESULTS / "predictions.jsonl")])
    ap.add_argument("--glob", default="")
    ap.add_argument("--n-boot", type=int, default=2000)
    ap.add_argument("--out", default=str(RESULTS / "statistical_report.json"))
    args = ap.parse_args()

    paths = list(args.pred)
    if args.glob:
        paths = globmod.glob(args.glob)
    rows = load(paths)
    if not rows:
        sys.exit(f"no predictions found in {paths}")

    report = analyse(rows, args.n_boot)
    Path(args.out).write_text(json.dumps(report, indent=1), encoding="utf-8")
    print_report(report)
    print(f"\nsummary -> {args.out}")


if __name__ == "__main__":
    main()
