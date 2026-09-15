"""Experiment runner: dataset x prompting strategy x model -> metrics.

Implements the metric suite fixed in the Project Scope Note:

  binary       Accuracy, Precision, Recall, F1, Balanced Accuracy, MCC
  multi-class  CWE accuracy, strict and lenient (parent/child credited,
               as Tamberg & Bahsi do), plus macro-F1 over CWE classes
  operational  latency, call count, format-adherence rate

Balanced Accuracy and MCC are reported because our corpus is deliberately
imbalanced; plain accuracy is misleading there. Format adherence is reported
because papers 4 and 6 both found models drift from the requested output
shape - patching that over silently would hide a real weakness.

    python src/evaluate.py --models stub --strategies zero_shot,cot_8step --limit 40
"""
from __future__ import annotations

import argparse
import json
import hashlib
import os
import math
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import cwe_catalog as K
import models as M
import prompts as PR
from research_identity import record_uid

RESULTS = C.DATA / "results"
RESULTS.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------------ metrics
def binary_metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    total = tp + fp + tn + fn
    acc = (tp + tn) / total if total else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    tpr = rec
    tnr = tn / (tn + fp) if (tn + fp) else 0.0
    bacc = (tpr + tnr) / 2
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / denom) if denom else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": round(acc, 4), "precision": round(prec, 4),
            "recall": round(rec, 4), "f1": round(f1, 4),
            "balanced_accuracy": round(bacc, 4), "mcc": round(mcc, 4)}


def macro_f1_by_cwe(rows: list[dict], lenient: bool) -> float:
    """Macro-F1 over CWE classes, computed on truly-vulnerable samples."""
    classes = {r["true_cwe"] for r in rows if r["true_label"] == 1 and r["true_cwe"]}
    if not classes:
        return 0.0
    f1s = []
    for cls in classes:
        tp = fp = fn = 0
        for r in rows:
            pred, truth = r.get("pred_cwe"), r.get("true_cwe")
            pred_is = bool(pred) and (K.matches(pred, cls, lenient) if pred else False)
            true_is = r["true_label"] == 1 and truth == cls
            if pred_is and true_is:
                tp += 1
            elif pred_is and not true_is:
                fp += 1
            elif true_is and not pred_is:
                fn += 1
        p = tp / (tp + fp) if (tp + fp) else 0.0
        rc = tp / (tp + fn) if (tp + fn) else 0.0
        f1s.append(2 * p * rc / (p + rc) if (p + rc) else 0.0)
    return round(sum(f1s) / len(f1s), 4)


def score(rows: list[dict]) -> dict:
    tp = sum(1 for r in rows if r["pred_label"] == 1 and r["true_label"] == 1)
    fp = sum(1 for r in rows if r["pred_label"] == 1 and r["true_label"] == 0)
    tn = sum(1 for r in rows if r["pred_label"] == 0 and r["true_label"] == 0)
    fn = sum(1 for r in rows if r["pred_label"] == 0 and r["true_label"] == 1)
    out = binary_metrics(tp, fp, tn, fn)

    vuln_rows = [r for r in rows if r["true_label"] == 1]
    caught = [r for r in vuln_rows if r["pred_label"] == 1]
    out["cwe_acc_strict"] = round(
        sum(1 for r in caught if r.get("pred_cwe") and
            K.matches(r["pred_cwe"], r["true_cwe"], lenient=False)) / len(vuln_rows), 4
    ) if vuln_rows else 0.0
    out["cwe_acc_lenient"] = round(
        sum(1 for r in caught if r.get("pred_cwe") and
            K.matches(r["pred_cwe"], r["true_cwe"], lenient=True)) / len(vuln_rows), 4
    ) if vuln_rows else 0.0
    out["cwe_macro_f1_lenient"] = macro_f1_by_cwe(rows, lenient=True)

    out["n"] = len(rows)
    out["format_adherence"] = round(sum(1 for r in rows if r.get("parse_ok")) / len(rows), 4) if rows else 0.0
    out["unparsed"] = sum(1 for r in rows if r["pred_label"] is None)
    out["api_errors"] = sum(1 for r in rows if not r.get("ok", True))
    lat = [r.get("latency_s", 0.0) for r in rows]
    out["latency_mean_s"] = round(sum(lat) / len(lat), 2) if lat else 0.0
    out["total_calls"] = sum(r.get("calls", 1) for r in rows)
    return out


# ------------------------------------------------------------------- runner
def run_one(provider: M.Provider, strategy: str, rec: dict, label_space: dict,
            examples: list[dict]) -> dict:
    p = PR.build(strategy, rec, label_space, examples=examples)
    calls = 0

    if strategy == "self_consistency":
        # k independent samples at a non-zero temperature, majority verdict
        old_t = provider.temperature
        provider.temperature = 0.7
        votes, cwes, ok_all, lat = [], [], True, 0.0
        for i in range(p.n_calls):
            rep = provider.generate(p.system, p.user + f"\n\n[sample {i+1}]")
            calls += 1
            lat += rep.latency_s
            ok_all &= rep.ok
            a = PR.parse_answer(rep.text)
            if a["vulnerable"] is not None:
                votes.append(a["vulnerable"])
            if a["cwe"]:
                cwes.append(a["cwe"])
        provider.temperature = old_t
        pred = (sum(votes) > len(votes) / 2) if votes else None
        ans = {"vulnerable": pred,
               "cwe": Counter(cwes).most_common(1)[0][0] if cwes else None,
               "reason": "majority vote", "parse_ok": bool(votes)}
        reply_ok, latency = ok_all, lat

    elif strategy == "rci":
        # answer -> critique -> revise (stateless provider, so we carry context)
        r1 = provider.generate(p.system, p.user); calls += 1
        r2 = provider.generate(
            p.system, f"{p.user}\n\nYour answer:\n{r1.text}\n\n{PR.RCI_CRITIQUE}"); calls += 1
        r3 = provider.generate(
            p.system,
            f"{p.user}\n\nYour answer:\n{r1.text}\n\nCritique:\n{r2.text}\n\n{PR.RCI_REVISE}")
        calls += 1
        ans = PR.parse_answer(r3.text)
        reply_ok = r1.ok and r2.ok and r3.ok
        latency = r1.latency_s + r2.latency_s + r3.latency_s

    else:
        rep = provider.generate(p.system, p.user); calls += 1
        ans = PR.parse_answer(rep.text)
        reply_ok, latency = rep.ok, rep.latency_s

    return {
        "sample_id": rec["sample_id"], "language": rec["language"],
        "record_uid": record_uid(rec), "func_hash": rec.get("func_hash"),
        "repo": rec.get("repo"), "cve_id": rec.get("cve_id"),
        "language_family": rec["language_family"],
        "true_label": rec["label"], "true_cwe": rec.get("cwe_primary"),
        "pred_label": (None if ans["vulnerable"] is None else int(ans["vulnerable"])),
        "pred_cwe": ans["cwe"], "parse_ok": ans.get("parse_ok", False),
        "reason": (ans.get("reason") or "")[:400],
        "ok": reply_ok, "latency_s": latency, "calls": calls,
        "model": provider.name, "strategy": strategy,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(C.PROCESSED / "test.jsonl"))
    ap.add_argument("--train", default=str(C.PROCESSED / "train.jsonl"),
                    help="source of few-shot examples")
    ap.add_argument("--label-space", default=str(C.PROCESSED / "label_space.json"))
    ap.add_argument("--models", default="stub")
    ap.add_argument("--strategies", default=",".join(PR.CORE))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=None, help="New output file; existing results are not overwritten")
    args = ap.parse_args()
    out = Path(args.out) if args.out else RESULTS/"vulnerability_v2"/time.strftime("%Y%m%d-%H%M%S")/"predictions.jsonl"
    sp = out.with_suffix(".summary.json")
    manifest_path = out.with_suffix(".manifest.json")
    if any(p.exists() for p in (out,sp,manifest_path)):
        sys.exit("Refusing to overwrite an existing experiment; select a new output path")
    out.parent.mkdir(parents=True,exist_ok=True)

    data_path = Path(args.data)
    if not data_path.exists():
        sys.exit(f"No evaluation data at {data_path} - run finalize.py first.")
    recs = [json.loads(l) for l in data_path.open(encoding="utf-8") if l.strip()]
    if args.limit:
        rng = random.Random(args.seed)
        recs = rng.sample(recs, min(args.limit, len(recs)))

    label_space = json.loads(Path(args.label_space).read_text(encoding="utf-8"))
    train = []
    tp = Path(args.train)
    if tp.exists():
        train = [json.loads(l) for l in tp.open(encoding="utf-8") if l.strip()]

    model_names = [m.strip() for m in args.models.split(",") if m.strip()]
    strategies = [s.strip() for s in args.strategies.split(",") if s.strip()]
    manifest = {"schema_version":2,"seed":args.seed,"models":model_names,"strategies":strategies,
                "selected_record_uids":[record_uid(r) for r in recs],
                "input_sha256":{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (data_path,tp,Path(args.label_space)) if p.exists()},
                "source_sha256":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob("*.py")},
                "status":"started","started_at":time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    manifest_path.write_text(json.dumps(manifest,indent=2),encoding="utf-8")

    missing = [m for m in model_names if not M.get(m).is_available()]
    if missing:
        sys.exit(f"No API key for: {missing}. Set the env var(s), or use --models stub. "
                 f"Available now: {M.available()}")

    print(f"eval set  : {len(recs)} samples ({data_path.name})")
    print(f"models    : {model_names}")
    print(f"strategies: {strategies}\n")

    all_rows: list[dict] = []
    summaries: list[dict] = []
    for mname in model_names:
        provider = M.get(mname)
        for strat in strategies:
            t0 = time.time()
            rows = []
            for i, rec in enumerate(recs, 1):
                ex = PR.sample_examples(train, k=4, seed=args.seed,
                                        language=rec.get("language")) if strat == "few_shot" else []
                row = run_one(provider, strat, rec, label_space, ex)
                rows.append(row)
                with out.open("a",encoding="utf-8") as checkpoint:
                    checkpoint.write(json.dumps(row,ensure_ascii=False)+"\n")
                    checkpoint.flush()
                    os.fsync(checkpoint.fileno())
                if i % 25 == 0:
                    print(f"  {mname}/{strat}: {i}/{len(recs)}")
            s = score(rows)
            s.update({"model": mname, "strategy": strat,
                      "wall_s": round(time.time() - t0, 1)})
            summaries.append(s)
            all_rows.extend(rows)
            print(f"  {mname:<20}{strat:<18}"
                  f"F1={s['f1']:.3f} BAcc={s['balanced_accuracy']:.3f} "
                  f"MCC={s['mcc']:+.3f} CWE(len)={s['cwe_acc_lenient']:.3f} "
                  f"fmt={s['format_adherence']:.2f}")

    sp.write_text(json.dumps(summaries, indent=1), encoding="utf-8")
    manifest["status"] = "complete"
    manifest["n_prediction_rows"] = len(all_rows)
    manifest_path.write_text(json.dumps(manifest,indent=2),encoding="utf-8")

    print("\n" + "=" * 96)
    print(f"{'model':<20}{'strategy':<18}{'F1':>7}{'BAcc':>7}{'MCC':>8}"
          f"{'CWEs':>7}{'CWEl':>7}{'fmt':>6}{'calls':>7}")
    print("-" * 96)
    for s in sorted(summaries, key=lambda x: -x["f1"]):
        print(f"{s['model']:<20}{s['strategy']:<18}{s['f1']:>7.3f}"
              f"{s['balanced_accuracy']:>7.3f}{s['mcc']:>+8.3f}"
              f"{s['cwe_acc_strict']:>7.3f}{s['cwe_acc_lenient']:>7.3f}"
              f"{s['format_adherence']:>6.2f}{s['total_calls']:>7}")
    print("=" * 96)
    print(f"\npredictions -> {out}\nsummary     -> {sp}")


if __name__ == "__main__":
    main()
