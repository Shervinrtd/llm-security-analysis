"""Pick the best prompting strategy for a model, by measuring them.

Why this works the way it does
------------------------------
The app is asked to "try all prompting strategies, compare them, and use the
best one for the report". There is a catch: on an arbitrary GitHub repository
we have NO ground truth, so on that repo alone we cannot tell which strategy
was better - every strategy just produces opinions.

So we calibrate where the answers ARE known: a small, stratified sample of our
own labelled benchmark. Each strategy is scored with real metrics (F1 / balanced
accuracy / MCC), ranked, and the winner is then used for the repository scan.
That is both what was asked for and methodologically sound - the choice is
evidence-based rather than arbitrary.

Which split to calibrate on
---------------------------
The VALIDATION split, never the test split. Choosing a strategy is a decision
made from data, so the data it is made from is no longer held out: calibrating
on test and then reporting test scores would report the score of the strategy
that happened to look best on that very sample. That is selection-on-test, and
it silently inflates every number downstream.

    train  ->  few-shot examples shown inside the prompt
    val    ->  choosing the prompting strategy      (this file)
    test   ->  measuring how well the choice worked (never touched here)

Results are cached per (model, sample size), so calibration runs once and later
scans reuse it. This matters because free-tier LLMs are rate-limited.
"""
from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import models as M
import prompts as PR
from audit_runtime import check_cancel, ScanCancelled, AnalysisError
from evaluate import run_one, score

CALIB_CACHE = C.CACHE / "calibration"
CALIB_CACHE.mkdir(parents=True, exist_ok=True)

# Strategies compared. Multi-call ones (self_consistency, rci) are excluded by
# default because they cost 3x the requests, which free tiers cannot absorb.
DEFAULT_STRATEGIES = ["zero_shot", "few_shot", "cot_8step", "dataflow"]


def _cache_path(model: str, n: int, strategies: list[str]) -> Path:
    # the split is part of the key: results calibrated on a different split are
    # not interchangeable, and stale caches must not silently survive the change
    tag = f"{model}_{CALIB_SPLIT}_{n}_{'-'.join(sorted(strategies))}"
    return CALIB_CACHE / f"{tag}.json"


CALIB_SPLIT = "val"       # never "test" - see the module docstring


def load_sample(n: int, seed: int = 42) -> tuple[list[dict], list[dict], dict]:
    """A small, label-balanced sample from the VALIDATION split."""
    calib_p = C.PROCESSED / f"{CALIB_SPLIT}.jsonl"
    train_p = C.PROCESSED / "train.jsonl"
    ls_p = C.PROCESSED / "label_space.json"
    if not calib_p.exists():
        raise FileNotFoundError(
            f"No {CALIB_SPLIT} split at {calib_p} - run make_splits.py first. "
            "Calibration deliberately does not fall back to test.jsonl: doing so "
            "would tune the strategy on the data reserved for measuring it.")

    recs = [json.loads(l) for l in calib_p.open(encoding="utf-8") if l.strip()]
    vul = [r for r in recs if r["label"] == 1]
    safe = [r for r in recs if r["label"] == 0]
    rng = random.Random(seed)
    half = max(1, n // 2)
    sample = rng.sample(vul, min(half, len(vul))) + rng.sample(safe, min(n - half, len(safe)))
    rng.shuffle(sample)

    train = [json.loads(l) for l in train_p.open(encoding="utf-8") if l.strip()] \
        if train_p.exists() else []
    ls = json.loads(ls_p.read_text(encoding="utf-8")) if ls_p.exists() \
        else {"classes": [], "prompt_block": ""}
    return sample, train, ls


def calibrate(model_name: str, n_samples: int = 10,
              strategies: list[str] | None = None,
              use_cache: bool = True, progress=None, cancel_event=None) -> dict:
    """Score every strategy for one model; return the ranking and the winner."""
    strategies = strategies or list(DEFAULT_STRATEGIES)
    check_cancel(cancel_event)
    cp = _cache_path(model_name, n_samples, strategies)
    if use_cache and cp.exists():
        try:
            data = json.loads(cp.read_text(encoding="utf-8"))
            if progress:
                progress(f"{model_name}: using cached strategy comparison "
                         f"(winner: {data.get('winner')})")
            return data
        except Exception:
            pass

    provider = M.get(model_name)
    sample, train, ls = load_sample(n_samples)
    results = []

    for strat in strategies:
        if progress:
            progress(f"{model_name}: testing strategy '{strat}' on {len(sample)} labelled samples ...")
        rows, t0 = [], time.time()
        for rec in sample:
            check_cancel(cancel_event)
            ex = PR.sample_examples(train, k=4, seed=42, language=rec.get("language")) \
                if strat == "few_shot" else []
            rows.append(run_one(provider, strat, rec, ls, ex))
        s = score(rows)
        s.update({"strategy": strat, "wall_s": round(time.time() - t0, 1)})
        results.append(s)
        if progress:
            progress(f"    {strat}: F1={s['f1']:.3f}  balanced-acc={s['balanced_accuracy']:.3f}  "
                     f"format-ok={s['format_adherence']:.2f}")

    # Rank by F1, then balanced accuracy, then how reliably the model followed
    # the requested answer format (a strategy whose output cannot be parsed is
    # useless in production even if it scores well).
    ranked = sorted(results,
                    key=lambda s: (s["f1"], s["balanced_accuracy"], s["format_adherence"]),
                    reverse=True)
    out = {
        "model": model_name,
        "n_samples": len(sample),
        "strategies_tested": strategies,
        "results": ranked,
        "winner": ranked[0]["strategy"] if ranked else "zero_shot",
        "winner_f1": ranked[0]["f1"] if ranked else 0.0,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    cp.write_text(json.dumps(out, indent=1), encoding="utf-8")
    if progress:
        progress(f"{model_name}: BEST strategy = '{out['winner']}' (F1={out['winner_f1']:.3f})")
    return out


def calibrate_many(model_names: list[str], n_samples: int = 10,
                   strategies: list[str] | None = None, progress=None, cancel_event=None) -> dict:
    """Calibrate several models; also pick the overall best model+strategy."""
    per_model = {}
    for mn in model_names:
        try:
            check_cancel(cancel_event)
            result = calibrate(mn, n_samples, strategies, progress=progress, cancel_event=cancel_event)
            valid = [s for s in result.get("results", [])
                     if not s.get("api_errors") and s.get("format_adherence") == 1.0 and s.get("n", 0) > 0]
            if not valid:
                raise AnalysisError("No strategy completed calibration without request or parsing errors.")
            per_model[mn] = dict(result, results=valid, winner=valid[0]["strategy"], winner_f1=valid[0]["f1"])
        except ScanCancelled:
            raise
        except Exception as e:
            if progress:
                progress(f"{mn}: calibration unavailable ({type(e).__name__}). Check quota and benchmark files.")
    best_model, best = None, -1.0
    for mn, r in per_model.items():
        if r.get("winner_f1", 0) > best:
            best, best_model = r["winner_f1"], mn
    return {"per_model": per_model, "best_model": best_model,
            "best_strategy": per_model.get(best_model, {}).get("winner", "zero_shot"),
            "best_f1": best}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="stub")
    ap.add_argument("--n", type=int, default=8)
    ap.add_argument("--strategies", default=",".join(DEFAULT_STRATEGIES))
    ap.add_argument("--no-cache", action="store_true")
    a = ap.parse_args()
    names = [x.strip() for x in a.models.split(",") if x.strip()]
    strats = [x.strip() for x in a.strategies.split(",") if x.strip()]
    for mn in names:
        r = calibrate(mn, a.n, strats, use_cache=not a.no_cache, progress=lambda m: print("  " + m))
        print(f"\n{mn}: winner = {r['winner']} (F1={r['winner_f1']:.3f})")
        for s in r["results"]:
            print(f"   {s['strategy']:<12} F1={s['f1']:.3f} BAcc={s['balanced_accuracy']:.3f} "
                  f"MCC={s['mcc']:+.3f} fmt={s['format_adherence']:.2f}")
