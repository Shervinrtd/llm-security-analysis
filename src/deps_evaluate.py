"""Pillar 4, step 3 - evaluate LLMs vs a conventional scanner on dependency risk.

Task: given a project manifest, name the dependencies that have a known
vulnerability. Scoring is per dependency entry, not per manifest, so a model
that flags everything is punished by precision.

Two baselines are included:

  osv_lookup   an exact database lookup against the OSV advisory index. This is
               what conventional scanners (osv-scanner, pip-audit, npm audit)
               do, and it is effectively an upper bound: the ground truth was
               derived from the same feed, so it should score near-perfectly.
               Its purpose is to frame the LLM numbers, not to compete.

  llm          the model sees only the manifest text and must rely on its own
               knowledge of which versions are affected.

The gap between them is the interesting result: it measures how much of a
vulnerability database an LLM has actually internalised - and how often it
invents one.

    python src/deps_evaluate.py --models stub --strategies zero_shot,cot --limit 30
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import models as M

RESULTS = C.DATA / "results"
RESULTS.mkdir(parents=True, exist_ok=True)

SYSTEM = ("You are a software supply-chain security analyst performing defensive "
          "dependency review. You identify dependencies with known published "
          "vulnerabilities so they can be upgraded.")

ANSWER_SPEC = (
    'Reply with ONE JSON object and nothing else:\n'
    '{"vulnerable_dependencies": [{"package": "<name>", "version": "<version>", '
    '"reason": "<short reason>"}]}\n'
    'Include ONLY dependencies you believe have a known published vulnerability '
    'at the pinned version. Return an empty list if none.'
)


def prompt_zero_shot(case: dict) -> tuple[str, str]:
    user = (f"Review this {case['ecosystem']} manifest ({case['filename']}) and identify "
            f"dependencies pinned to a version with a known published vulnerability.\n\n"
            f"```\n{case['content']}\n```\n\n{ANSWER_SPEC}")
    return SYSTEM, user


def prompt_cot(case: dict) -> tuple[str, str]:
    # NOTE: kept byte-for-byte stable on purpose. The salvage path in parse_reply
    # already recovers truncated chain-of-thought replies, so changing this prompt
    # would only orphan the cached responses and force fresh (quota-costing) calls
    # for no correctness gain. If a future change here is needed, expect a re-run.
    user = (f"Review this {case['ecosystem']} manifest ({case['filename']}).\n\n"
            f"```\n{case['content']}\n```\n\n"
            "Work through it carefully:\n"
            "1. For each dependency, recall whether that package has known published advisories.\n"
            "2. If it does, compare the PINNED version against the affected version range.\n"
            "3. A package is only vulnerable if the pinned version falls inside that range - "
            "a package with past advisories pinned to a patched version is NOT vulnerable.\n"
            "4. Exclude anything you are not reasonably confident about.\n\n"
            f"Then give the final answer.\n{ANSWER_SPEC}")
    return SYSTEM, user


STRATEGIES = {"zero_shot": prompt_zero_shot, "cot": prompt_cot}

JSON_OBJ_RE = re.compile(r"\{.*\}", re.S)


# salvage: a package entry, wherever it appears, even if the JSON is truncated
PKG_RE = re.compile(r'"package"\s*:\s*"([^"]+)"')
VDEP_MARKER = re.compile(r'"vulnerable_dependencies"\s*:')


def parse_reply(text: str) -> tuple[list[str], bool]:
    """Return (flagged package names, parsed_strictly).

    A chain-of-thought reply can reason until it runs out of the token budget,
    leaving the final JSON truncated - which made 90% of one model's cot run
    unparseable and dragged its score to nonsense. So after the strict attempt
    fails, salvage: if the answer STARTED (the vulnerable_dependencies key is
    present), pull every "package":"..." out of it, even from a JSON that never
    got its closing braces. The salvage only reads the answer's own field name,
    so it cannot invent packages the model did not list.
    """
    if not text:
        return [], False
    # 1. strict: a well-formed JSON object
    for chunk in (re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
                  + JSON_OBJ_RE.findall(text)):
        try:
            obj = json.loads(chunk)
        except Exception:
            continue
        items = obj.get("vulnerable_dependencies")
        if isinstance(items, list):
            names = []
            for it in items:
                if isinstance(it, dict) and it.get("package"):
                    names.append(str(it["package"]).strip())
                elif isinstance(it, str):
                    names.append(it.strip())
            return names, True
    # 2. salvage: the answer began but the JSON is malformed/truncated
    if VDEP_MARKER.search(text):
        tail = text[VDEP_MARKER.search(text).start():]
        names = [m.group(1).strip() for m in PKG_RE.finditer(tail)]
        # an empty list is a real answer ("nothing vulnerable"); packages found
        # from a truncated reply are a real answer too
        return names, True
    return [], False


def osv_lookup(case: dict, index: dict) -> list[str]:
    """Conventional scanner baseline: exact (package, version) database lookup."""
    out = []
    for d in case["dependencies"]:
        if (d["package"], d["version"]) in index.get(case["ecosystem"], set()):
            out.append(d["package"])
    return out


def build_index(adv_path: Path) -> dict:
    """(package, affected_version) pairs per ecosystem."""
    idx: dict[str, set] = defaultdict(set)
    for rec in json.loads(adv_path.read_text(encoding="utf-8")):
        for v in rec.get("vulnerable_versions") or []:
            idx[rec["ecosystem"]].add((rec["package"], v))
    return idx


def score(rows: list[dict]) -> dict:
    tp = sum(r["tp"] for r in rows); fp = sum(r["fp"] for r in rows)
    fn = sum(r["fn"] for r in rows); tn = sum(r["tn"] for r in rows)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    total = tp + fp + tn + fn
    hallu = sum(r["hallucinated"] for r in rows)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "accuracy": round((tp + tn) / total, 4) if total else 0.0,
            "manifests": len(rows), "dependency_entries": total,
            "hallucinated_packages": hallu,
            "precision_all_reported": round(tp / (tp + fp + hallu), 4) if tp + fp + hallu else 0.0,
            "f1_all_reported": round(2 * tp / (2 * tp + fp + hallu + fn), 4) if 2 * tp + fp + hallu + fn else 0.0,
            "format_ok": round(sum(1 for r in rows if r["parse_ok"]) / len(rows), 3) if rows else 0,
            "latency_mean_s": round(sum(r["latency_s"] for r in rows) / len(rows), 2) if rows else 0}


def evaluate_case(case: dict, flagged: list[str]) -> dict:
    truth = {d["package"]: d["vulnerable"] for d in case["dependencies"]}
    listed = set(truth)
    flg = {f for f in flagged}
    # packages the model named that are not in the manifest at all
    hallucinated = len(flg - listed)
    flg &= listed
    tp = sum(1 for p in flg if truth[p])
    fp = sum(1 for p in flg if not truth[p])
    fn = sum(1 for p, v in truth.items() if v and p not in flg)
    tn = sum(1 for p, v in truth.items() if not v and p not in flg)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "hallucinated": hallucinated}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(C.PROCESSED / "deps_benchmark.jsonl"))
    ap.add_argument("--advisories", default=str(C.INTERIM / "dep_advisories.json"))
    ap.add_argument("--models", default="stub")
    ap.add_argument("--strategies", default="zero_shot,cot")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default=str(RESULTS / "deps_predictions.jsonl"))
    args = ap.parse_args()

    cases = [json.loads(l) for l in Path(args.data).open(encoding="utf-8") if l.strip()]
    if args.limit:
        cases = cases[:args.limit]
    index = build_index(Path(args.advisories))

    print(f"manifests : {len(cases)}")
    summaries, all_rows = [], []

    # ---- conventional scanner baseline ----
    rows = []
    for c in cases:
        t0 = time.time()
        flagged = osv_lookup(c, index)
        r = evaluate_case(c, flagged)
        r.update({"manifest_id": c["manifest_id"], "ecosystem": c["ecosystem"],
                  "model": "osv_lookup", "strategy": "database",
                  "parse_ok": True, "latency_s": time.time() - t0})
        rows.append(r); all_rows.append(r)
    s = score(rows); s.update({"model": "osv_lookup", "strategy": "database"})
    summaries.append(s)
    print(f"  {'osv_lookup':<18}{'database':<12}P={s['precision']:.3f} R={s['recall']:.3f} F1={s['f1']:.3f}")

    # ---- LLMs ----
    names = [m.strip() for m in args.models.split(",") if m.strip()]
    strats = [x.strip() for x in args.strategies.split(",") if x.strip()]
    missing = [m for m in names if not M.get(m).is_available()]
    if missing:
        print(f"\n  (skipping {missing} - no API key set; available: {M.available()})")
        names = [m for m in names if m not in missing]

    for mn in names:
        prov = M.get(mn)
        for st in strats:
            rows = []
            for i, c in enumerate(cases, 1):
                sysmsg, user = STRATEGIES[st](c)
                rep = prov.generate(sysmsg, user)
                flagged, ok = parse_reply(rep.text)
                r = evaluate_case(c, flagged)
                r.update({"manifest_id": c["manifest_id"], "ecosystem": c["ecosystem"],
                          "model": mn, "strategy": st, "parse_ok": ok,
                          "latency_s": rep.latency_s})
                rows.append(r); all_rows.append(r)
                if i % 25 == 0:
                    print(f"    {mn}/{st}: {i}/{len(cases)}")
            s = score(rows); s.update({"model": mn, "strategy": st})
            summaries.append(s)
            print(f"  {mn:<18}{st:<12}P={s['precision']:.3f} R={s['recall']:.3f} "
                  f"F1={s['f1']:.3f} halluc={s['hallucinated_packages']}")

    out = Path(args.out)
    with out.open("w", encoding="utf-8") as fh:
        for r in all_rows:
            fh.write(json.dumps(r) + "\n")
    (out.with_name("deps_summary.json")).write_text(json.dumps(summaries, indent=1), encoding="utf-8")

    print("\n" + "=" * 92)
    print(f"{'model':<18}{'strategy':<12}{'prec':>7}{'recall':>8}{'F1':>7}{'TP':>6}{'FP':>6}{'FN':>6}{'halluc':>8}")
    print("-" * 92)
    for s in sorted(summaries, key=lambda x: -x["f1"]):
        print(f"{s['model']:<18}{s['strategy']:<12}{s['precision']:>7.3f}{s['recall']:>8.3f}"
              f"{s['f1']:>7.3f}{s['tp']:>6}{s['fp']:>6}{s['fn']:>6}{s['hallucinated_packages']:>8}")
    print("=" * 92)
    print(f"\npredictions -> {out}")


if __name__ == "__main__":
    main()
