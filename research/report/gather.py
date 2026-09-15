"""Gather every number needed for the REVISED report into one JSON.

Portable: all paths are derived from this file's location and from the
project root, no user- or machine-specific paths. Run from anywhere:

    python research/report/gather.py

This is a post-hoc methodological audit, not a new experiment. Historical
pillar summaries (data/results/*.json) are read as before for descriptive
numbers; output/experiment-audit/audit.json is merged in as the corrected/
supplementary reanalysis (582-row sensitivity set, cluster-bootstrap CIs,
repo-bench descriptive-only rates, label-review confusion matrix, split
overlap, trusted-corpus reuse warning). Where the two disagree, the audit
numbers are what the revised narrative in build_report_v2.py uses; the
historical numbers are kept alongside, explicitly labelled, not replaced
silently.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # .../vulndataset
BUILD = ROOT / "output" / "report_build"
BUILD.mkdir(parents=True, exist_ok=True)
OUT = BUILD / "report_data.json"
AUDIT_PATH = ROOT / "output" / "experiment-audit" / "audit.json"
VALIDITY_PATH = ROOT / "output" / "experiment-audit" / "validity_checks.json"
PERTURB_V2_PATH = ROOT / "output" / "experiment-audit" / "perturbation-v2.summary.json"

D: dict = {}

# ---------------------------------------------------------------- audit
if AUDIT_PATH.exists():
    D["audit"] = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
else:
    print(f"WARNING: no audit.json found at {AUDIT_PATH} - revised claims cannot be "
          "computed. Run the audit process first.", file=sys.stderr)
    D["audit"] = {}

D["validity_checks"] = (json.loads(VALIDITY_PATH.read_text(encoding="utf-8"))
                        if VALIDITY_PATH.exists() else {})
D["perturbation_v2"] = (json.loads(PERTURB_V2_PATH.read_text(encoding="utf-8"))
                        if PERTURB_V2_PATH.exists() else {})

# ---------------------------------------------------------------- main dataset
lang = Counter(); lab = Counter(); cwe = Counter(); fam = Counter()
lang_lab = defaultdict(lambda: Counter())
cves = set(); repos = set(); n = 0
loc_vals = []
ds_path = ROOT / "data/processed/dataset_merged.jsonl"
if ds_path.exists():
    for line in ds_path.open(encoding="utf-8"):
        r = json.loads(line); n += 1
        lang[r["language"]] += 1; lab[r["label"]] += 1; fam[r["language_family"]] += 1
        lang_lab[r["language"]][r["label"]] += 1
        if r.get("cwe_primary"):
            cwe[r["cwe_primary"]] += 1
        if r.get("cve_id"):
            cves.add(r["cve_id"])
        if r.get("repo"):
            repos.add(r["repo"])
        if r.get("loc"):
            loc_vals.append(r["loc"])

sys.path.insert(0, str(ROOT / "src"))
try:
    import cwe_catalog as K
    cwe_names = {c: K.name_of(c) for c, _ in cwe.most_common(12)}
except Exception:
    cwe_names = {}

D["dataset"] = {
    "total": n, "vulnerable": lab[1], "safe": lab[0],
    "languages": dict(lang), "families": dict(fam),
    "cves": len(cves), "repos": len(repos), "cwe_types": len(cwe),
    "top_cwe": cwe.most_common(10), "cwe_names": cwe_names,
    "lang_label": {k: dict(v) for k, v in lang_lab.items()},
    "splits": {s: sum(1 for _ in (ROOT / f"data/processed/{s}.jsonl").open(encoding="utf-8"))
               for s in ("train", "val", "test")} if (ROOT / "data/processed/train.jsonl").exists() else {},
}
if loc_vals:
    loc_vals.sort()
    D["dataset"]["loc_median"] = loc_vals[len(loc_vals) // 2]
    D["dataset"]["loc_p90"] = loc_vals[int(len(loc_vals) * 0.9)]

# ---------------------------------------------------------------- pillar benchmarks
D["benchmarks"] = {}
for f in ("deps_benchmark", "secrets_benchmark", "malware_benchmark"):
    p = ROOT / f"data/processed/{f}.jsonl"
    if p.exists():
        D["benchmarks"][f] = sum(1 for _ in p.open(encoding="utf-8"))


def load(name):
    p = ROOT / "data/results" / name
    if p.exists():
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else [d]
    return []


D["results"] = {
    "vuln": load("summary.json"),
    "deps": load("deps_summary.json"),
    "secrets": load("secrets_summary.json"),
    "malware": load("malware_summary.json"),
}

sr = ROOT / "data/results/statistical_report.json"
if sr.exists():
    D["vuln_stats_historical"] = json.loads(sr.read_text(encoding="utf-8"))

for key, fn in (("fp", "fp_corpus_summary.json"), ("evasion", "evasion_summary.json"),
                ("interp", "interpretability_summary.json"),
                ("repo_bench_historical", "repo_bench_summary.json")):
    p = ROOT / "data/results" / fn
    if p.exists():
        D[key] = json.loads(p.read_text(encoding="utf-8"))

# ---------------------------------------------------------------- interpretability,
# recomputed honestly here rather than carrying forward a hand-typed figure.
if D.get("interp"):
    tot_n = tot_grounded = tot_halluc = 0
    per_strategy = []
    for e in D["interp"]:
        f = e.get("findings", {})
        nf = f.get("n", 0)
        per_strategy.append({
            "model": e.get("model"), "strategy": e.get("strategy"),
            "n_findings": nf,
            "grounded": f.get("grounded"),
            "explanations_with_hallucination": f.get("explanations_with_hallucination"),
            "hallucination_rate": (f.get("explanations_with_hallucination", 0) / nf) if nf else None,
            "true_positive_composite": e.get("true_positives", {}).get("composite"),
            "true_positive_located": e.get("true_positives", {}).get("located"),
        })
        tot_n += nf
        tot_grounded += (f.get("grounded") or 0) * nf
        tot_halluc += f.get("explanations_with_hallucination", 0)
    D["interp_derived"] = {
        "per_strategy": per_strategy,
        "n_total_findings": tot_n,
        "grounded_weighted_mean": (tot_grounded / tot_n) if tot_n else None,
        "hallucination_rate_overall": (tot_halluc / tot_n) if tot_n else None,
        "models_covered": sorted({e.get("model") for e in D["interp"]}),
        "note": "only local-qwen-coder was scored by this rubric; no gemini-flash "
                "interpretability run exists in data/results/interpretability_summary.json.",
    }

# ---------------------------------------------------------------- label-review
# derived agreement stats with an explicit, disclosed treatment of "Unclear",
# computed from the audit's confusion matrix rather than re-deriving from raw CSVs.
lr_audit = D["audit"].get("label_review", {})
conf = lr_audit.get("confusion_human_rows_llm_columns", {})
if conf:
    VULN = {"CORRECT", "WRONG_CWE"}
    n_shared = lr_audit.get("n_shared", sum(conf.values()))
    exact = sum(v for k, v in conf.items() if k.split("/")[0] == k.split("/")[1])

    def bucket(v: str) -> str:
        if v == "UNCLEAR":
            return "unclear"
        return "vuln" if v in VULN else "not_vuln"

    agree3 = disagree_reversal = 0
    agree_excl_unclear = n_excl_unclear = 0
    reversal_cells = []
    for cell, cnt in conf.items():
        h, l = cell.split("/")
        bh, bl = bucket(h), bucket(l)
        if bh == bl:
            agree3 += cnt
        if bh != "unclear" and bl != "unclear":
            n_excl_unclear += cnt
            if bh == bl:
                agree_excl_unclear += cnt
        # "human stricter" = human bucket ranked below llm bucket on
        # {not_vuln < unclear < vuln}; flag the reverse direction explicitly.
        rank = {"not_vuln": 0, "unclear": 1, "vuln": 2}
        if bh != bl and rank[bh] > rank[bl]:
            reversal_cells.append({"cell": cell, "n": cnt})

    human_counts = lr_audit.get("counts", {}).get("human", {})
    llm_counts = lr_audit.get("counts", {}).get("llm", {})
    cats = ("CORRECT", "WRONG_CWE", "NOT_VULNERABLE", "UNCLEAR")
    pe = sum((human_counts.get(c, 0) / n_shared) * (llm_counts.get(c, 0) / n_shared) for c in cats)
    po = exact / n_shared
    kappa = (po - pe) / (1 - pe) if pe < 1 else 0.0

    D["label_review_derived"] = {
        "n_shared": n_shared,
        "exact_4way_agreement": po,
        "three_way_agreement_incl_unclear": agree3 / n_shared,
        "binary_agreement_excluding_unclear_either_rater": {
            "agree": agree_excl_unclear, "n": n_excl_unclear,
            "rate": (agree_excl_unclear / n_excl_unclear) if n_excl_unclear else None,
        },
        "cohen_kappa_4way": kappa,
        "direction_reversal_cells": reversal_cells,
        "note": "bucket = {CORRECT, WRONG_CWE} -> vuln; NOT_VULNERABLE -> not_vuln; "
                "UNCLEAR -> unclear (its own category, not merged into either side).",
    }

# Explicit run selection: never silently pick the latest directory.
import hashlib
import perturbation_eval as PE
runs = {"repo": ROOT/"data/results/repo_bench_v2/20260915-022618",
        "perturbation": ROOT/"data/results/perturbation_v2/20260915-025616"}
D["followup_runs"] = {}
for kind, directory in runs.items():
    manifest = json.loads((directory/"predictions.manifest.json").read_text())
    if manifest["status"] != "complete":
        raise ValueError(f"Incomplete follow-up run: {directory}")
    rows = PE.read_rows(directory/"predictions.jsonl")
    summary = json.loads((directory/"predictions.summary.json").read_text())
    item = {"path": str(directory.relative_to(ROOT)), "manifest": manifest, "summary": summary,
            "sha256": {p.name: PE.digest(p) for p in directory.glob("*.json*")}}
    if kind == "perturbation":
        assert PE.summarise(rows) == summary, "Paired summary mismatch"
        assert len({(r['sample_id'],r['detector']) for r in rows}) == len(rows)
        assert PE.digest(ROOT/'data/processed/malware_benchmark.jsonl') == manifest['source_sha256']
        assert PE.digest(ROOT/'output/experiment-audit/perturbation-v2.jsonl') == manifest['fixtures_sha256']
        PE.pairs(PE.read_rows(ROOT/'data/processed/malware_benchmark.jsonl'),
                 PE.read_rows(ROOT/'output/experiment-audit/perturbation-v2.jsonl'))
        item['cached_responses'] = sum(r[a].get('cached',False) for r in rows for a in ('original','transformed'))
    else:
        assert len({r['case_id'] for r in rows}) == len(rows)
        assert all(not r['detected'] or r['selected'] for r in rows)
        assert all('selected_files' in r['coverage'] for r in rows)
        item['counts'] = {k: sum(bool(r[k]) for r in rows) for k in ('selected','detected','localised','cwe_strict')}
        item['n_repos'] = len({r['repo'] for r in rows})
        assert len(rows) == manifest['n_scored'] == summary['n_cases']
    D['followup_runs'][kind] = item

OUT.write_text(json.dumps(D, indent=1, default=str), encoding="utf-8")
print("gathered ->", OUT)
print("dataset total:", D["dataset"].get("total"))
print("audit present:", bool(D["audit"]))
print("label_review_derived:", D.get("label_review_derived"))
print("interp_derived:", D.get("interp_derived", {}).get("grounded_weighted_mean"),
      D.get("interp_derived", {}).get("hallucination_rate_overall"))
