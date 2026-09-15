"""Reanalyse saved experiments without model calls or changes to historical data.

Outputs are an explicitly post-hoc sensitivity analysis, not new validation data.
Uses only aggregate predictions and metadata; never executes benchmark fixtures.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import itertools
import json
import math
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
import stats as S

ROOT = Path(__file__).resolve().parents[1]


def read_rows(path):
    with path.open(encoding="utf-8-sig") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def wilson(k, n):
    if not n:
        return {"n": 0, "point": None, "ci_low": None, "ci_high": None}
    z = 1.959963984540054
    p = k / n
    den = 1 + z*z/n
    mid = (p + z*z/(2*n))/den
    half = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))/den
    return {"n": n, "successes": k, "point": p, "ci_low": max(0, mid-half), "ci_high": min(1, mid+half)}


def adjusted_holm(pvalues):
    out, previous = {}, 0.0
    ordered = sorted(pvalues.items(), key=lambda kv: kv[1])
    for i, (name, p) in enumerate(ordered):
        previous = max(previous, min(1.0, p*(len(ordered)-i)))
        out[name] = previous
    return out


def cluster_ci(rows, n_boot=2000, seed=42):
    """Resample whole repositories; preserve within-repository dependence."""
    groups = defaultdict(list)
    for row in rows:
        groups[row["repo"]].append(row)
    totals = []
    for group in groups.values():
        c = S.binary_counts([r["pred"] for r in group], [r["truth"] for r in group])
        totals.append([c[k] for k in ("tp", "fp", "tn", "fn")])
    if not totals:
        return {}
    rng = random.Random(seed)
    vals = {m: [] for m in ("f1", "mcc", "accuracy")}
    for _ in range(n_boot):
        c = [0]*4
        for _ in totals:
            draw = totals[rng.randrange(len(totals))]
            c = [a+b for a,b in zip(c, draw)]
        for metric in vals:
            vals[metric].append(S.METRICS[metric](*c))
    result = {"n_repositories": len(totals), "n_boot": n_boot}
    for metric, values in vals.items():
        values.sort()
        result[metric] = {"ci_low": values[int(.025*n_boot)], "ci_high": values[int(.975*n_boot)-1]}
    return result


def unique_index(rows, key):
    ids = [r[key] for r in rows]
    if len(ids) != len(set(ids)):
        raise ValueError(f"Duplicate {key}; do not silently overwrite predictions")
    return dict(zip(ids, rows))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", type=Path, default=ROOT/"output"/"experiment-audit")
    ap.add_argument("--repo-pred", type=Path, default=ROOT/"data/results/repo_bench_predictions.jsonl",
                    help="Explicit repository-run file; defaults to the historical report input")
    ap.add_argument("--repo-model", default="local-qwen-coder")
    ap.add_argument("--repo-strategy", default="zero_shot")
    args = ap.parse_args()
    processed, results = ROOT/"data"/"processed", ROOT/"data"/"results"
    tracked = list(results.glob("*.json*")) + list(processed.glob("*.jsonl")) + list(processed.glob("label_review_*.csv"))
    if args.repo_pred.resolve() not in {p.resolve() for p in tracked}:
        tracked.append(args.repo_pred.resolve())
    path_key = lambda p: str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p)
    before = {path_key(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked}
    splits = {s: read_rows(processed/f"{s}.jsonl") for s in ("train", "val", "test")}
    all_meta = [r for rows in splits.values() for r in rows]
    meta_counts = Counter(r["sample_id"] for r in all_meta)
    meta = {r["sample_id"]: r for r in all_meta if meta_counts[r["sample_id"]] == 1}
    overlap = {}
    for a,b in itertools.combinations(splits,2):
        overlap[f"{a}/{b}"] = {key: len({r[key] for r in splits[a] if r.get(key)} & {r[key] for r in splits[b] if r.get(key)})
                                for key in ("sample_id", "pair_id", "func_hash", "repo", "cve_id")}
    out = {"analysis_type": "post-hoc reanalysis of historical predictions", "seed": 42,
           "input_sha256": before, "split_overlap": overlap,
           "split_sizes": {s: len(v) for s,v in splits.items()},
           "versions": dict(Counter(r["version"] for r in all_meta)),
           "ambiguous_sample_ids": sum(n > 1 for n in meta_counts.values())}
    predictions = read_rows(results/"predictions.jsonl")
    groups = defaultdict(list)
    for r in predictions:
        groups[f"{r['model']}/{r['strategy']}"].append(r)
    out["vulnerability"] = {}
    paired = {}
    test_ids = {r["sample_id"] for r in splits["test"]}
    development_cves = {r["cve_id"] for s in ("train","val") for r in splits[s]}
    test_path = re.compile(r"(^|/)(tests?|testing|fixtures?|examples?|benchmarks?)(/|$)|(^|/)test_[^/]+|[^/]+_test\.[^/]+$", re.I)
    for key, rows in groups.items():
        original = rows
        duplicate_ids = [sid for sid,n in Counter(r["sample_id"] for r in rows).items() if n > 1]
        rows = [r for r in rows if r["sample_id"] in meta and r["sample_id"] not in duplicate_ids]
        index = unique_index(rows, "sample_id")
        enriched = [dict(r, repo=meta[r["sample_id"]]["repo"], pred=int(r.get("pred_label") == 1), truth=r["true_label"]) for r in rows]
        p,t = [r["pred"] for r in enriched], [r["truth"] for r in enriched]
        counts = S.binary_counts(p,t)
        invalid = sum(r.get("pred_label") is None or not r.get("ok", True) or r.get("parse_ok") is False for r in rows)
        entry = {"n": len(rows), "historical_rows": len(original), "excluded_ambiguous_identity": len(original)-len(rows),
                 "duplicate_prediction_ids": duplicate_ids,
                 "historical_metrics": {m: fn(**S.binary_counts([int(r.get('pred_label')==1) for r in original], [r['true_label'] for r in original])) for m,fn in S.METRICS.items()},
                 "n_unique": len(index), "not_in_test": len(set(index)-test_ids), "invalid": invalid,
                 "counts": counts, "metrics": {m: fn(**counts) for m,fn in S.METRICS.items()},
                 "cluster_bootstrap": cluster_ci(enriched),
                 "always_negative_accuracy": t.count(0)/len(t),
                 "label_disagreements": sum(r["true_label"] != meta[r["sample_id"]]["label"] for r in rows)}
        paired[key] = index
        entry["posthoc_exclusion_sensitivity"] = {}
        for name, subset in {
            "exclude_test_example_fixture_paths": [r for r in enriched if not test_path.search(meta[r["sample_id"]]["file_path"].replace("\\","/"))],
            "exclude_development_cves": [r for r in enriched if meta[r["sample_id"]]["cve_id"] not in development_cves],
        }.items():
            c = S.binary_counts([r["pred"] for r in subset],[r["truth"] for r in subset])
            entry["posthoc_exclusion_sensitivity"][name] = {"n":len(subset), "excluded":len(enriched)-len(subset),
                "counts":c,"metrics":{m:fn(**c) for m,fn in S.METRICS.items()}}
        out["vulnerability"][key] = entry
    out["pairwise_accuracy"] = {}
    raw = {}
    for a,b in itertools.combinations(paired,2):
        ids = sorted(paired[a].keys() & paired[b].keys())
        if not ids:
            continue
        aa,bb = [paired[a][i] for i in ids],[paired[b][i] for i in ids]
        if any(x["true_label"] != y["true_label"] for x,y in zip(aa,bb)):
            raise ValueError("Paired truth-label mismatch")
        res = S.mcnemar([int(r.get("pred_label")==1) for r in aa], [int(r.get("pred_label")==1) for r in bb], [r["true_label"] for r in aa])
        # Recompute full precision before multiple-comparison adjustment.
        x,y = res["a_only_correct"],res["b_only_correct"]
        p = min(1.0, 2*sum(math.comb(x+y,i) for i in range(min(x,y)+1))/2**(x+y)) if x+y else 1.0
        key = f"{a} vs {b}"
        res.update(n_shared=len(ids), p_raw=p)
        res["repository_permutation"] = S.clustered_accuracy_permutation(
            [int(r.get("pred_label")==1) for r in aa], [int(r.get("pred_label")==1) for r in bb],
            [r["true_label"] for r in aa], [meta[i]["repo"] for i in ids])
        out["pairwise_accuracy"][key] = res
        raw[key] = p
    for key,p in adjusted_holm(raw).items():
        out["pairwise_accuracy"][key]["p_holm"] = p
    for key,p in adjusted_holm({k:v["repository_permutation"]["p_value"] for k,v in out["pairwise_accuracy"].items()}).items():
        out["pairwise_accuracy"][key]["repository_permutation"]["p_holm"] = p
    repo_rows = [r for r in read_rows(args.repo_pred) if r["model"] == args.repo_model and r["strategy"] == args.repo_strategy]
    unique_index(repo_rows,"case_id")
    violations = [r["case_id"] for r in repo_rows if r["detected"] and not r["selected"]]
    out["repository_benchmark"] = {"n_cases": len(repo_rows), "n_repositories": len({r["repo"] for r in repo_rows}),
        "detected_without_selected": violations,
        "model":args.repo_model,"strategy":args.repo_strategy,"source":str(args.repo_pred),
        "selection_metrics_valid": bool(repo_rows) and not violations and all(r.get("schema_version") == 2 and "selected_files" in r.get("coverage",{}) for r in repo_rows),
        "selection_warning": "Only schema-v2 rows with saved selection traces can support selection metrics. Legacy paths were recomputed without triage.",
        "partial_target_verification": [r["case_id"] for r in repo_rows if len(set(r["verified_targets"].split('/'))) != 1],
        "rates": {k: wilson(sum(r[k] for r in repo_rows), len(repo_rows)) for k in ("detected", "localised", "cwe_strict")}}
    labels = {name: list(csv.DictReader((processed/f"label_review_{name}.csv").open(encoding="utf-8-sig"))) for name in ("human","llm")}
    li = {k: unique_index(v,"sample_id") for k,v in labels.items()}
    shared = sorted(li["human"].keys() & li["llm"].keys())
    confusion = Counter((li["human"][i]["verdict"],li["llm"][i]["verdict"]) for i in shared)
    out["label_review"] = {"n_shared": len(shared), "confusion_human_rows_llm_columns": {f"{a}/{b}":n for (a,b),n in confusion.items()},
        "counts": {k: dict(Counter(r["verdict"] for r in v)) for k,v in labels.items()},
        "sampling_warning": "Diversity-oriented round-robin sampling of paired positives; unweighted rates describe the 50 reviewed cases, not corpus-wide error. Negatives and orphaned positives were not reviewed."}
    fp = json.loads((results/"fp_corpus_summary.json").read_text())
    out["trusted_corpus"] = {**fp, "wilson_descriptive": wilson(fp["false_dangerous_verdicts"], fp["n_repos"]),
        "one_sided_95_upper_if_iid_zero_failures": 1-.05**(1/fp["n_repos"]),
        "warning": "Reused for detector development; not held-out testing. IID bounds are illustrative, not generalisation guarantees."}
    mal = read_rows(processed/"malware_benchmark.jsonl")
    out["malware_composition"] = {"n":len(mal), "labels":dict(Counter(str(r["is_malicious"]) for r in mal)),
                                  "techniques":dict(Counter(r.get("technique") for r in mal))}
    auxiliary = {}
    for filename,id_field in (("malware_predictions.jsonl","sample_id"),("secrets_predictions.jsonl","file_id"),("deps_predictions.jsonl","manifest_id")):
        ag = defaultdict(list)
        for r in read_rows(results/filename):
            ag[f"{r['model']}/{r['strategy']}"].append(r)
        auxiliary[filename] = {k:{"n":len(v),"n_unique":len({r[id_field] for r in v}),
                                 "parse_failures":sum(r.get("parse_ok") is False for r in v)} for k,v in ag.items()}
        auxiliary[filename]["shared_ids"] = {f"{a} vs {b}":len({r[id_field] for r in ag[a]} & {r[id_field] for r in ag[b]}) for a,b in itertools.combinations(ag,2)}
    out["auxiliary_identity_checks"] = auxiliary
    for p in tracked:
        if hashlib.sha256(p.read_bytes()).hexdigest() != before[path_key(p)]:
            raise RuntimeError(f"Input changed during analysis: {p.name}")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir/"audit.json").write_text(json.dumps(out,indent=2),encoding="utf-8")
    print(json.dumps({"output":str(args.out_dir/"audit.json"), "split_overlap":overlap,
                      "repository_benchmark":out["repository_benchmark"],"label_review":out["label_review"]},indent=2))


if __name__ == "__main__":
    main()
