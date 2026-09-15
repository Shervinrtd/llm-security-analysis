"""Dataset statistics and integrity report.

Produces the numbers that go straight into the paper's dataset section, and
re-runs the integrity assertions so a corrupted build never goes unnoticed.

    python src/report_stats.py --data data/processed/dataset.jsonl
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def integrity(recs: list[dict]) -> dict[str, int]:
    issues: Counter = Counter()
    for r in recs:
        if not r["code"].strip():
            issues["empty_code"] += 1
        if r["label"] == 1 and not r["cwe_primary"]:
            issues["vulnerable_without_cwe"] += 1
        if r["label"] == 0 and r["cwe_primary"]:
            issues["safe_with_cwe"] += 1
        if r["loc"] != len(r["code"].splitlines()):
            issues["loc_mismatch"] += 1
        if r["version"] == "pre" and not r["changed_lines_in_func"]:
            issues["pre_without_changed_lines"] += 1
        if r["language"] not in C.TARGET_LANGS:
            issues["unexpected_language"] += 1

    hashes = [r["func_hash"] for r in recs]
    if len(hashes) != len(set(hashes)):
        issues["duplicate_func_hash"] = len(hashes) - len(set(hashes))

    pairs: dict[str, dict] = defaultdict(dict)
    for r in recs:
        if r.get("pair_id"):
            pairs[r["pair_id"]][r["version"]] = r
    for pid, p in pairs.items():
        if "pre" not in p or "post" not in p:
            issues["incomplete_pair"] += 1
        elif p["pre"]["code"] == p["post"]["code"]:
            issues["identical_pair"] += 1
    return dict(issues)


def report(recs: list[dict]) -> str:
    L: list[str] = []
    add = L.append

    total = len(recs)
    vuln = [r for r in recs if r["label"] == 1]
    safe = [r for r in recs if r["label"] == 0]
    pairs = {r["pair_id"] for r in recs if r.get("pair_id")}

    add("=" * 66)
    add("DATASET REPORT")
    add("=" * 66)
    add(f"total function records : {total}")
    add(f"  vulnerable (label=1) : {len(vuln)}")
    add(f"  safe       (label=0) : {len(safe)}")
    if vuln:
        add(f"  vulnerable ratio     : 1 : {len(safe)/max(len(vuln),1):.1f}")
    add(f"matched pre/post pairs : {len(pairs)}")
    add(f"unique CVEs            : {len({r['cve_id'] for r in recs})}")
    add(f"unique repositories    : {len({r['repo'] for r in recs})}")
    add(f"unique commits         : {len({r['commit_sha'] for r in recs})}")

    add("")
    add("-- by language family --")
    fam_v = Counter(r["language_family"] for r in vuln)
    fam_a = Counter(r["language_family"] for r in recs)
    add(f"{'family':<14}{'total':>8}{'vulnerable':>12}{'safe':>8}")
    for fam in sorted(fam_a):
        add(f"{fam:<14}{fam_a[fam]:>8}{fam_v.get(fam,0):>12}{fam_a[fam]-fam_v.get(fam,0):>8}")

    add("")
    add("-- by version --")
    for k, v in sorted(Counter(r["version"] for r in recs).items()):
        add(f"  {k:<12}{v}")

    add("")
    add("-- CWE coverage (vulnerable only) --")
    cwe = Counter(r["cwe_primary"] for r in vuln)
    add(f"  distinct CWEs: {len(cwe)}")
    for c, n in cwe.most_common(15):
        add(f"    {c:<12}{n}")

    add("")
    add("-- severity (vulnerable only) --")
    sev = Counter(r.get("cvss_severity") or "UNKNOWN" for r in vuln)
    for s, n in sev.most_common():
        add(f"  {s:<10}{n}")

    add("")
    add("-- function size (LOC) --")
    locs = [r["loc"] for r in recs]
    if locs:
        qs = statistics.quantiles(locs, n=4) if len(locs) > 3 else [0, 0, 0]
        add(f"  min {min(locs)} | Q1 {qs[0]:.0f} | median {statistics.median(locs):.0f} "
            f"| Q3 {qs[2]:.0f} | max {max(locs)} | mean {statistics.mean(locs):.1f}")

    add("")
    add("-- temporal spread (CVE publication year) --")
    yrs = Counter((r.get("cve_published") or "?")[:4] for r in recs)
    for y, n in sorted(yrs.items()):
        add(f"  {y}: {n}")

    add("")
    add("-- integrity --")
    iss = integrity(recs)
    add("  PASS - no issues detected" if not iss
        else "\n".join(f"  FAIL {k}: {v}" for k, v in iss.items()))
    add("=" * 66)
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(C.PROCESSED / "dataset.jsonl"))
    ap.add_argument("--save", default="", help="also write the report to this path")
    args = ap.parse_args()

    path = Path(args.data)
    if not path.exists():
        sys.exit(f"No dataset at {path}")
    recs = load(path)
    text = report(recs)
    print(text)
    if args.save:
        Path(args.save).write_text(text, encoding="utf-8")
        print(f"\nsaved -> {args.save}")


if __name__ == "__main__":
    main()
