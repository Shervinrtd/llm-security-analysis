"""Create leakage-safe train / validation / test splits.

Splitting naively by record leaks in three ways, all of which inflate results:

  1. a `pre`/`post` pair split across train and test lets a model memorise one
     half and trivially answer the other;
  2. two functions from the SAME CVE (or the same commit) are near-identical in
     style and fix pattern;
  3. functions from the same repository share idioms and naming conventions.

We therefore group by CVE (default) or by repository (stricter, recommended for
the headline generalisation claim) and assign whole groups to one split.

    python src/make_splits.py --group repo --test 0.2 --val 0.1
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C


def load(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.open(encoding="utf-8") if l.strip()]


def group_key(rec: dict, mode: str) -> str:
    if mode == "repo":
        return rec["repo"]
    if mode == "commit":
        return f"{rec['repo']}@{rec['commit_sha']}"
    return rec["cve_id"]          # default


def split_groups(records: list[dict], mode: str, test_frac: float,
                 val_frac: float, seed: int = 42,
                 stratify_language: bool = True) -> dict[str, str]:
    """Assign each group to train/val/test, balancing vulnerable-sample counts.

    Balancing on the TOTAL vulnerable count alone lets a minority language end
    up almost absent from the test split - in our first build Java landed only
    13 test positives out of 261 available, purely by chance. That would make
    any per-language claim unsupportable.

    With `stratify_language` (default) each split tracks a per-language quota,
    and a group is placed where it best fills the language it actually
    contributes, so every language keeps a usable test share.
    """
    by_group: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_group[group_key(r, mode)].append(r)

    rng = random.Random(seed)
    groups = list(by_group)
    rng.shuffle(groups)

    def vuln_by_lang(rows: list[dict]) -> Counter:
        return Counter(r["language_family"] for r in rows if r["label"] == 1)

    shares = {"train": 1.0 - test_frac - val_frac, "val": val_frac, "test": test_frac}

    if not stratify_language:
        total_vuln = sum(1 for r in records if r["label"] == 1)
        targets = {k: shares[k] * total_vuln for k in shares}
        got = {k: 0 for k in shares}
        assign: dict[str, str] = {}
        groups.sort(key=lambda g: -sum(1 for r in by_group[g] if r["label"] == 1))
        for g in groups:
            n_v = sum(1 for r in by_group[g] if r["label"] == 1)
            deficit = {k: (targets[k] - got[k]) / max(targets[k], 1e-9) for k in targets}
            pick = max(deficit, key=deficit.get)
            assign[g] = pick
            got[pick] += n_v
        return assign

    # --- language-stratified assignment ---
    total_by_lang = vuln_by_lang(records)
    targets = {sp: {lang: shares[sp] * n for lang, n in total_by_lang.items()}
               for sp in shares}
    got = {sp: Counter() for sp in shares}
    assign = {}

    # Place the groups that carry the most positives first; among equals,
    # rarer-language groups go first so they are not left to the last split.
    def priority(g: str) -> tuple:
        vb = vuln_by_lang(by_group[g])
        rarity = min((total_by_lang[l] for l in vb), default=10**9)
        return (-sum(vb.values()), rarity)

    groups.sort(key=priority)

    for g in groups:
        vb = vuln_by_lang(by_group[g])
        if not vb:                       # groups with no positives: fill by size
            sizes = {sp: sum(got[sp].values()) for sp in shares}
            total = sum(sizes.values()) or 1
            pick = max(shares, key=lambda sp: shares[sp] - sizes[sp] / total)
        else:
            # choose the split with the largest unmet need for THIS group's languages
            def need(sp: str) -> float:
                return sum((targets[sp][l] - got[sp][l]) / max(targets[sp][l], 1e-9) * n
                           for l, n in vb.items())
            pick = max(shares, key=need)
        assign[g] = pick
        got[pick].update(vb)
    return assign


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(C.PROCESSED / "dataset.jsonl"))
    ap.add_argument("--outdir", default=str(C.PROCESSED))
    ap.add_argument("--group", choices=["cve", "repo", "commit"], default="repo",
                    help="unit kept intact within a split (repo = strictest)")
    ap.add_argument("--test", type=float, default=0.20)
    ap.add_argument("--val", type=float, default=0.10)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--no-stratify", action="store_true",
                    help="disable per-language stratification (not recommended)")
    args = ap.parse_args()

    path = Path(args.data)
    if not path.exists():
        sys.exit(f"No dataset at {path}")
    recs = load(path)
    assign = split_groups(recs, args.group, args.test, args.val, args.seed,
                          stratify_language=not args.no_stratify)

    buckets: dict[str, list[dict]] = {"train": [], "val": [], "test": []}
    for r in recs:
        buckets[assign[group_key(r, args.group)]].append(r)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    print(f"grouping unit: {args.group} | seed {args.seed} | "
          f"language-stratified: {not args.no_stratify}")
    print(f"{'split':<8}{'records':>9}{'vuln':>7}{'safe':>7}{'CVEs':>7}{'repos':>7}")
    for name, rows in buckets.items():
        out = outdir / f"{name}.jsonl"
        with out.open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        v = sum(1 for r in rows if r["label"] == 1)
        print(f"{name:<8}{len(rows):>9}{v:>7}{len(rows)-v:>7}"
              f"{len({r['cve_id'] for r in rows}):>7}{len({r['repo'] for r in rows}):>7}")

    # per-language vulnerable counts - the number that actually gates
    # whether a per-language claim is defensible
    langs = sorted({r["language_family"] for r in recs})
    print(f"\nvulnerable samples per language:")
    print(f"{'split':<8}" + "".join(f"{l:>12}" for l in langs))
    for name, rows in buckets.items():
        c = Counter(r["language_family"] for r in rows if r["label"] == 1)
        print(f"{name:<8}" + "".join(f"{c.get(l,0):>12}" for l in langs))

    # Leakage assertions - these must hold or the splits are unusable.
    print("\nleakage checks:")
    ok = True
    for a in ("train", "val", "test"):
        for b in ("train", "val", "test"):
            if a >= b:
                continue
            for field, label in (("repo", "repos"), ("cve_id", "CVEs"),
                                 ("pair_id", "pairs"), ("func_hash", "function texts")):
                sa = {r[field] for r in buckets[a] if r.get(field)}
                sb = {r[field] for r in buckets[b] if r.get(field)}
                shared = sa & sb
                # repo/CVE overlap is expected unless that was the grouping unit
                expected = (field == "repo" and args.group != "repo") or \
                           (field == "cve_id" and args.group == "repo" and False)
                if shared and not expected:
                    print(f"  WARN {a}/{b} share {len(shared)} {label}")
                    if field in ("pair_id", "func_hash"):
                        ok = False
    print("  PASS - no pair or function-text leakage across splits" if ok
          else "  FAIL - leakage detected")


if __name__ == "__main__":
    main()
