"""Build a REPOSITORY-level benchmark from the CVE commits we already collected.

The project objective calls for "an experimental evaluation on a diverse set of
public repositories". Until now the only benchmark was function-level: isolated
snippets with the surrounding project stripped away. That measures something
different from what the platform actually does, which is walk a whole repository,
decide which files are worth reading, and report on the ones that matter.

Each case here is a real public repository, pinned at a real commit, containing a
real published vulnerability whose exact location is known:

    repo + fix_sha           the commit that PATCHED the flaw
    targets                  file and function that were vulnerable before it
    cve_id / cwe_primary     what the flaw was

The repository is materialised in its VULNERABLE state by downloading the tree at
the fix commit and reverse-applying that commit's patch - the same self-validating
technique that built the function dataset, so the ground truth is exact rather
than annotated.

Cases are drawn ONLY from the test split. That keeps the benchmark clean: none of
these functions were used for few-shot prompting or strategy calibration, and the
evaluation-scope CVE index excludes them, so a detection cannot come from having
already memorised the answer.

    python src/repo_bench_build.py --n 60
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C

OUT = C.PROCESSED / "repo_benchmark.jsonl"
SOURCE = C.PROCESSED / "test.jsonl"          # test split only - see the docstring

# One repository must not dominate the benchmark: a project with 40 CVEs would
# otherwise decide the headline number on its own.
MAX_CASES_PER_REPO = 3


def collect() -> dict[tuple, dict]:
    """Group vulnerable test-split records into (repo, fix_sha) cases."""
    cases: dict[tuple, dict] = {}
    for line in SOURCE.open(encoding="utf-8"):
        r = json.loads(line)
        if r.get("label") != 1 or not r.get("repo") or not r.get("commit_sha"):
            continue
        if not r.get("file_path") or not r.get("func_name"):
            continue
        key = (r["repo"], r["commit_sha"])
        case = cases.setdefault(key, {
            "case_id": hashlib.md5(f"{key[0]}|{key[1]}".encode()).hexdigest()[:16],
            "repo": r["repo"], "fix_sha": r["commit_sha"],
            "cve_id": r.get("cve_id"), "cwe_primary": r.get("cwe_primary"),
            "cwe_name": r.get("cwe_name"), "language": r["language"],
            "severity": r.get("cvss_severity"), "cvss_score": r.get("cvss_score"),
            "cve_published": r.get("cve_published"),
            "cve_description": (r.get("cve_description") or "")[:400],
            "targets": [],
        })
        case["targets"].append({
            "file_path": r["file_path"], "func_name": r["func_name"],
            "func_hash": r.get("func_hash"), "loc": r.get("loc"),
            "sample_id": r.get("sample_id"),
        })
    for c in cases.values():
        # de-duplicate targets that repeat across records
        seen, uniq = set(), []
        for t in c["targets"]:
            k = (t["file_path"], t["func_name"], t.get("func_hash"))
            if k not in seen:
                seen.add(k)
                uniq.append(t)
        c["targets"] = uniq
        c["n_targets"] = len(uniq)
        c["files"] = sorted({t["file_path"] for t in uniq})
    return cases


def select(cases: dict[tuple, dict], n: int, seed: int = 42) -> list[dict]:
    """Language-stratified selection, capped per repository."""
    import random
    rng = random.Random(seed)

    by_lang: dict[str, list] = defaultdict(list)
    for c in cases.values():
        by_lang[c["language"]].append(c)

    per_repo: dict[str, int] = defaultdict(int)
    chosen: list[dict] = []
    langs = sorted(by_lang)
    for lst in by_lang.values():
        rng.shuffle(lst)

    # round-robin across languages so every language is represented even when
    # one of them has far more material than the others
    idx = {lang: 0 for lang in langs}
    while len(chosen) < n:
        progressed = False
        for lang in langs:
            if len(chosen) >= n:
                break
            lst = by_lang[lang]
            while idx[lang] < len(lst):
                cand = lst[idx[lang]]
                idx[lang] += 1
                if per_repo[cand["repo"]] >= MAX_CASES_PER_REPO:
                    continue
                per_repo[cand["repo"]] += 1
                chosen.append(cand)
                progressed = True
                break
        if not progressed:
            break            # every language exhausted
    return chosen


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=60, help="how many repository cases")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    if not SOURCE.exists():
        sys.exit(f"missing {SOURCE} - run make_splits.py first")

    cases = collect()
    print(f"candidate (repo, commit) cases in the test split: {len(cases)}")
    chosen = select(cases, args.n, args.seed)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for c in chosen:
            fh.write(json.dumps(c) + "\n")

    from collections import Counter
    print(f"\nselected {len(chosen)} cases -> {out}")
    print("  languages :", dict(Counter(c["language"] for c in chosen)))
    print("  repos     :", len({c["repo"] for c in chosen}))
    print("  CVEs      :", len({c["cve_id"] for c in chosen if c["cve_id"]}))
    print("  CWEs      :", len({c["cwe_primary"] for c in chosen if c["cwe_primary"]}))
    print("  targets   :", sum(c["n_targets"] for c in chosen),
          f"(mean {sum(c['n_targets'] for c in chosen)/max(len(chosen),1):.1f} per repo)")


if __name__ == "__main__":
    main()
