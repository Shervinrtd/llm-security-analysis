"""Merge dataset shards into one corpus with global de-duplication.

The corpus is built from two collection routes (NVD-wide and OSV per-ecosystem),
which overlap: the same CVE can appear in both, and unrelated advisories can
point at the same fix commit. De-duplicating only within a shard would leave
cross-shard duplicates, which is exactly the leakage that inflates scores in
BigVul/CVEfixes.

So we re-run the same global rules over the union:
  * one record per normalised function text (vulnerable kept preferentially)
  * pre/post pairs left orphaned by de-duplication get their pair_id cleared
    rather than being deleted

    python src/merge_datasets.py --inputs data/processed/dataset.jsonl,data/processed/dataset_osv.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
from build_dataset import dedupe


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", required=True, help="comma-separated jsonl shards")
    ap.add_argument("--out", default=str(C.PROCESSED / "dataset_merged.jsonl"))
    args = ap.parse_args()

    paths = [Path(p.strip()) for p in args.inputs.split(",") if p.strip()]
    combined: list[dict] = []
    for p in paths:
        if not p.exists():
            sys.exit(f"missing shard: {p}")
        rows = [json.loads(l) for l in p.open(encoding="utf-8") if l.strip()]
        v = sum(1 for r in rows if r["label"] == 1)
        print(f"  {p.name:<28}{len(rows):>7} records ({v} vulnerable)")
        combined.extend(rows)

    print(f"\ncombined before de-duplication : {len(combined)}")
    stats: Counter = Counter()
    merged = dedupe(combined, stats)
    print(f"removed as duplicates          : {stats['deduped']}")
    print(f"pair_ids cleared (orphaned)    : {stats['pair_orphaned_unlinked']}")
    print(f"final                          : {len(merged)}")

    out = Path(args.out)
    with out.open("w", encoding="utf-8") as fh:
        for r in merged:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    v = [r for r in merged if r["label"] == 1]
    print(f"\nvulnerable: {len(v)} | safe: {len(merged)-len(v)}")
    print(f"per language (vulnerable): {dict(Counter(r['language_family'] for r in v))}")
    print(f"distinct CWEs: {len({r['cwe_primary'] for r in v})}")
    print(f"unique CVEs  : {len({r['cve_id'] for r in merged})}")
    print(f"\nWrote -> {out}")


if __name__ == "__main__":
    main()
