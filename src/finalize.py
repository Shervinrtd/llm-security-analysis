"""Post-process a built dataset into the task-ready artifacts.

  1. enrich  - attach CWE names (needed for multi-class prompting)
  2. label space - derive the candidate CWE list the prompts will offer
  3. report  - statistics + integrity assertions
  4. splits  - leakage-safe train/val/test

    python src/finalize.py --data data/processed/dataset.jsonl
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import cwe_catalog as K

PY = sys.executable
SRC = Path(__file__).resolve().parent


def enrich(path: Path) -> int:
    recs = [json.loads(l) for l in path.open(encoding="utf-8") if l.strip()]
    n = 0
    for r in recs:
        if r.get("label") == 1 and r.get("cwe_primary"):
            name = K.name_of(r["cwe_primary"])
            if r.get("cwe_name") != name:
                r["cwe_name"] = name
                n += 1
        else:
            r.setdefault("cwe_name", None)
    with path.open("w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    return n


def build_label_space(path: Path, out: Path, min_count: int = 3) -> dict:
    """The CWE label space the classification prompts will use.

    CWEs seen fewer than `min_count` times are folded into an OTHER bucket:
    a class with two examples cannot be scored meaningfully.
    """
    recs = [json.loads(l) for l in path.open(encoding="utf-8") if l.strip()]
    counts = Counter(r["cwe_primary"] for r in recs if r.get("label") == 1 and r.get("cwe_primary"))
    kept = {c: n for c, n in counts.items() if n >= min_count}
    folded = {c: n for c, n in counts.items() if n < min_count}

    space = {
        "min_count": min_count,
        "n_classes": len(kept),
        "classes": [
            {"cwe": c, "name": K.name_of(c), "count": n,
             "lenient_matches": sorted(K.related(c))}
            for c, n in sorted(kept.items(), key=lambda kv: -kv[1])
        ],
        "folded_into_other": sorted(folded),
        "prompt_block": K.prompt_options(
            [c for c, _ in sorted(kept.items(), key=lambda kv: -kv[1])], max_items=60),
    }
    out.write_text(json.dumps(space, indent=1), encoding="utf-8")
    return space


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(C.PROCESSED / "dataset.jsonl"))
    ap.add_argument("--group", choices=["cve", "repo", "commit"], default="repo")
    ap.add_argument("--min-class-count", type=int, default=3)
    args = ap.parse_args()

    path = Path(args.data)
    if not path.exists():
        sys.exit(f"No dataset at {path}")

    print("== 1. enriching with CWE names ==")
    print(f"   updated {enrich(path)} records")

    print("\n== 2. deriving CWE label space ==")
    space_path = C.PROCESSED / "label_space.json"
    space = build_label_space(path, space_path, args.min_class_count)
    print(f"   {space['n_classes']} classes (>= {args.min_class_count} samples), "
          f"{len(space['folded_into_other'])} rare CWEs folded into OTHER")
    print(f"   -> {space_path}")

    print("\n== 3. statistics + integrity ==")
    subprocess.run([PY, str(SRC / "report_stats.py"), "--data", str(path),
                    "--save", str(C.PROCESSED / "dataset_report.txt")], check=False)

    print("\n== 4. leakage-safe splits ==")
    subprocess.run([PY, str(SRC / "make_splits.py"), "--data", str(path),
                    "--group", args.group], check=False)


if __name__ == "__main__":
    main()
