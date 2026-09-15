"""Measure the 'located' dimension of the interpretability rubric.

interpretability.py scores four dimensions - grounded, specific, mechanism,
located - but `located` needs the model to cite a line number, and the core
answer format (prompts.py ANSWER_SPEC) never asks for one. Changing that
shared spec would invalidate every already-reported zero_shot/cot_8step
number (different prompt -> different cache key -> different answers), so
instead of touching it, this makes ONE extra, narrowly-scoped call per
already-confirmed true positive, asking only for the line number of the flaw
already identified. Nothing about the existing classification results is
touched.

    python src/located_eval.py --model local-qwen-coder --strategy zero_shot
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import models as M

RESULTS = C.DATA / "results"
LINE_RE = re.compile(r'"line"\s*:\s*(\d+)')

SYSTEM = (
    "You are a security code reviewer performing defensive analysis. "
    "You previously identified a vulnerability in a function; now point to "
    "exactly where it is."
)


def load_code_index(*splits: str) -> dict[str, dict]:
    idx: dict[str, dict] = {}
    for name in splits:
        p = C.PROCESSED / name
        if not p.exists():
            continue
        for line in p.open(encoding="utf-8"):
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("sample_id"):
                idx[r["sample_id"]] = r
    return idx


def numbered(code: str) -> str:
    return "\n".join(f"{i+1:>4} | {ln}" for i, ln in enumerate(code.splitlines()))


def build_prompt(rec: dict, cwe: str | None) -> tuple[str, str]:
    user = (
        f"This {rec.get('language','')} function was already flagged as vulnerable "
        f"({cwe or 'unspecified CWE'}). The lines are numbered.\n\n"
        f"{numbered(rec['code'])}\n\n"
        "Which line number contains the vulnerable code (the specific line where "
        "the flaw is, not just where it is used)? "
        'Answer with ONE JSON object and nothing else: {"line": <int>}'
    )
    return SYSTEM, user


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", default=str(RESULTS / "predictions.jsonl"))
    ap.add_argument("--model", default="local-qwen-coder")
    ap.add_argument("--strategy", default="zero_shot")
    ap.add_argument("--out", default=str(RESULTS / "location_summary.json"))
    args = ap.parse_args()

    rows = [json.loads(l) for l in Path(args.pred).open(encoding="utf-8") if l.strip()]
    tps = [r for r in rows if r.get("model") == args.model and r.get("strategy") == args.strategy
           and r.get("true_label") == 1 and r.get("pred_label") == 1]
    if not tps:
        sys.exit(f"no true positives for {args.model}/{args.strategy} in {args.pred}")

    code_idx = load_code_index("test.jsonl", "val.jsonl", "train.jsonl")
    provider = M.get(args.model)

    n_scored, n_located, n_no_citation, n_missing_truth = 0, 0, 0, 0
    detail = []
    for i, r in enumerate(tps, 1):
        rec = code_idx.get(r.get("sample_id"))
        if not rec or not rec.get("changed_lines_in_func"):
            n_missing_truth += 1
            continue
        true_lines = rec["changed_lines_in_func"]
        system, user = build_prompt(rec, r.get("pred_cwe"))
        reply = provider.generate(system, user)
        m = LINE_RE.search(reply.text or "")
        cited = int(m.group(1)) if m else None
        located = None
        if cited is not None:
            located = any(abs(cited - t) <= 3 for t in true_lines)
        n_scored += 1
        if cited is None:
            n_no_citation += 1
        elif located:
            n_located += 1
        detail.append({"sample_id": r["sample_id"], "cited_line": cited,
                       "true_lines": true_lines, "located": located})
        if i % 10 == 0:
            print(f"  {i}/{len(tps)}")

    rate = n_located / n_scored if n_scored else 0.0
    out = {
        "model": args.model, "strategy": args.strategy,
        "n_true_positives": len(tps), "n_scored": n_scored,
        "n_missing_ground_truth": n_missing_truth,
        "n_no_line_citation": n_no_citation,
        "n_located": n_located, "located_rate": round(rate, 4),
    }
    Path(args.out).write_text(json.dumps({"summary": out, "detail": detail}, indent=1),
                              encoding="utf-8")
    print(f"\nlocated_rate = {rate:.1%}  "
          f"({n_located}/{n_scored} true positives, {n_no_citation} gave no line number)")
    print(f"-> {args.out}")


if __name__ == "__main__":
    main()
