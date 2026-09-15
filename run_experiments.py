"""One command to run the whole scientific evaluation, unattended and resumable.

    python run_experiments.py --models local-qwen-coder,gemini-flash --scale pilot
    python run_experiments.py --models local-qwen-coder --scale full

Why this is safe to launch and leave
------------------------------------
Every LLM response is cached on disk by content hash, so if a run is interrupted
- a rate limit, a dropped connection, closing the laptop - just run the same
command again. Everything already done is skipped for free; only the missing
calls are made. There is no penalty for re-running, and no state to clean up.

What it runs
------------
All four detection pillars plus the repository-level benchmark, for every model
you list, across the core prompting strategies. Then it computes the statistics
(bootstrap CIs, per-language breakdown, pairwise significance) into one report.

Scales
------
    pilot   small, fast sanity pass          (few hundred calls total)
    medium  a defensible experiment          (language-stratified subsets)
    full    everything                        (long; use the free local model)

Cloud free tiers are rate-limited, so put the local model first for the heavy
pillars and use cloud models on the smaller ones or overnight.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable

# (label, script, per-scale sample limit, strategies)
SCALES = {
    "pilot":  {"vuln": 60,   "pillar": 60,  "repo": 8},
    "medium": {"vuln": 600,  "pillar": 300, "repo": 30},
    "full":   {"vuln": 0,    "pillar": 0,   "repo": 60},   # 0 = no limit
}


def run(cmd: list[str], label: str) -> bool:
    print("\n" + "=" * 78)
    print(f"  {label}")
    print("  $ " + " ".join(str(c) for c in cmd))
    print("=" * 78)
    t = time.time()
    r = subprocess.run(cmd, cwd=str(ROOT))
    print(f"  ({label}: exit {r.returncode}, {time.time() - t:.0f}s)")
    return r.returncode == 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="local-qwen-coder",
                    help="comma-separated, e.g. local-qwen-coder,gemini-flash,groq-llama")
    ap.add_argument("--scale", choices=list(SCALES), default="pilot")
    ap.add_argument("--strategies", default="zero_shot,cot_8step")
    ap.add_argument("--skip", default="", help="comma list: vuln,deps,secrets,malware,repo,stats")
    args = ap.parse_args()

    lim = SCALES[args.scale]
    models = args.models
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    res_dir = ROOT / "data" / "results"

    def limarg(n):
        return ["--limit", str(n)] if n else []

    steps = []
    if "vuln" not in skip:
        steps.append(("Pillar 1 - Vulnerabilities", [
            PY, "src/evaluate.py", "--models", models,
            "--strategies", args.strategies, *limarg(lim["vuln"]),
            "--out", str(res_dir / "predictions.jsonl")]))
    if "deps" not in skip:
        steps.append(("Pillar 4 - Dependencies", [
            PY, "src/deps_evaluate.py", "--models", models,
            "--strategies", "zero_shot,cot", *limarg(lim["pillar"])]))
    if "secrets" not in skip:
        steps.append(("Pillar 3 - Secrets", [
            PY, "src/secrets_evaluate.py", "--models", models,
            "--strategies", "zero_shot,context", *limarg(lim["pillar"])]))
    if "malware" not in skip:
        steps.append(("Pillar 2 - Malware", [
            PY, "src/malware_evaluate.py", "--models", models,
            "--strategies", "zero_shot,triage", *limarg(lim["pillar"])]))

    ok = 0
    for label, cmd in steps:
        if run(cmd, label):
            ok += 1

    # repository-level + statistics are per-model
    if "repo" not in skip:
        for m in [x.strip() for x in models.split(",") if x.strip()]:
            run([PY, "src/repo_bench_eval.py", "--model", m,
                 "--strategy", "zero_shot", *limarg(lim["repo"])],
                f"Repo-level benchmark ({m})")

    if "stats" not in skip:
        run([PY, "src/analyze_results.py", "--pred", str(res_dir / "predictions.jsonl")],
            "Statistics: CIs, per-language, significance")
        run([PY, "src/interpretability_eval.py", "--pred", str(res_dir / "predictions.jsonl")],
            "Interpretability of explanations")

    print("\n" + "#" * 78)
    print(f"  DONE - {ok}/{len(steps)} detection pillars ran at scale '{args.scale}'.")
    print(f"  Results in data/results/ . Re-run this exact command any time to")
    print(f"  resume or extend; cached answers make it free to repeat.")
    print("#" * 78)


if __name__ == "__main__":
    main()
