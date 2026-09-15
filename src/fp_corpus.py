"""False-alarm measurement on repositories that are known to be safe.

The single most important number for an auditing platform is not how much it
finds - it is how often it is WRONG about code that is fine. A scanner that
calls Flask dangerous will be ignored within a week, and an ignored scanner
protects nobody.

So: take widely used, heavily reviewed open-source projects that millions of
people install, scan them, and count the alarms. These projects are not
provably free of bugs - nothing is - but they are emphatically NOT malware, so
any "do not clone" verdict here is a false positive by construction, and needs
no labelling effort to interpret.

Two things are measured separately, because they cost very different amounts:

    tier A   deterministic supply-chain checks. Free, so every repository in the
             corpus is scanned. This is the headline number, because tier A is
             what is allowed to produce a "do not clone" verdict.
    tier C   the LLM pass. Expensive, so it is opt-in with --with-llm on a
             subset. Reported as alarm VOLUME rather than as a verdict.

    python src/fp_corpus.py --limit 10
    python src/fp_corpus.py --with-llm --model local-qwen-coder --limit 5
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C

RESULTS = C.DATA / "results"
CORPUS_CACHE = C.CACHE / "benign_repos"

# Deliberately curated rather than pulled from a "top packages" API: every entry
# is a project with a long public history, many maintainers and heavy external
# review. That is what licenses the assumption "an alarm here is a false alarm".
BENIGN = [
    # python
    ("pallets/flask", "python"), ("psf/requests", "python"),
    ("django/django", "python"), ("numpy/numpy", "python"),
    ("pytest-dev/pytest", "python"), ("psf/black", "python"),
    ("tiangolo/fastapi", "python"), ("urllib3/urllib3", "python"),
    ("encode/httpx", "python"), ("pallets/click", "python"),
    # javascript
    ("expressjs/express", "javascript"), ("lodash/lodash", "javascript"),
    ("axios/axios", "javascript"), ("chalk/chalk", "javascript"),
    ("vuejs/vue", "javascript"), ("moment/moment", "javascript"),
    ("socketio/socket.io", "javascript"), ("caolan/async", "javascript"),
    ("visionmedia/debug", "javascript"), ("sindresorhus/got", "javascript"),
    # java
    ("google/gson", "java"), ("square/okhttp", "java"),
    ("square/retrofit", "java"), ("junit-team/junit4", "java"),
    ("FasterXML/jackson-core", "java"), ("apache/commons-lang", "java"),
    # c
    ("curl/curl", "c"), ("madler/zlib", "c"),
    ("libgit2/libgit2", "c"), ("jqlang/jq", "c"),
    # c++
    ("nlohmann/json", "cpp"), ("fmtlib/fmt", "cpp"),
    ("google/googletest", "cpp"), ("gabime/spdlog", "cpp"),
    ("catchorg/Catch2", "cpp"),
]


def fetch(repo: str, dest: Path) -> Path | None:
    """Latest default-branch tree. Reuses the benchmark's commit-pinned fetcher."""
    import repo_bench_eval as RB
    return RB.download_at(repo, "HEAD", dest)


def scan_deterministic(root: Path) -> dict:
    import supply_chain as SUP
    return SUP.analyse(root)


def scan_llm(root: Path, repo: str, model: str, strategy: str, max_files: int) -> dict:
    import models as M
    import repo_analyze as RA
    ls = json.loads((C.PROCESSED / "label_space.json").read_text(encoding="utf-8"))
    rep = RA.analyse_repo(root, M.get(model), ls, strategy, max_files=max_files,
                          verbose=False, repo_slug=repo, novelty_scope="eval")
    return {"clone_safety": rep.clone_safety, "risk_level": rep.risk_level,
            "by_pillar": rep.by_pillar, "by_tier": rep.by_tier,
            "n_findings": len(rep.findings), "n_analysed": rep.n_analysed,
            "vuln_findings": sum(1 for f in rep.findings
                                 if f["pillar"] == "vulnerability")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--with-llm", action="store_true",
                    help="also run the (expensive) model pass")
    ap.add_argument("--model", default="local-qwen-coder")
    ap.add_argument("--strategy", default="zero_shot")
    ap.add_argument("--max-files", type=int, default=10)
    ap.add_argument("--out", default=str(RESULTS / "fp_corpus.jsonl"))
    args = ap.parse_args()

    corpus = BENIGN[:args.limit] if args.limit else BENIGN
    CORPUS_CACHE.mkdir(parents=True, exist_ok=True)
    rows = []
    t0 = time.time()

    for i, (repo, lang) in enumerate(corpus, 1):
        root = fetch(repo, CORPUS_CACHE)
        if root is None:
            print(f"  [{i}/{len(corpus)}] {repo}: download failed, skipping")
            continue
        det = scan_deterministic(root)
        row = {"repo": repo, "language": lang,
               "clone_safe": det["clone_safe"],
               "supply_findings": len(det["findings"]),
               "by_kind": det["by_kind"],
               "worst": det["worst_severity"],
               "detail": [f"{f['kind']}:{f['file']}" for f in det["findings"][:6]]}
        if args.with_llm:
            row["llm"] = scan_llm(root, repo, args.model, args.strategy, args.max_files)
        rows.append(row)

        flag = "" if det["clone_safe"] else "  <-- FALSE ALARM"
        extra = ""
        if args.with_llm:
            extra = f" | llm findings={row['llm']['n_findings']}"
        print(f"  [{i}/{len(corpus)}] {repo:<28} supply-chain alarms="
              f"{len(det['findings'])}{extra}{flag}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    n = len(rows)
    unsafe = [r for r in rows if not r["clone_safe"]]
    any_alarm = [r for r in rows if r["supply_findings"]]
    kinds = Counter()
    for r in rows:
        kinds.update(r["by_kind"])

    summary = {
        "n_repos": n,
        "false_dangerous_verdicts": len(unsafe),
        "false_dangerous_rate": round(len(unsafe) / n, 4) if n else 0.0,
        "repos_with_any_supply_alarm": len(any_alarm),
        "mean_supply_alarms": round(sum(r["supply_findings"] for r in rows) / n, 3) if n else 0,
        "alarm_kinds": dict(kinds),
        "wall_s": round(time.time() - t0, 1),
    }
    if args.with_llm:
        llm_rows = [r["llm"] for r in rows if "llm" in r]
        if llm_rows:
            summary["llm"] = {
                "model": args.model, "strategy": args.strategy,
                "mean_findings_per_repo": round(
                    sum(x["n_findings"] for x in llm_rows) / len(llm_rows), 2),
                "mean_vuln_findings_per_repo": round(
                    sum(x["vuln_findings"] for x in llm_rows) / len(llm_rows), 2),
                "repos_rated_high_or_critical": sum(
                    1 for x in llm_rows if x["risk_level"] in ("high", "critical")),
            }

    spath = RESULTS / "fp_corpus_summary.json"
    spath.write_text(json.dumps(summary, indent=1), encoding="utf-8")

    print("\n" + "=" * 68)
    print("FALSE-ALARM RATE ON TRUSTED OPEN-SOURCE PROJECTS")
    print("=" * 68)
    print(f"  repositories scanned            {summary['n_repos']}")
    print(f"  false 'do not clone' verdicts   {summary['false_dangerous_verdicts']}"
          f"   ({summary['false_dangerous_rate']*100:.1f}%)")
    print(f"  repos with any supply alarm     {summary['repos_with_any_supply_alarm']}")
    print(f"  mean supply-chain alarms/repo   {summary['mean_supply_alarms']}")
    print(f"  alarm kinds                     {summary['alarm_kinds'] or '{}'}")
    if "llm" in summary:
        L = summary["llm"]
        print(f"\n  LLM pass ({L['model']}):")
        print(f"    mean findings per repo        {L['mean_findings_per_repo']}")
        print(f"    mean vulnerability findings   {L['mean_vuln_findings_per_repo']}")
        print(f"    repos rated high/critical     {L['repos_rated_high_or_critical']}/{n}")
    print(f"\n  rows    -> {out}\n  summary -> {spath}")


if __name__ == "__main__":
    main()
