"""Pillar 3, step 2 - evaluate LLMs vs Gitleaks on hardcoded-secret detection.

Baseline: the real Gitleaks binary (tools/gitleaks.exe), not a reimplementation.

What we expected vs. what we measured
-------------------------------------
We expected regex scanners to drown in false positives on placeholders and
documentation examples. **That turned out to be wrong.** Gitleaks 8.30.1 scored
precision 1.000 on this benchmark - zero false positives across all five
non-secret kinds - because it carries allowlists and entropy checks well beyond
naive pattern matching.

The real gap is recall (0.802), and it is highly structured:

    perfect (1.00)  github_pat, google_api_key, private_key, slack_token,
                    stripe_secret, twilio_key   -> distinctive vendor prefixes
    blind  (0.00)   db_url            -> password embedded in a connection string
           (0.17)   generic_password  -> an ordinary password variable

Gitleaks recognises secrets that announce themselves with a fixed prefix
(`ghp_`, `AIza`, `sk_live_`). It cannot recognise a secret whose only signal is
*context*: `postgres://admin:Gf2le...@db.internal/prod` has no regex signature,
but is obviously a credential to any reader.

So the question this pillar actually tests is:

    can a model catch context-dependent secrets that pattern matching cannot see,
    without giving up the precision the regex baseline achieves?

Both halves matter, so we report precision/recall/F1 AND the false-positive rate
broken down by kind of non-secret.

    python src/secrets_evaluate.py --models stub --strategies zero_shot,context
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import models as M

RESULTS = C.DATA / "results"
RESULTS.mkdir(parents=True, exist_ok=True)
SCAN_DIR = C.INTERIM / "secrets_scan"
GITLEAKS = C.ROOT / "tools" / ("gitleaks.exe" if sys.platform.startswith("win") else "gitleaks")

SYSTEM = ("You are a secret-scanning analyst performing defensive security review. "
          "You identify credentials that were committed by mistake, while avoiding "
          "false alarms on placeholders and test data.")

ANSWER_SPEC = (
    'Reply with ONE JSON object and nothing else:\n'
    '{"real_secrets": [{"line": <line number>, "type": "<kind of credential>", '
    '"reason": "<why it is a genuine credential>"}]}\n'
    'Include ONLY lines holding a REAL credential. Exclude placeholders '
    '(CHANGEME, <YOUR_KEY>), redacted values (****), documentation examples, '
    'test fixtures, and environment-variable lookups. Empty list if none.'
)


def numbered(content: str) -> str:
    return "\n".join(f"{i}: {ln}" for i, ln in enumerate(content.splitlines(), 1))


def prompt_zero_shot(f: dict) -> tuple[str, str]:
    return SYSTEM, (
        f"File: {f['filename']}\n\n```\n{numbered(f['content'])}\n```\n\n"
        f"Which lines contain a real hardcoded credential?\n\n{ANSWER_SPEC}")


def prompt_context(f: dict) -> tuple[str, str]:
    """Explicitly directs attention to the real/placeholder distinction."""
    return SYSTEM, (
        f"File: {f['filename']}\n\n```\n{numbered(f['content'])}\n```\n\n"
        "A line is a REAL secret only if all of these hold:\n"
        "  1. the value looks like a genuine credential, not a template or mask;\n"
        "  2. it is a literal value, not a reference such as ${VAR} or os.environ[...];\n"
        "  3. it is not a vendor documentation example (e.g. AWS's AKIAIOSFODNN7EXAMPLE);\n"
        "  4. it is not obviously test or dummy data.\n"
        "Also weigh the file's purpose - a README example or a test fixture is far "
        "less likely to hold a live credential than a production config.\n\n"
        f"{ANSWER_SPEC}")


STRATEGIES = {"zero_shot": prompt_zero_shot, "context": prompt_context}
JSON_OBJ_RE = re.compile(r"\{.*\}", re.S)


def parse_reply(text: str) -> tuple[set[int], bool]:
    if not text:
        return set(), False
    for chunk in (re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
                  + JSON_OBJ_RE.findall(text)):
        try:
            obj = json.loads(chunk)
        except Exception:
            continue
        items = obj.get("real_secrets")
        if isinstance(items, list):
            out = set()
            for it in items:
                if isinstance(it, dict) and it.get("line") is not None:
                    try:
                        out.add(int(it["line"]))
                    except (TypeError, ValueError):
                        pass
                elif isinstance(it, int):
                    out.add(it)
            return out, True
    return set(), False


def run_gitleaks(files: list[dict]) -> dict[str, set[int]]:
    """Return {filename: {flagged line numbers}} from the real Gitleaks binary."""
    if SCAN_DIR.exists():
        shutil.rmtree(SCAN_DIR)
    SCAN_DIR.mkdir(parents=True, exist_ok=True)
    for f in files:
        (SCAN_DIR / f["filename"]).write_text(f["content"], encoding="utf-8")

    report = C.INTERIM / "gitleaks_report.json"
    if report.exists():
        report.unlink()
    if not GITLEAKS.exists():
        print(f"  !! gitleaks not found at {GITLEAKS} - skipping baseline")
        return {}
    subprocess.run([str(GITLEAKS), "detect", "--source", str(SCAN_DIR), "--no-git",
                    "--report-format", "json", "--report-path", str(report),
                    "--exit-code", "0"], capture_output=True, timeout=900)
    if not report.exists():
        return {}
    out: dict[str, set[int]] = defaultdict(set)
    for fnd in json.loads(report.read_text(encoding="utf-8")):
        out[Path(fnd.get("File", "")).name].add(int(fnd.get("StartLine", 0)))
    return out


def evaluate_file(f: dict, flagged: set[int]) -> dict:
    real = {x["line_no"] for x in f["findings"] if x["is_real_secret"]}
    nonsecret = {x["line_no"]: x["non_secret_kind"] for x in f["findings"]
                 if not x["is_real_secret"]}
    known = real | set(nonsecret)
    flg = flagged & known                       # ignore lines outside our entries

    tp = len(flg & real)
    fp = len(flg & set(nonsecret))
    fn = len(real - flg)
    tn = len(set(nonsecret) - flg)
    fp_by_kind = Counter(nonsecret[l] for l in (flg & set(nonsecret)))
    seen_by_kind = Counter(nonsecret.values())
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "fp_by_kind": dict(fp_by_kind), "seen_by_kind": dict(seen_by_kind)}


def score(rows: list[dict]) -> dict:
    tp = sum(r["tp"] for r in rows); fp = sum(r["fp"] for r in rows)
    fn = sum(r["fn"] for r in rows); tn = sum(r["tn"] for r in rows)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpk: Counter = Counter(); seen: Counter = Counter()
    for r in rows:
        fpk.update(r["fp_by_kind"]); seen.update(r["seen_by_kind"])
    rate = {k: round(fpk.get(k, 0) / seen[k], 3) for k in sorted(seen)}
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "fp_rate_by_kind": rate,
            "format_ok": round(sum(1 for r in rows if r.get("parse_ok", True)) / len(rows), 3) if rows else 0,
            "latency_mean_s": round(sum(r.get("latency_s", 0) for r in rows) / len(rows), 2) if rows else 0}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(C.PROCESSED / "secrets_benchmark.jsonl"))
    ap.add_argument("--models", default="stub")
    ap.add_argument("--strategies", default="zero_shot,context")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default=str(RESULTS / "secrets_predictions.jsonl"))
    args = ap.parse_args()

    files = [json.loads(l) for l in Path(args.data).open(encoding="utf-8") if l.strip()]
    if args.limit:
        files = files[:args.limit]
    print(f"files: {len(files)}")

    summaries, all_rows = [], []

    # ---- Gitleaks baseline ----
    t0 = time.time()
    gl = run_gitleaks(files)
    gl_wall = time.time() - t0
    rows = []
    for f in files:
        r = evaluate_file(f, gl.get(f["filename"], set()))
        r.update({"file_id": f["file_id"], "context": f["context"],
                  "model": "gitleaks", "strategy": "regex", "parse_ok": True,
                  "latency_s": gl_wall / max(len(files), 1)})
        rows.append(r); all_rows.append(r)
    s = score(rows); s.update({"model": "gitleaks", "strategy": "regex"})
    summaries.append(s)
    print(f"  {'gitleaks':<16}{'regex':<10}P={s['precision']:.3f} R={s['recall']:.3f} F1={s['f1']:.3f}")

    # ---- LLMs ----
    names = [m.strip() for m in args.models.split(",") if m.strip()]
    strats = [x.strip() for x in args.strategies.split(",") if x.strip()]
    missing = [m for m in names if not M.get(m).is_available()]
    if missing:
        print(f"  (skipping {missing} - no API key; available: {M.available()})")
        names = [m for m in names if m not in missing]

    for mn in names:
        prov = M.get(mn)
        for st in strats:
            rows = []
            for i, f in enumerate(files, 1):
                sysmsg, user = STRATEGIES[st](f)
                rep = prov.generate(sysmsg, user)
                flagged, ok = parse_reply(rep.text)
                r = evaluate_file(f, flagged)
                r.update({"file_id": f["file_id"], "context": f["context"],
                          "model": mn, "strategy": st, "parse_ok": ok,
                          "latency_s": rep.latency_s})
                rows.append(r); all_rows.append(r)
                if i % 50 == 0:
                    print(f"    {mn}/{st}: {i}/{len(files)}")
            s = score(rows); s.update({"model": mn, "strategy": st})
            summaries.append(s)
            print(f"  {mn:<16}{st:<10}P={s['precision']:.3f} R={s['recall']:.3f} F1={s['f1']:.3f}")

    out = Path(args.out)
    with out.open("w", encoding="utf-8") as fh:
        for r in all_rows:
            fh.write(json.dumps(r) + "\n")
    out.with_name("secrets_summary.json").write_text(json.dumps(summaries, indent=1), encoding="utf-8")

    print("\n" + "=" * 78)
    print(f"{'model':<16}{'strategy':<10}{'prec':>7}{'recall':>8}{'F1':>7}{'TP':>6}{'FP':>6}{'FN':>6}")
    print("-" * 78)
    for s in sorted(summaries, key=lambda x: -x["f1"]):
        print(f"{s['model']:<16}{s['strategy']:<10}{s['precision']:>7.3f}{s['recall']:>8.3f}"
              f"{s['f1']:>7.3f}{s['tp']:>6}{s['fp']:>6}{s['fn']:>6}")
    print("=" * 78)
    print("\nFALSE-POSITIVE RATE BY KIND OF NON-SECRET  (lower is better)")
    kinds = sorted({k for s in summaries for k in s["fp_rate_by_kind"]})
    print(f"{'model/strategy':<28}" + "".join(f"{k:>16}" for k in kinds))
    for s in summaries:
        tag = f"{s['model']}/{s['strategy']}"
        print(f"{tag:<28}" + "".join(f"{s['fp_rate_by_kind'].get(k,0):>16.3f}" for k in kinds))
    print(f"\npredictions -> {out}")


if __name__ == "__main__":
    main()
