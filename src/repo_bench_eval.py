"""Evaluate the platform on whole repositories, not isolated functions.

For each benchmark case this:

  1. downloads the repository tree at the FIX commit (that state is patched),
  2. reverse-applies that commit's patch, returning the tree to its VULNERABLE
     state,
  3. verifies the reconstruction by hashing the target function and comparing it
     with the hash recorded when the dataset was built - if they differ the case
     is skipped rather than scored, so no result rests on a tree we failed to
     rebuild,
  4. scans it exactly as the app would, and
  5. scores the outcome against the known location of the flaw.

What is measured, and why each part matters
-------------------------------------------
    selected     with a limited file budget, did the scanner even LOOK at the
                 file containing the vulnerability? This is a property of file
                 prioritisation, and a miss here caps everything downstream.
    detected     given that it looked, did it flag that file?
    localised    did it flag the vulnerable FUNCTION rather than merely the file?
    cwe_correct  did it name the right weakness class (lenient = parent/child)?
    alarms       findings in files with no known flaw - the false-alarm proxy.

Leakage control: the novelty index runs in "eval" scope, so the CVEs in this
benchmark are absent from it. A detection therefore cannot come from recognising
a memorised hash - it has to come from the model reading the code.

    python src/repo_bench_eval.py --model local-qwen-coder --limit 10
"""
from __future__ import annotations

import argparse
import io
import hashlib
import json
import os
import sys
import time
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import cwe_catalog as K
import models as M
import patch_fetch as PF
import repo_analyze as RA
import vuln_intel as VI

BENCH = C.PROCESSED / "repo_benchmark.jsonl"
RESULTS = C.DATA / "results"
REPO_CACHE = C.CACHE / "repos"
ARCHIVE = "https://github.com/{repo}/archive/{sha}.zip"


# ------------------------------------------------------------- materialising
def _long(p: Path) -> str:
    r"""Windows caps paths at 260 characters unless they carry the \\?\ prefix.
    Real projects - Java monorepos especially - nest far past that, and without
    this they fail to extract at all, silently biasing the benchmark against the
    deepest repositories."""
    s = str(p.resolve())
    if sys.platform == "win32" and not s.startswith("\\\\?\\"):
        return "\\\\?\\" + s
    return s


def download_at(repo: str, sha: str, dest: Path, timeout: int = 180) -> Path | None:
    """Repository tree at one exact commit. The archive endpoint takes a SHA and
    is not subject to the API rate limit, so no token is needed."""
    # short directory name: every character here is charged against MAX_PATH
    target = dest / f"{repo.split('/')[-1][:18]}_{sha[:8]}"
    marker = target / ".extracted"
    if marker.exists():
        kids = [p for p in target.iterdir() if p.is_dir()]
        return kids[0] if len(kids) == 1 else target    # cached from an earlier run
    url = ARCHIVE.format(repo=repo, sha=sha)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": C.USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            blob = resp.read()
    except Exception:
        return None
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except Exception:
        return None

    target.mkdir(parents=True, exist_ok=True)
    skipped = 0
    for member in zf.infolist():
        if member.is_dir():
            continue
        out = target / member.filename
        try:
            # the directory creation needs the long-path prefix too, otherwise it
            # fails first and the file is skipped before the prefixed open is reached
            os.makedirs(_long(out.parent), exist_ok=True)
            with zf.open(member) as src, open(_long(out), "wb") as dst:
                dst.write(src.read())
        except (OSError, ValueError):
            skipped += 1                                # unextractable path; keep going
    if skipped:
        print(f"      (note: {skipped} file(s) could not be extracted on this filesystem)")
    marker.write_text(f"skipped={skipped}", encoding="utf-8")
    # the archive wraps everything in a single <repo>-<sha> directory
    kids = [p for p in target.iterdir() if p.is_dir()]
    return kids[0] if len(kids) == 1 else target


def make_vulnerable(root: Path, case: dict, verbose: bool = False) -> tuple[bool, str]:
    """Reverse-apply the fix so the tree holds the flaw again. Verified, not assumed.

    Must be idempotent: the extracted tree is cached between runs, and once it has
    been mutated the patch no longer applies to it. Without the marker a second run
    would report every case as unreconstructable - which is exactly what happened
    the first time this was run twice.
    """
    marker = root / ".vulnerable_state"
    if marker.exists() and marker.read_text(encoding="utf-8").strip() == case["case_id"]:
        return True, "already materialised (cached)"

    patch = PF.fetch_patch(case["repo"], case["fix_sha"])
    if not patch:
        return False, "patch unavailable"
    diffs = {d.path: d for d in PF.parse_patch(patch)}
    if not diffs:
        return False, "patch had no usable file diffs"

    restored = 0
    for target in case["targets"]:
        path = target["file_path"]
        fd = diffs.get(path)
        if fd is None:                                   # try a suffix match
            cand = [p for p in diffs if p.endswith(path) or path.endswith(p)]
            fd = diffs[cand[0]] if cand else None
        if fd is None:
            continue
        f = root / path
        if not f.exists():
            continue
        try:
            post = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        pre = PF.reverse_apply(post, fd)
        if pre is None:
            continue
        f.write_text(pre, encoding="utf-8")
        restored += 1

    if not restored:
        return False, "could not reverse-apply the patch to any target file"
    marker.write_text(case["case_id"], encoding="utf-8")
    return True, f"restored {restored}/{len(case['targets'])} target file(s)"


def verify(root: Path, case: dict) -> tuple[int, int]:
    """Confirm the rebuilt functions really are the recorded vulnerable ones."""
    from func_extract import extract_functions
    matched = 0
    for t in case["targets"]:
        f = root / t["file_path"]
        if not f.exists() or not t.get("func_hash"):
            continue
        try:
            code = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lang = C.EXT_TO_LANG.get(f.suffix.lower())
        if not lang:
            continue
        for fn in extract_functions(code, lang):
            if fn.name == t["func_name"] and VI.norm_hash(fn.code) == t["func_hash"]:
                matched += 1
                break
    return matched, len(case["targets"])


# ------------------------------------------------------------------ scoring
def score_case(case: dict, rep, scanned: list[str]) -> dict:
    """Compare what the scan reported against where the flaw actually is."""
    targets = {t["file_path"].replace("\\", "/") for t in case["targets"]}
    target_funcs = {(t["file_path"].replace("\\", "/"), t.get("func_hash")) for t in case["targets"] if t.get("func_hash")}
    scanned_set = {s.replace("\\", "/") for s in scanned}

    def norm(p):
        return (p or "").replace("\\", "/")

    selected = bool(targets & scanned_set)

    vuln_findings = [f for f in rep.findings if f["pillar"] == "vulnerability"]
    flagged_files = {norm(f["file"]) for f in vuln_findings}
    detected = bool(targets & flagged_files)
    if detected and not selected:
        raise ValueError("Invalid benchmark trace: target detected but not selected")

    localised = False
    cwe_strict = cwe_lenient = False
    for f in vuln_findings:
        fpath = norm(f["file"])
        if fpath not in targets:
            continue
        # Overloads may share a name; CWE credit requires the verified body.
        if (fpath, f.get("function_hash")) not in target_funcs:
            continue
        localised = True
        pred = f.get("cwe_id") or f.get("category")
        truth = case.get("cwe_primary")
        if pred and truth:
            if K.matches(pred, truth, lenient=False):
                cwe_strict = True
            if K.matches(pred, truth, lenient=True):
                cwe_lenient = True

    alarms = len([f for f in vuln_findings if norm(f["file"]) not in targets])
    return {
        "case_id": case["case_id"], "repo": case["repo"], "cve_id": case["cve_id"],
        "cwe_primary": case.get("cwe_primary"), "language": case["language"],
        "n_targets": case["n_targets"], "n_scanned": len(scanned),
        "selected": selected, "detected": detected, "localised": localised,
        "cwe_strict": cwe_strict, "cwe_lenient": cwe_lenient,
        "localisation_method": "verified_function_hash",
        "alarms_elsewhere": alarms,
        "total_findings": len(rep.findings),
        "clone_safety": rep.clone_safety,
        "supply_chain_findings": rep.by_pillar.get("supply_chain", 0),
    }


def summarise(rows: list[dict], model: str, strategy: str) -> dict:
    n = len(rows)
    if not n:
        return {}
    sel = sum(r["selected"] for r in rows)
    det = sum(r["detected"] for r in rows)
    # detection conditional on having looked at the file - separates the two failures
    det_given_sel = sum(r["detected"] for r in rows if r["selected"])
    return {
        "model": model, "strategy": strategy, "n_cases": n,
        "file_selection_rate": round(sel / n, 4),
        "detection_rate": round(det / n, 4),
        "detection_given_selected": round(det_given_sel / sel, 4) if sel else 0.0,
        "localisation_rate": round(sum(r["localised"] for r in rows) / n, 4),
        "cwe_strict_rate": round(sum(r["cwe_strict"] for r in rows) / n, 4),
        "cwe_lenient_rate": round(sum(r["cwe_lenient"] for r in rows) / n, 4),
        "mean_alarms_elsewhere": round(sum(r["alarms_elsewhere"] for r in rows) / n, 2),
        "mean_findings": round(sum(r["total_findings"] for r in rows) / n, 2),
        "by_language": {
            lang: round(sum(r["detected"] for r in rows if r["language"] == lang) /
                        max(sum(1 for r in rows if r["language"] == lang), 1), 4)
            for lang in sorted({r["language"] for r in rows})},
    }


# ------------------------------------------------------------------- driver
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", default=str(BENCH))
    ap.add_argument("--model", default="stub")
    ap.add_argument("--strategy", default="zero_shot")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-files", type=int, default=25)
    ap.add_argument("--out", default=None,
                    help="New prediction file; existing files are never overwritten")
    args = ap.parse_args()
    run_id = time.strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else RESULTS / "repo_bench_v2" / run_id / "predictions.jsonl"
    if out.exists():
        sys.exit(f"Refusing to overwrite existing predictions: {out}")
    out.parent.mkdir(parents=True, exist_ok=True)
    manifest_path = out.with_suffix(".manifest.json")
    if manifest_path.exists():
        sys.exit(f"Refusing to overwrite existing run manifest: {manifest_path}")

    bench = Path(args.bench)
    if not bench.exists():
        sys.exit(f"missing {bench} - run repo_bench_build.py first")
    cases = [json.loads(l) for l in bench.open(encoding="utf-8") if l.strip()]
    if args.limit:
        cases = cases[:args.limit]
    manifest = {"schema_version": 2, "model": args.model, "strategy": args.strategy,
                "max_files": args.max_files, "n_cases_requested": len(cases),
                "bench_sha256": hashlib.sha256(bench.read_bytes()).hexdigest(),
                "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in Path(__file__).parent.glob("*.py")},
                "status": "started", "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    provider = M.get(args.model)
    if not provider.is_available():
        sys.exit(f"model '{args.model}' unavailable. Have: {M.available()}")
    ls = json.loads((C.PROCESSED / "label_space.json").read_text(encoding="utf-8"))

    REPO_CACHE.mkdir(parents=True, exist_ok=True)
    rows, skipped = [], Counter()
    t0 = time.time()

    for i, case in enumerate(cases, 1):
        tag = f"[{i}/{len(cases)}] {case['repo']}@{case['fix_sha'][:8]} {case['cve_id']}"
        root = download_at(case["repo"], case["fix_sha"], REPO_CACHE)
        if root is None:
            print(f"  {tag}: SKIP (download failed)")
            skipped["download"] += 1
            continue
        okay, why = make_vulnerable(root, case)
        if not okay:
            print(f"  {tag}: SKIP ({why})")
            skipped["reconstruct"] += 1
            continue
        matched, total = verify(root, case)
        if matched != total or not total:
            print(f"  {tag}: SKIP (rebuild did not match the recorded function)")
            skipped["verify"] += 1
            continue

        rep = RA.analyse_repo(root, provider, ls, args.strategy,
                              max_files=args.max_files, verbose=False,
                              repo_slug=case["repo"], novelty_scope="eval")
        scanned = rep.coverage["selected_files"]
        row = score_case(case, rep, scanned)
        row["verified_targets"] = f"{matched}/{total}"
        row["model"], row["strategy"] = args.model, args.strategy
        row["coverage"] = rep.coverage
        # Preserve the evidence required to adjudicate target-file alarm hits.
        row["findings"] = rep.findings
        row["schema_version"] = 2
        rows.append(row)
        # Checkpoint each completed case; a cancelled run retains its evidence.
        with out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        print(f"  {tag}: selected={row['selected']} detected={row['detected']} "
              f"cwe={row['cwe_lenient']} alarms={row['alarms_elsewhere']}")

    s = summarise(rows, args.model, args.strategy)
    s["skipped"] = dict(skipped)
    s["wall_s"] = round(time.time() - t0, 1)
    spath = out.with_suffix(".summary.json")
    spath.write_text(json.dumps(s, indent=1), encoding="utf-8")
    manifest["status"] = "complete"
    manifest["n_scored"] = len(rows)
    manifest["skipped"] = dict(skipped)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print("\n" + "=" * 68)
    print(f"REPOSITORY-LEVEL RESULTS — {args.model} / {args.strategy}")
    print("=" * 68)
    for k in ("n_cases", "file_selection_rate", "detection_rate",
              "detection_given_selected", "localisation_rate",
              "cwe_strict_rate", "cwe_lenient_rate", "mean_alarms_elsewhere"):
        print(f"  {k:<26} {s.get(k)}")
    print(f"  by language                {s.get('by_language')}")
    print(f"  skipped                    {dict(skipped)}")
    print(f"\n  predictions -> {out}\n  summary     -> {spath}")


if __name__ == "__main__":
    main()
