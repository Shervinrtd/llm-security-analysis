"""Step D - Orchestrate collection into the final labelled dataset.

For every CVE fix commit we emit up to three kinds of function-level records:

  version="pre"       label=1  the function BEFORE the fix   (vulnerable)
  version="post"      label=0  the same function AFTER the fix (patched)
  version="unchanged" label=0  other functions in the same file, untouched

"pre"/"post" form matched pairs, which supports the paired "can the model tell
the vulnerable version from the fixed one?" analysis. "unchanged" records give
the corpus a realistic vulnerable:safe imbalance instead of a forced 50/50.

Output: JSONL, one record per function, at data/processed/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import cwe_catalog
import patch_fetch as P
from func_extract import extract_functions, functions_touching, changed_within

SCHEMA_VERSION = "1.0"


def norm_hash(code: str) -> str:
    """Whitespace-insensitive hash, used for de-duplication (SecVulEval-style)."""
    compact = re.sub(r"\s+", " ", code).strip()
    return hashlib.md5(compact.encode("utf-8", errors="replace")).hexdigest()


def make_record(*, cve: dict, repo: str, sha: str, commit_msg: str, path: str,
                lang: str, func, version: str, label: int,
                changed_lines: list[int], pair_id: str | None) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": hashlib.md5(
            f"{cve['cve_id']}|{repo}|{sha}|{path}|{func.name}|{version}".encode()
        ).hexdigest()[:16],
        "pair_id": pair_id,

        # ---- task labels ----
        "label": label,                                   # 1 = vulnerable
        "cwe_primary": cve["cwe_primary"] if label == 1 else None,
        "cwe_name": cwe_catalog.name_of(cve["cwe_primary"]) if label == 1 else None,
        "cwe_ids": cve["cwe_ids"] if label == 1 else [],

        # ---- code ----
        "language": lang,
        "language_family": C.LANG_FAMILY[lang],
        "func_name": func.name,
        "code": func.code,
        "loc": func.loc,
        "version": version,
        "changed_lines_in_func": changed_lines,           # 1-based within function

        # ---- provenance (also enables a future leakage audit by date) ----
        "cve_id": cve["cve_id"],
        "cve_published": cve.get("published"),
        "cve_description": cve.get("description", "")[:1500],
        "cvss_score": cve.get("cvss_score"),
        "cvss_severity": cve.get("cvss_severity"),
        "repo": repo,
        "commit_sha": sha,
        "commit_message": (commit_msg or "")[:1000],
        "file_path": path,
        "func_hash": norm_hash(func.code),
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def process_cve(cve: dict, want_langs: set[str], stats: Counter,
                include_unchanged: bool = True, verbose: bool = False) -> list[dict]:
    records: list[dict] = []

    for ref in cve["commit_refs"][:2]:          # at most 2 commits per CVE
        repo, sha = ref["repo"], ref["sha"]
        patch = P.fetch_patch(repo, sha)
        if not patch:
            stats["commit_fetch_failed"] += 1
            continue

        msg = P.commit_message_from_patch(patch)
        if P.is_noisy_commit(msg):
            stats["commit_noisy_skipped"] += 1
            continue

        fds = P.parse_patch(patch)
        src_fds = [fd for fd in fds
                   if P.lang_of(fd.path) in want_langs
                   and not fd.is_new and not fd.is_deleted and fd.hunks]
        if not src_fds:
            stats["commit_no_target_lang"] += 1
            continue
        if len(fds) > C.MAX_FILES_PER_COMMIT:
            stats["commit_too_many_files"] += 1
            continue

        for fd in src_fds:
            lang = P.lang_of(fd.path)
            post_text = P.fetch_file(repo, sha, fd.path)
            if not post_text:
                stats["file_fetch_failed"] += 1
                continue
            pre_text = P.reverse_apply(post_text, fd)
            if pre_text is None:
                stats["file_reverse_apply_failed"] += 1
                continue

            post_funcs = extract_functions(post_text, lang)
            pre_funcs = extract_functions(pre_text, lang)
            if not post_funcs and not pre_funcs:
                stats["file_no_functions"] += 1
                continue

            touched_post = functions_touching(post_funcs, fd.changed_new_lines)
            touched_pre = functions_touching(pre_funcs, fd.changed_old_lines)
            if len(touched_post) > C.MAX_CHANGED_FUNCS_PER_COMMIT:
                stats["file_too_many_changed_funcs"] += 1
                continue

            pre_by_name = defaultdict(list)
            for f in touched_pre:
                pre_by_name[f.name].append(f)
            touched_names = {f.name for f in touched_post} | {f.name for f in touched_pre}

            # --- changed functions: emit the pre (vulnerable) / post (fixed) pair
            for pf in touched_post:
                if pf.name == "<anonymous>":
                    stats["func_anonymous_skipped"] += 1
                    continue
                cands = pre_by_name.get(pf.name)
                if not cands:
                    stats["func_no_pre_match"] += 1
                    continue
                vf = cands[0]
                if not (C.MIN_FUNC_LOC <= vf.loc <= C.MAX_FUNC_LOC):
                    stats["func_loc_out_of_range"] += 1
                    continue
                if norm_hash(vf.code) == norm_hash(pf.code):
                    stats["func_identical_pre_post"] += 1
                    continue

                pair_id = hashlib.md5(f"{cve['cve_id']}|{repo}|{sha}|{fd.path}|{pf.name}".encode()).hexdigest()[:16]
                records.append(make_record(
                    cve=cve, repo=repo, sha=sha, commit_msg=msg, path=fd.path, lang=lang,
                    func=vf, version="pre", label=1,
                    changed_lines=changed_within(vf, fd.changed_old_lines), pair_id=pair_id))
                records.append(make_record(
                    cve=cve, repo=repo, sha=sha, commit_msg=msg, path=fd.path, lang=lang,
                    func=pf, version="post", label=0,
                    changed_lines=changed_within(pf, fd.changed_new_lines), pair_id=pair_id))
                stats["pairs_emitted"] += 1

            # --- untouched functions in the same file: realistic negatives.
            # Capped per file and sampled deterministically, so one large file
            # cannot dominate the corpus (seeded by path => reproducible).
            if include_unchanged:
                eligible = [pf for pf in post_funcs
                            if pf.name not in touched_names
                            and pf.name != "<anonymous>"
                            and C.MIN_FUNC_LOC <= pf.loc <= C.MAX_FUNC_LOC]
                if len(eligible) > C.MAX_UNCHANGED_PER_FILE:
                    rng = random.Random(f"{repo}|{sha}|{fd.path}")
                    eligible = rng.sample(eligible, C.MAX_UNCHANGED_PER_FILE)
                    stats["unchanged_downsampled_files"] += 1
                for pf in eligible:
                    records.append(make_record(
                        cve=cve, repo=repo, sha=sha, commit_msg=msg, path=fd.path, lang=lang,
                        func=pf, version="unchanged", label=0,
                        changed_lines=[], pair_id=None))
                    stats["unchanged_emitted"] += 1

    return records


def dedupe(records: list[dict], stats: Counter) -> list[dict]:
    """Drop functions whose normalised text was already seen (prevents leakage).

    De-duplication can remove one half of a pre/post pair when that half's text
    collides with something else, orphaning the survivor. An orphaned `pre` is
    still a perfectly good vulnerable sample, so we keep it but clear its
    `pair_id` - that preserves the invariant "every pair_id has both halves"
    without discarding usable data.
    """
    seen: set[str] = set()
    out = []
    # Keep vulnerable samples preferentially when text collides.
    for rec in sorted(records, key=lambda r: (-r["label"], r["version"] != "post")):
        h = rec["func_hash"]
        if h in seen:
            stats["deduped"] += 1
            continue
        seen.add(h)
        out.append(rec)

    halves: dict[str, set[str]] = defaultdict(set)
    for rec in out:
        if rec.get("pair_id"):
            halves[rec["pair_id"]].add(rec["version"])
    orphaned = {pid for pid, vs in halves.items() if not {"pre", "post"} <= vs}
    for rec in out:
        if rec.get("pair_id") in orphaned:
            rec["pair_id"] = None
            stats["pair_orphaned_unlinked"] += 1
    return out


def summarise(records: list[dict]) -> str:
    if not records:
        return "  (no records)"
    by_lang = Counter(r["language_family"] for r in records)
    by_label = Counter(r["label"] for r in records)
    by_ver = Counter(r["version"] for r in records)
    vuln = [r for r in records if r["label"] == 1]
    by_cwe = Counter(r["cwe_primary"] for r in vuln)
    lines = [
        f"  total functions : {len(records)}",
        f"  vulnerable (1)  : {by_label.get(1,0)}",
        f"  safe (0)        : {by_label.get(0,0)}",
        f"  versions        : {dict(by_ver)}",
        f"  languages       : {dict(by_lang)}",
        f"  unique CVEs     : {len({r['cve_id'] for r in records})}",
        f"  distinct CWEs   : {len(by_cwe)}",
        f"  top CWEs        : {by_cwe.most_common(8)}",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the labelled vulnerability dataset")
    ap.add_argument("--candidates", default=str(C.INTERIM / "cve_candidates.json"))
    ap.add_argument("--out", default=str(C.PROCESSED / "dataset.jsonl"))
    ap.add_argument("--limit", type=int, default=0, help="max CVEs to process (0 = all)")
    ap.add_argument("--langs", default="c,cpp,java,python,javascript")
    ap.add_argument("--no-unchanged", action="store_true",
                    help="skip untouched functions (emit only pre/post pairs)")
    args = ap.parse_args()

    want = {s.strip() for s in args.langs.split(",") if s.strip()}
    cves = json.loads(Path(args.candidates).read_text(encoding="utf-8"))
    if args.limit:
        cves = cves[:args.limit]

    print(f"Processing {len(cves)} CVEs | languages: {sorted(want)}")
    stats: Counter = Counter()
    all_records: list[dict] = []

    # Long runs are interruptible, so checkpoint periodically rather than only
    # writing at the end - otherwise a stop at 95% loses everything.
    ckpt = Path(args.out).with_suffix(".partial.jsonl")

    def write_partial() -> None:
        with ckpt.open("w", encoding="utf-8") as fh:
            for rec in all_records:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    for i, cve in enumerate(cves, 1):
        try:
            recs = process_cve(cve, want, stats, include_unchanged=not args.no_unchanged)
        except Exception as e:            # never let one bad CVE kill a long run
            stats[f"error_{type(e).__name__}"] += 1
            continue
        all_records.extend(recs)
        if i % 25 == 0 or i == len(cves):
            print(f"  [{i}/{len(cves)}] records so far: {len(all_records)}")
        if i % 200 == 0:
            write_partial()

    final = dedupe(all_records, stats)
    if ckpt.exists():
        ckpt.unlink()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for rec in final:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print("\n=== pipeline counters ===")
    for k, v in sorted(stats.items(), key=lambda kv: -kv[1]):
        print(f"  {k:34s} {v}")
    print("\n=== dataset summary ===")
    print(summarise(final))
    print(f"\nWrote {len(final)} records -> {out_path}")


if __name__ == "__main__":
    main()
