"""Ecosystem-targeted collection from OSV (osv.dev).

Why this exists
---------------
NVD does not record a vulnerability's language, so `nvd_collect.py` has to
collect everything and discover the language only after downloading each patch.
That is wasteful, and in practice it produced a corpus that was 83% C/C++ -
too thin in Java/JS/Python to support a per-language claim.

OSV publishes advisories grouped by PACKAGE ECOSYSTEM, which maps almost
directly onto language:

    Maven -> Java        npm -> JavaScript/TypeScript        PyPI -> Python

so we can pull language-targeted data at the source. Records also carry
`database_specific.cwe_ids`, giving us the CWE label without a second lookup.

Output matches `nvd_collect.distill()` exactly, so `build_dataset.py` consumes
it unchanged.

    python src/osv_collect.py --ecosystems Maven,npm,PyPI
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import zipfile
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C

OSV_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
OSV_CACHE = C.CACHE / "osv"
OSV_CACHE.mkdir(parents=True, exist_ok=True)

ECOSYSTEM_LANG = {"Maven": "java", "npm": "javascript", "PyPI": "python"}

COMMIT_RE = re.compile(
    r"https?://github\.com/"
    r"([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)"
    r"/commits?/"
    r"([0-9a-fA-F]{7,40})"
)
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")

SEVERITY_SCORE = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}


def download(eco: str, verbose: bool = True) -> zipfile.ZipFile:
    local = OSV_CACHE / f"{eco}.zip"
    if not local.exists():
        if verbose:
            print(f"  downloading {eco} ...")
        r = requests.get(OSV_ZIP.format(eco=eco), timeout=900,
                         headers={"User-Agent": C.USER_AGENT})
        r.raise_for_status()
        local.write_bytes(r.content)
    if verbose:
        print(f"  {eco}: {local.stat().st_size / 1e6:.1f} MB cached")
    return zipfile.ZipFile(local)


def parse_advisory(adv: dict) -> dict | None:
    """Convert one OSV record into our CVE-candidate schema, or None if unusable."""
    ds = adv.get("database_specific") or {}
    cwes = [c for c in (ds.get("cwe_ids") or [])
            if isinstance(c, str) and c.startswith("CWE-")]
    if not cwes:
        return None

    refs, seen = [], set()
    for ref in adv.get("references", []):
        url = ref.get("url", "") or ""
        m = COMMIT_RE.search(url)
        if not m:
            continue
        repo, sha = m.group(1), m.group(2)
        if repo.endswith(".git"):
            repo = repo[:-4]
        key = (repo.lower(), sha.lower())
        if key in seen:
            continue
        seen.add(key)
        # OSV tags fix commits as type FIX - treat those as patch-confidence
        refs.append({"repo": repo, "sha": sha,
                     "tagged_patch": ref.get("type") == "FIX", "url": url})
    if not refs:
        return None
    refs.sort(key=lambda r: (not r["tagged_patch"],))

    # Prefer the CVE alias as the id so records join cleanly with the NVD pool.
    cve_id = next((a for a in adv.get("aliases", []) if CVE_RE.match(a)), adv.get("id"))
    sev = (ds.get("severity") or "").upper() or None

    score = None
    for s in adv.get("severity", []) or []:
        if isinstance(s, dict) and s.get("type", "").startswith("CVSS"):
            m = re.search(r"/AV:", s.get("score", ""))
            if m:
                break
    if sev in SEVERITY_SCORE:
        score = SEVERITY_SCORE[sev]

    return {
        "cve_id": cve_id,
        "osv_id": adv.get("id"),
        "published": adv.get("published"),
        "cwe_ids": cwes,
        "cwe_primary": cwes[0],
        "description": (adv.get("summary") or adv.get("details") or "")[:1500],
        "cvss_score": score,
        "cvss_severity": sev,
        "commit_refs": refs,
    }


def collect(ecosystems: list[str], verbose: bool = True) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for eco in ecosystems:
        z = download(eco, verbose)
        names = z.namelist()
        kept = 0
        for n in names:
            if not n.endswith(".json"):
                continue
            try:
                adv = json.loads(z.read(n))
            except Exception:
                continue
            rec = parse_advisory(adv)
            if not rec:
                continue
            if rec["cve_id"] in seen:
                continue
            seen.add(rec["cve_id"])
            rec["osv_ecosystem"] = eco
            rec["expected_language"] = ECOSYSTEM_LANG.get(eco)
            out.append(rec)
            kept += 1
        if verbose:
            print(f"  {eco}: {len(names)} advisories -> {kept} usable "
                  f"(CWE + GitHub commit)")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ecosystems", default="Maven,npm,PyPI")
    ap.add_argument("--out", default=str(C.INTERIM / "osv_candidates.json"))
    args = ap.parse_args()

    ecos = [e.strip() for e in args.ecosystems.split(",") if e.strip()]
    print(f"OSV ecosystem collection: {ecos}")
    recs = collect(ecos)
    Path(args.out).write_text(json.dumps(recs, indent=1), encoding="utf-8")

    from collections import Counter
    print(f"\ntotal usable advisories : {len(recs)}")
    print(f"by ecosystem            : {dict(Counter(r['osv_ecosystem'] for r in recs))}")
    print(f"distinct CWEs           : {len({r['cwe_primary'] for r in recs})}")
    print(f"top CWEs                : {Counter(r['cwe_primary'] for r in recs).most_common(8)}")
    print(f"\nWrote -> {args.out}")


if __name__ == "__main__":
    main()
