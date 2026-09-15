"""Pillar 4, step 1 - build a package-advisory index from the cached OSV data.

For each advisory we need three things to construct a dependency benchmark:

    * the package name and ecosystem
    * at least one version that IS affected      -> used to create a positive
    * the version that fixed it                  -> used to create a hard negative

The hard negative matters: a scanner (or model) that simply flags any package
name it has ever seen in an advisory would score well on a benchmark made only
of vulnerable pins. Including the *patched* version of the same package forces
the system to reason about the version, not just the name.

    python src/deps_collect.py --ecosystems PyPI,npm,Maven
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C

OSV_CACHE = C.CACHE / "osv"
ECOSYSTEM_LANG = {"PyPI": "python", "npm": "javascript", "Maven": "java"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")


def fixed_versions(affected: dict) -> list[str]:
    """Versions listed as introducing the fix (ECOSYSTEM/SEMVER ranges)."""
    out = []
    for rng in affected.get("ranges") or []:
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        for ev in rng.get("events") or []:
            if ev.get("fixed"):
                out.append(ev["fixed"])
    return out


def extract(adv: dict) -> list[dict]:
    """One record per affected package in this advisory."""
    ds = adv.get("database_specific") or {}
    cwes = [c for c in (ds.get("cwe_ids") or []) if isinstance(c, str) and c.startswith("CWE-")]
    sev = (ds.get("severity") or "").upper() or None
    cve = next((a for a in adv.get("aliases", []) if CVE_RE.match(a)), None)

    out = []
    for aff in adv.get("affected") or []:
        pkg = aff.get("package") or {}
        name, eco = pkg.get("name"), pkg.get("ecosystem")
        if not name or eco not in ECOSYSTEM_LANG:
            continue
        vulnerable = list(aff.get("versions") or [])
        fixed = fixed_versions(aff)
        if not vulnerable:
            continue
        out.append({
            "advisory_id": adv.get("id"),
            "cve_id": cve,
            "ecosystem": eco,
            "language": ECOSYSTEM_LANG[eco],
            "package": name,
            "vulnerable_versions": vulnerable[-25:],   # newest affected are most realistic
            "fixed_versions": fixed,
            "cwe_ids": cwes,
            "cwe_primary": cwes[0] if cwes else None,
            "severity": sev,
            "summary": (adv.get("summary") or "")[:300],
            "published": adv.get("published"),
        })
    return out


def collect(ecosystems: list[str], verbose: bool = True) -> list[dict]:
    records: list[dict] = []
    for eco in ecosystems:
        zp = OSV_CACHE / f"{eco}.zip"
        if not zp.exists():
            print(f"  !! {eco}.zip not cached - run osv_collect.py first")
            continue
        z = zipfile.ZipFile(zp)
        names = [n for n in z.namelist() if n.endswith(".json")]
        kept = 0
        for n in names:
            try:
                adv = json.loads(z.read(n))
            except Exception:
                continue
            for rec in extract(adv):
                records.append(rec)
                kept += 1
        if verbose:
            print(f"  {eco:6s} {len(names):6d} advisories -> {kept:5d} package records")
    return records


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ecosystems", default="PyPI,npm,Maven")
    ap.add_argument("--out", default=str(C.INTERIM / "dep_advisories.json"))
    args = ap.parse_args()

    ecos = [e.strip() for e in args.ecosystems.split(",") if e.strip()]
    print(f"Building package-advisory index for: {ecos}")
    recs = collect(ecos)
    Path(args.out).write_text(json.dumps(recs), encoding="utf-8")

    with_fix = sum(1 for r in recs if r["fixed_versions"])
    with_cwe = sum(1 for r in recs if r["cwe_primary"])
    print(f"\ntotal package records      : {len(recs)}")
    print(f"  with a known fixed version: {with_fix}")
    print(f"  with a CWE label          : {with_cwe}")
    print(f"  unique packages           : {len({(r['ecosystem'], r['package']) for r in recs})}")
    print(f"  by ecosystem              : {dict(Counter(r['ecosystem'] for r in recs))}")
    print(f"  by severity               : {dict(Counter(r['severity'] or 'UNK' for r in recs))}")
    print(f"\nWrote -> {args.out}")


if __name__ == "__main__":
    main()
