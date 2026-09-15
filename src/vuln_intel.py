"""Advisory knowledge used at ANALYSIS time (not dataset-build time).

The collection scripts already gather everything needed to name a vulnerability,
but until now that knowledge was only used to build the training corpus. This
module makes it available while a repository is being scanned, so a finding can
carry an identifier instead of only a description.

Two independent services:

  lookup_dependency()   (ecosystem, package, version) -> the advisory that
                        covers it: CVE id, CWE, severity, summary, and the
                        version to upgrade to.

  classify_novelty()    Is a flagged function a vulnerability that has already
                        been published, or one with no match in the corpus?

    known           the exact function text matches a function that was patched
                    for a published CVE. Highest confidence; the CVE is named.
    known_location  same project and function name as a past CVE, but the code
                    differs - a fixed, refactored, or regressed version of a
                    function with vulnerability history. Worth a human look.
    novel           no match. IMPORTANT: this means "absent from this corpus",
                    not "confirmed zero-day". Corpus limits are reported by
                    corpus_info() and printed in the report so the claim stays
                    honest.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C

ADVISORIES = C.INTERIM / "dep_advisories.json"
CORPUS = C.PROCESSED / "dataset_merged.jsonl"

# Two indexes, because the same lookup serves two incompatible purposes.
#
#   audit  every CVE we know of. Correct when auditing a real repository: you
#          want to recognise a known vulnerability no matter which split it
#          happened to land in.
#   eval   train + val only. Required when MEASURING the platform on the test
#          split - an index containing the test functions would "recognise"
#          them instantly and report a detection rate that is pure leakage.
SCOPES = {"audit": None,                                   # everything
          "eval": ("train.jsonl", "val.jsonl")}            # test held out
FUNC_CACHE = {"audit": C.INTERIM / "known_func_index.json",
              "eval": C.INTERIM / "known_func_index_eval.json"}

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, None: 0}

_dep_idx: dict | None = None
_func_idx: dict[str, dict] = {}


# --------------------------------------------------------------- helpers
def norm_hash(code: str) -> str:
    """Must stay identical to build_dataset.norm_hash or nothing will match."""
    compact = re.sub(r"\s+", " ", code).strip()
    return hashlib.md5(compact.encode("utf-8", errors="replace")).hexdigest()


def _best(advs: list[dict]) -> dict:
    """Most serious advisory wins; prefer one that actually carries a CVE id."""
    return max(advs, key=lambda a: (SEV_RANK.get(a.get("severity"), 0),
                                    bool(a.get("cve_id"))))


# ------------------------------------------------------- dependency lookup
def _load_dep_index() -> dict:
    global _dep_idx
    if _dep_idx is not None:
        return _dep_idx
    exact: dict[tuple, list] = {}
    by_pkg: dict[tuple, list] = {}
    if ADVISORIES.exists():
        for rec in json.loads(ADVISORIES.read_text(encoding="utf-8")):
            eco, pkg = rec["ecosystem"], rec["package"]
            key_pkg = (eco, pkg.lower())
            slim = {
                "advisory_id": rec.get("advisory_id"),
                "cve_id": rec.get("cve_id"),
                "cwe_primary": rec.get("cwe_primary"),
                "severity": rec.get("severity"),
                "summary": (rec.get("summary") or "").strip(),
                "fixed_versions": rec.get("fixed_versions") or [],
                "published": rec.get("published"),
                "package": pkg,
            }
            by_pkg.setdefault(key_pkg, []).append(slim)
            for v in rec.get("vulnerable_versions") or []:
                exact.setdefault((eco, pkg.lower(), v), []).append(slim)
    _dep_idx = {"exact": exact, "by_package": by_pkg}
    return _dep_idx


def lookup_dependency(ecosystem: str, package: str, version: str | None) -> dict:
    """What the advisory data says about this package version.

    Always returns a dict, because "we found nothing" has two very different
    meanings and collapsing them into None would let missing data read as
    proof of safety:

        affected         this exact version is listed as affected - confirmed
        unpinned         the package has advisories but the manifest gives a
                         range, so we cannot tell which version is installed
        not_affected     the package is covered and this version is not listed
        no_advisory_data we hold no advisories for this package at all; this is
                         a gap in coverage, NOT evidence that it is safe
    """
    idx = _load_dep_index()
    pkg = (package or "").lower()
    known_pkg = (ecosystem, pkg) in idx["by_package"]

    if version:
        hits = idx["exact"].get((ecosystem, pkg, version))
        if hits:
            a = dict(_best(hits))
            a["status"] = "affected"
            a["n_advisories"] = len(hits)
            return a
        return {"status": "not_affected" if known_pkg else "no_advisory_data"}

    hits = idx["by_package"].get((ecosystem, pkg))
    if hits:
        a = dict(_best(hits))
        a["status"] = "unpinned"
        a["n_advisories"] = len(hits)
        return a
    return {"status": "no_advisory_data"}


def identifier(adv: dict) -> str:
    """Preferred public id. Half of GHSA advisories have no CVE assigned."""
    return adv.get("cve_id") or adv.get("advisory_id") or "unidentified"


def remediation(adv: dict) -> str | None:
    fixed = adv.get("fixed_versions") or []
    return f"upgrade to {fixed[0]}" if fixed else None


# ------------------------------------------------------ novelty of a finding
def _sources(scope: str) -> list[Path]:
    files = SCOPES.get(scope, None)
    if files is None:
        return [CORPUS]
    return [C.PROCESSED / f for f in files]


def _build_func_index(scope: str = "audit") -> dict:
    """func_hash -> CVE facts, plus a looser project+function index."""
    by_hash: dict[str, dict] = {}
    by_loc: dict[str, dict] = {}
    published: list[str] = []
    for src in _sources(scope):
        if not src.exists():
            continue
        with src.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if r.get("label") != 1 or not r.get("cve_id"):
                    continue
                info = {"cve_id": r["cve_id"], "cwe_primary": r.get("cwe_primary"),
                        "cwe_name": r.get("cwe_name"), "published": r.get("cve_published"),
                        "severity": r.get("cvss_severity"), "repo": r.get("repo"),
                        "file_path": r.get("file_path"), "func_name": r.get("func_name")}
                if r.get("func_hash"):
                    by_hash.setdefault(r["func_hash"], info)
                if r.get("repo") and r.get("func_name"):
                    by_loc.setdefault(f"{r['repo'].lower()}::{r['func_name']}", info)
                if r.get("cve_published"):
                    published.append(r["cve_published"][:10])
    published.sort()
    return {"by_hash": by_hash, "by_loc": by_loc,
            "n_functions": len(by_hash), "n_locations": len(by_loc),
            "n_cves": len({v["cve_id"] for v in by_hash.values()}),
            "earliest": published[0] if published else None,
            "latest": published[-1] if published else None}


def _load_func_index(scope: str = "audit") -> dict:
    """Cached: parsing the full corpus each scan would cost seconds every run."""
    if scope in _func_idx:
        return _func_idx[scope]
    cache = FUNC_CACHE[scope]
    newest = max((s.stat().st_mtime for s in _sources(scope) if s.exists()),
                 default=0.0)
    if cache.exists() and newest and cache.stat().st_mtime >= newest:
        try:
            _func_idx[scope] = json.loads(cache.read_text(encoding="utf-8"))
            return _func_idx[scope]
        except Exception:
            pass                      # corrupt cache: fall through and rebuild
    idx = _build_func_index(scope)
    _func_idx[scope] = idx
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(idx), encoding="utf-8")
    except Exception:
        pass                          # cache is an optimisation, never required
    return idx


def classify_novelty(code: str, repo_slug: str | None = None,
                     func_name: str | None = None, scope: str = "audit") -> dict:
    """{novelty, cve_id, cwe_primary, note} for a function the model flagged.

    scope="audit" when auditing a real repository (recognise every known CVE);
    scope="eval"  when measuring on the test split (test CVEs held out, so a
    detection cannot come from having the answer in the index).
    """
    idx = _load_func_index(scope)

    hit = idx["by_hash"].get(norm_hash(code))
    if hit:
        return {"novelty": "known", "cve_id": hit["cve_id"],
                "cwe_primary": hit.get("cwe_primary"),
                "severity": hit.get("severity"),
                "note": f"exact match to the function patched for {hit['cve_id']}"
                        f" ({hit.get('cwe_name') or hit.get('cwe_primary') or 'unclassified'})"}

    if repo_slug and func_name:
        hit = idx["by_loc"].get(f"{repo_slug.lower()}::{func_name}")
        if hit:
            return {"novelty": "known_location", "cve_id": hit["cve_id"],
                    "cwe_primary": hit.get("cwe_primary"),
                    "severity": hit.get("severity"),
                    "note": f"same function was patched for {hit['cve_id']}, but the "
                            f"code differs - check for a regression or an incomplete fix"}

    return {"novelty": "novel", "cve_id": None, "cwe_primary": None, "severity": None,
            "note": "no matching advisory in the corpus - unreported, or outside "
                    "the corpus coverage"}


def corpus_info(scope: str = "audit") -> dict:
    """Coverage of the novelty check, so a report can state its own limits."""
    idx = _load_func_index(scope)
    return {"functions": idx.get("n_functions", 0),
            "cves": idx.get("n_cves", 0),
            "earliest": idx.get("earliest"),
            "latest": idx.get("latest")}


def advisory_info() -> dict:
    """Coverage of the dependency lookup."""
    idx = _load_dep_index()
    pkgs = idx["by_package"]
    per_eco: dict[str, int] = {}
    for eco, _ in pkgs:
        per_eco[eco] = per_eco.get(eco, 0) + 1
    return {"packages": len(pkgs), "per_ecosystem": per_eco}


def coverage_note(scope: str = "audit") -> str:
    c = corpus_info(scope)
    a = advisory_info()
    if not c["functions"]:
        return ("Novelty was not checked: the reference corpus is unavailable, so "
                "no finding can be confirmed as previously published.")
    span = f" published {c['earliest']} to {c['latest']}" if c["earliest"] else ""
    return (f"\"Known\" means the code matches one of {c['functions']:,} functions "
            f"patched for {c['cves']:,} published CVEs{span}. \"Not previously "
            f"reported\" means no match was found in that corpus - it is a lead to "
            f"investigate, not a confirmed zero-day. Dependency identifiers come "
            f"from advisories for {a['packages']:,} packages; a package we hold no "
            f"advisories for is reported as unknown coverage, never as safe.")


if __name__ == "__main__":
    print("corpus  :", corpus_info())
    print("advisory:", advisory_info())
    print()
    print(coverage_note())
    print()
    for eco, pkg, ver in (("PyPI", "flask", "0.12"), ("PyPI", "flask", "2.3.3"),
                          ("npm", "lodash", "4.17.20"), ("PyPI", "requests", None)):
        a = lookup_dependency(eco, pkg, ver)
        st = a["status"]
        extra = (f" {identifier(a)} [{a.get('severity')}] "
                 f"{remediation(a) or 'no fix listed'}") if st in ("affected", "unpinned") else ""
        print(f"  {eco}/{pkg}@{ver or '(unpinned)'}: {st}{extra}")
