"""Step A - Collect CVE metadata from the NVD 2.0 API.

Produces one record per CVE that has (a) at least one CWE assigned and
(b) at least one GitHub commit link tagged as a patch. Language is NOT known
at this stage - it is resolved later from the actual changed file extensions
(see patch_fetch.py / func_extract.py), which is the only reliable signal.

Raw API pages are cached to data/cache/nvd/ so re-runs cost zero requests.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C

NVD_CACHE = C.CACHE / "nvd"
NVD_CACHE.mkdir(parents=True, exist_ok=True)

# github.com/<owner>/<repo>/commit/<sha>  (also tolerates the /commits/ variant)
COMMIT_RE = re.compile(
    r"https?://github\.com/"
    r"([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)"   # owner/repo
    r"/commits?/"
    r"([0-9a-fA-F]{7,40})"                    # sha
)


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": C.USER_AGENT})
    key = os.environ.get("NVD_API_KEY")
    if key:
        s.headers.update({"apiKey": key})
    return s


def _sleep_for_rate_limit() -> None:
    time.sleep(C.NVD_SLEEP_WITH_KEY if os.environ.get("NVD_API_KEY") else C.NVD_SLEEP_NO_KEY)


def parse_commit_refs(cve: dict) -> list[dict]:
    """Return GitHub commit references, preferring those explicitly tagged 'Patch'."""
    out, seen = [], set()
    for ref in cve.get("references", []):
        url = ref.get("url", "")
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
        tags = ref.get("tags", []) or []
        out.append({"repo": repo, "sha": sha, "tagged_patch": "Patch" in tags, "url": url})
    # Patch-tagged references first: they are the highest-confidence fix commits.
    out.sort(key=lambda r: (not r["tagged_patch"],))
    return out


def parse_cwes(cve: dict) -> list[str]:
    out = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = (d.get("value") or "").strip()
            if v.startswith("CWE-") and v not in out:
                out.append(v)
    return out


def parse_cvss(cve: dict) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or arr[0].get("baseSeverity")
            return score, sev
    return None, None


def fetch_window(sess: requests.Session, start: datetime, end: datetime,
                 verbose: bool = True) -> list[dict]:
    """Fetch every CVE published in [start, end), paging through the API."""
    tag = f"{start:%Y%m%d}_{end:%Y%m%d}"
    cache_file = NVD_CACHE / f"nvd_{tag}.json"
    if cache_file.exists():
        if verbose:
            print(f"  [cache] {tag}")
        return json.loads(cache_file.read_text(encoding="utf-8"))

    collected, start_index, total = [], 0, None
    while True:
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT00:00:00.000"),
            "resultsPerPage": C.NVD_PAGE_SIZE,
            "startIndex": start_index,
        }
        for attempt in range(4):
            try:
                r = sess.get(C.NVD_API, params=params, timeout=90)
                if r.status_code == 200:
                    break
                if verbose:
                    print(f"    HTTP {r.status_code}, retry {attempt + 1}/4")
                time.sleep(8 * (attempt + 1))
            except requests.RequestException as e:
                if verbose:
                    print(f"    {type(e).__name__}, retry {attempt + 1}/4")
                time.sleep(8 * (attempt + 1))
        else:
            print(f"    !! giving up on window {tag} at index {start_index}")
            break

        payload = r.json()
        total = payload.get("totalResults", 0)
        vulns = payload.get("vulnerabilities", [])
        collected.extend(vulns)
        start_index += len(vulns)
        if verbose:
            print(f"    {tag}: {start_index}/{total}")
        if not vulns or start_index >= total:
            break
        _sleep_for_rate_limit()

    cache_file.write_text(json.dumps(collected), encoding="utf-8")
    _sleep_for_rate_limit()
    return collected


def distill(vulns: list[dict]) -> list[dict]:
    """Keep only CVEs usable for our task: has CWE + has a GitHub commit link."""
    out = []
    for item in vulns:
        cve = item.get("cve", {})
        if cve.get("vulnStatus") == "Rejected":
            continue
        cwes = parse_cwes(cve)
        # Drop non-informative placeholder CWEs.
        cwes = [c for c in cwes if c not in ("CWE-noinfo", "CWE-Other", "NVD-CWE-noinfo",
                                             "NVD-CWE-Other")]
        if not cwes:
            continue
        refs = parse_commit_refs(cve)
        if not refs:
            continue
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        score, sev = parse_cvss(cve)
        out.append({
            "cve_id": cve.get("id"),
            "published": cve.get("published"),
            "cwe_ids": cwes,
            "cwe_primary": cwes[0],
            "description": desc,
            "cvss_score": score,
            "cvss_severity": sev,
            "commit_refs": refs,
        })
    return out


# CWEs targeted for collection. Chosen to span BOTH ecosystems so the corpus is
# not monopolised by C/C++ memory bugs:
#   memory-safety   -> mostly C/C++
#   injection / web -> mostly Java, Python, JavaScript
TARGET_CWES = [
    # memory safety (C/C++)
    "CWE-787", "CWE-125", "CWE-416", "CWE-476", "CWE-190", "CWE-119",
    "CWE-401", "CWE-415", "CWE-369",
    # injection / web (Java, Python, JS)
    "CWE-79", "CWE-89", "CWE-22", "CWE-78", "CWE-77", "CWE-94",
    "CWE-502", "CWE-918", "CWE-611", "CWE-352", "CWE-601",
    # access control / resource / crypto (all languages)
    "CWE-287", "CWE-306", "CWE-863", "CWE-732", "CWE-400", "CWE-770",
    "CWE-327", "CWE-798", "CWE-20", "CWE-200",
]


def fetch_by_cwe(sess: requests.Session, cwe: str, max_pages: int = 2,
                 verbose: bool = True) -> list[dict]:
    """Fetch CVEs carrying a specific CWE. Far more efficient than sweeping all
    CVEs by date, because it pulls only records relevant to our task."""
    cache_file = NVD_CACHE / f"cwe_{cwe.replace('-', '')}.json"
    if cache_file.exists():
        if verbose:
            print(f"  [cache] {cwe}")
        return json.loads(cache_file.read_text(encoding="utf-8"))

    collected, start_index = [], 0
    for page in range(max_pages):
        params = {"cweId": cwe, "resultsPerPage": C.NVD_PAGE_SIZE, "startIndex": start_index}
        for attempt in range(3):
            try:
                r = sess.get(C.NVD_API, params=params, timeout=150)
                if r.status_code == 200:
                    break
                time.sleep(10 * (attempt + 1))
            except requests.RequestException:
                time.sleep(10 * (attempt + 1))
        else:
            if verbose:
                print(f"    !! {cwe} failed at index {start_index}")
            break

        payload = r.json()
        total = payload.get("totalResults", 0)
        vulns = payload.get("vulnerabilities", [])
        collected.extend(vulns)
        start_index += len(vulns)
        if verbose:
            print(f"    {cwe}: {start_index}/{total}")
        if not vulns or start_index >= total:
            break
        _sleep_for_rate_limit()

    cache_file.write_text(json.dumps(collected), encoding="utf-8")
    _sleep_for_rate_limit()
    return collected


def collect_by_cwes(cwes: list[str] | None = None, max_pages: int = 2,
                    verbose: bool = True) -> list[dict]:
    """Collect usable CVEs across a set of target CWEs, de-duplicated by CVE id."""
    sess = _session()
    cwes = cwes or TARGET_CWES
    if verbose:
        print(f"CWE-targeted collection over {len(cwes)} CWEs "
              f"(<= {max_pages} pages each)")

    seen: set[str] = set()
    out: list[dict] = []
    for i, cwe in enumerate(cwes, 1):
        if verbose:
            print(f"[{i}/{len(cwes)}] {cwe}")
        raw = fetch_by_cwe(sess, cwe, max_pages=max_pages, verbose=verbose)
        for rec in distill(raw):
            if rec["cve_id"] in seen:
                continue
            seen.add(rec["cve_id"])
            out.append(rec)
        if verbose:
            print(f"    running usable total: {len(out)}")
    return out


def collect(start_year: int, end_year: int, window_days: int = 100,
            verbose: bool = True) -> list[dict]:
    sess = _session()
    has_key = bool(os.environ.get("NVD_API_KEY"))
    if verbose:
        print(f"NVD collection {start_year}-{end_year} "
              f"({'with' if has_key else 'no'} API key, "
              f"{C.NVD_SLEEP_WITH_KEY if has_key else C.NVD_SLEEP_NO_KEY}s spacing)")

    cur = datetime(start_year, 1, 1, tzinfo=timezone.utc)
    stop = datetime(end_year + 1, 1, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    stop = min(stop, now)

    all_raw = []
    while cur < stop:
        nxt = min(cur + timedelta(days=window_days), stop)
        all_raw.extend(fetch_window(sess, cur, nxt, verbose=verbose))
        cur = nxt

    distilled = distill(all_raw)
    if verbose:
        print(f"\nRaw CVEs fetched      : {len(all_raw)}")
        print(f"Usable (CWE + commit) : {len(distilled)}")
    return distilled


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Collect CVEs with GitHub patch commits from NVD")
    ap.add_argument("--mode", choices=["cwe", "date"], default="cwe",
                    help="cwe = query target CWEs (efficient, default); "
                         "date = sweep all CVEs in a year range")
    ap.add_argument("--start", type=int, default=2020)
    ap.add_argument("--end", type=int, default=2024)
    ap.add_argument("--max-pages", type=int, default=2,
                    help="pages (2000 CVEs each) per CWE in cwe mode")
    ap.add_argument("--out", default=str(C.INTERIM / "cve_candidates.json"))
    args = ap.parse_args()

    if args.mode == "cwe":
        recs = collect_by_cwes(max_pages=args.max_pages)
    else:
        recs = collect(args.start, args.end)
    Path(args.out).write_text(json.dumps(recs, indent=1), encoding="utf-8")
    print(f"\nWrote {len(recs)} CVE candidates -> {args.out}")
