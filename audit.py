"""Audit a GitHub repository for security problems — the main tool.

Point it at a repository address and get back a comprehensive report:

    python audit.py https://github.com/owner/repo

It downloads the repository, runs all four security analysers (vulnerabilities,
malware, secrets, vulnerable dependencies), and writes an easy-to-read HTML
report plus a structured JSON report.

Needs one free API key (see `python run.py` for setup). Without a key it will
still download and route the repository using the offline self-test model, so
you can see the workflow end to end.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import config as C          # noqa: E402
import models as M          # noqa: E402
import repo_analyze as RA   # noqa: E402
import report_html as RH    # noqa: E402

GH_URL_RE = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com[/:]([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)


def parse_github(address: str) -> tuple[str, str] | None:
    m = GH_URL_RE.search(address.strip())
    if not m:
        return None
    return m.group(1), m.group(2)


def download_repo(owner: str, repo: str, dest: Path, verbose: bool = True) -> Path | None:
    """Get a repository's files into `dest`. Tries git clone, then a zip download."""
    # 1. shallow git clone (fast, no history) if git is available
    if shutil.which("git"):
        url = f"https://github.com/{owner}/{repo}.git"
        target = dest / repo
        if verbose:
            print(f"  cloning {url} ...")
        r = subprocess.run(["git", "clone", "--depth", "1", "--quiet", url, str(target)],
                           capture_output=True, text=True)
        if r.returncode == 0 and target.exists():
            return target
        if verbose:
            print(f"  git clone did not work ({r.stderr.strip()[:80]}), trying zip download ...")

    # 2. fall back to the codeload zip (public repos, no auth, not rate-limited)
    for branch in ("HEAD", "main", "master"):
        zurl = f"https://github.com/{owner}/{repo}/archive/{branch}.zip"
        try:
            req = urllib.request.Request(zurl, headers={"User-Agent": C.USER_AGENT})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read()
        except Exception:
            continue
        zpath = dest / "repo.zip"
        zpath.write_bytes(data)
        with zipfile.ZipFile(zpath) as z:
            z.extractall(dest)
        for child in dest.iterdir():
            if child.is_dir() and child.name.lower().startswith(repo.lower()):
                if verbose:
                    print(f"  downloaded via zip ({branch})")
                return child
    return None


def load_label_space() -> dict:
    p = C.PROCESSED / "label_space.json"
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"classes": [], "prompt_block": ""}


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit a GitHub repository for security problems")
    ap.add_argument("address", help="GitHub repository address, e.g. https://github.com/owner/repo")
    ap.add_argument("--model", default="", help="which model to use (default: first available)")
    ap.add_argument("--max-files", type=int, default=40, help="cap files analysed (cost control)")
    ap.add_argument("--vuln-strategy", default="zero_shot")
    ap.add_argument("--out", default="", help="HTML report path (default: reports/<repo>.html)")
    args = ap.parse_args()

    parsed = parse_github(args.address)
    if not parsed:
        sys.exit(f"Could not read a GitHub address from: {args.address}\n"
                 f"Expected something like  https://github.com/owner/repo")
    owner, repo = parsed

    # choose a model
    model_name = args.model
    if not model_name:
        avail = [m for m in M.available() if m != "stub"] or ["stub"]
        model_name = avail[0]
    provider = M.get(model_name)
    if not provider.is_available():
        sys.exit(f"Model '{model_name}' has no API key. Available: {M.available()}\n"
                 f"Run  python run.py  for setup help.")
    if model_name == "stub":
        print("  NOTE: no API key set — using the offline self-test model.")
        print("        The workflow will run, but the findings will be placeholders.")
        print("        Run  python run.py  to set up a free key for real analysis.\n")

    print(f"Auditing github.com/{owner}/{repo}   (model: {model_name})")

    tmp = Path(tempfile.mkdtemp(prefix="audit_"))
    try:
        root = download_repo(owner, repo, tmp)
        if root is None:
            sys.exit("Could not download the repository. Is it public and spelled correctly?")

        ls = load_label_space()
        print("  analysing files ...")
        report = RA.analyse_repo(root, provider, ls, args.vuln_strategy,
                                 max_files=args.max_files, verbose=False)
        report_dict = report.__dict__ if hasattr(report, "__dict__") else report

        # console summary
        print("\n" + "=" * 66)
        print(RA.natural_language_report(report))
        print("=" * 66)

        # HTML report
        out = Path(args.out) if args.out else (ROOT / "reports" / f"{owner}__{repo}.html")
        out.parent.mkdir(parents=True, exist_ok=True)
        RH.write(report_dict, out, source_url=f"github.com/{owner}/{repo}")

        # JSON report
        jout = out.with_suffix(".json")
        jout.write_text(json.dumps(report_dict, indent=1), encoding="utf-8")

        print(f"\n  Comprehensive report saved:")
        print(f"    HTML (open in a browser):  {out}")
        print(f"    JSON (structured data):    {jout}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
