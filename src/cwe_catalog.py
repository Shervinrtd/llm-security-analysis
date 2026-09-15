"""CWE catalogue: id -> name, abstraction level, and parent/child relations.

Two jobs in this project:

1. **Prompting.** A multi-class prompt must show the model candidate CWE
   *names*, not bare ids ("CWE-131" means nothing without
   "Incorrect Calculation of Buffer Size").

2. **Fair grading.** Tamberg & Bahsi credit a prediction when it names the
   parent or child of the true CWE, because those describe the same weakness at
   a different level of abstraction. That needs the real MITRE hierarchy, which
   `related()` provides. Pillar-level CWEs are excluded from this leniency -
   they are too broad to count as a meaningful match.

Source: MITRE CWE "Research Concepts" view (CWE-1000), cached locally.
"""
from __future__ import annotations

import csv
import io
import json
import re
import sys
import zipfile
from functools import lru_cache
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C

CWE_CSV_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
CATALOG_PATH = C.CACHE / "cwe_catalog.json"

CHILD_OF_RE = re.compile(r"ChildOf:CWE ID:(\d+)")


def _download() -> dict:
    r = requests.get(CWE_CSV_URL, timeout=120, headers={"User-Agent": C.USER_AGENT})
    r.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(r.content))
    txt = z.read(z.namelist()[0]).decode("utf-8", errors="replace")

    catalog: dict[str, dict] = {}
    for row in csv.DictReader(io.StringIO(txt)):
        cid = (row.get("CWE-ID") or "").strip()
        if not cid.isdigit():
            continue
        # A CWE can be listed as ChildOf the same parent in several views,
        # so de-duplicate while preserving order.
        parents = list(dict.fromkeys(
            CHILD_OF_RE.findall(row.get("Related Weaknesses", "") or "")))
        catalog[f"CWE-{cid}"] = {
            "name": (row.get("Name") or "").strip(),
            "abstraction": (row.get("Weakness Abstraction") or "").strip(),
            "description": (row.get("Description") or "").strip()[:400],
            "parents": [f"CWE-{p}" for p in parents],
        }
    # derive children from parents
    for cwe, meta in catalog.items():
        for p in meta["parents"]:
            if p in catalog:
                catalog[p].setdefault("children", []).append(cwe)
    for meta in catalog.values():
        meta["children"] = sorted(set(meta.get("children", [])))
    return catalog


@lru_cache(maxsize=1)
def catalog() -> dict:
    if CATALOG_PATH.exists():
        return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    cat = _download()
    CATALOG_PATH.write_text(json.dumps(cat), encoding="utf-8")
    return cat


def name_of(cwe: str) -> str:
    return catalog().get(cwe, {}).get("name", "")


def label_of(cwe: str) -> str:
    """'CWE-89: Improper Neutralization ... (SQL Injection)' - for prompts."""
    n = name_of(cwe)
    return f"{cwe}: {n}" if n else cwe


def abstraction_of(cwe: str) -> str:
    return catalog().get(cwe, {}).get("abstraction", "")


def is_pillar(cwe: str) -> bool:
    return abstraction_of(cwe) == "Pillar"


def related(cwe: str, include_pillars: bool = False) -> set[str]:
    """The CWE itself plus its immediate parents and children.

    Used for the lenient match rule: predicting a direct parent or child of the
    true CWE is credited. Pillars are excluded by default (too broad to be a
    meaningful answer).
    """
    meta = catalog().get(cwe)
    if not meta:
        return {cwe}
    out = {cwe} | set(meta.get("parents", [])) | set(meta.get("children", []))
    if not include_pillars:
        out = {c for c in out if not is_pillar(c)} or {cwe}
    return out


def matches(predicted: str, truth: str, lenient: bool = True) -> bool:
    """Is `predicted` an acceptable answer for `truth`?"""
    if not predicted or not truth:
        return False
    predicted, truth = predicted.upper().strip(), truth.upper().strip()
    if predicted == truth:
        return True
    return lenient and predicted in related(truth)


def prompt_options(cwes: list[str], max_items: int = 40) -> str:
    """Render a candidate CWE list for a multi-class prompt."""
    seen, lines = set(), []
    for c in cwes:
        if c in seen:
            continue
        seen.add(c)
        lines.append(f"- {label_of(c)}")
        if len(lines) >= max_items:
            break
    return "\n".join(lines)


if __name__ == "__main__":
    cat = catalog()
    print(f"catalogue entries: {len(cat)}")
    for c in ["CWE-79", "CWE-89", "CWE-131", "CWE-787", "CWE-476"]:
        meta = cat.get(c, {})
        print(f"\n{label_of(c)}")
        print(f"  abstraction: {meta.get('abstraction')}")
        print(f"  parents    : {meta.get('parents')}")
        print(f"  children   : {meta.get('children', [])[:5]}")
        print(f"  lenient set: {sorted(related(c))[:6]}")
    print("\nmatch checks:")
    print("  CWE-79 vs CWE-79   ->", matches("CWE-79", "CWE-79"))
    print("  CWE-121 vs CWE-787 ->", matches("CWE-121", "CWE-787"))
    print("  CWE-89 vs CWE-787  ->", matches("CWE-89", "CWE-787"))
