"""Compare the AI's findings against the static tools' findings.

Matching is done on file + line proximity (within a small window), because the
two approaches report positions slightly differently: a static rule fires on the
exact offending line, while the LLM often reports the start of the enclosing
function. Requiring an exact line match would understate agreement.

Output buckets:
    agreed        both the AI and a static tool flagged the same place
    ai_only       only the AI flagged it
    static_only   only a static tool flagged it
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

LINE_WINDOW = 12          # lines; tolerates function-start vs exact-line reporting


def _norm(p: str) -> str:
    path = str(p or "").replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _near(a: int | None, b: int | None) -> bool:
    if a is None or b is None:
        return False                     # no location evidence: do not claim agreement
    try:
        return int(a) > 0 and int(b) > 0 and abs(int(a) - int(b)) <= LINE_WINDOW
    except (ValueError, TypeError):
        return False


def _compatible(a, s):
    if a.get("pillar") not in ("vulnerability", "secret"):
        return False
    ac = a.get("cwe_id") or a.get("category")
    sc = s.get("cwe")
    if ac and sc and str(ac).startswith("CWE-"):
        return ac == sc
    return a.get("pillar") == "secret" and s.get("tool") == "gitleaks"


def _detail(f, key):
    if f.get("pillar") == "secret" or f.get("tool") == "gitleaks":
        return "Possible credential; value redacted. Verify locally and rotate if live."
    return str(f.get(key, ""))


def _ai_coverage(ai_report, static_finding):
    pillar = "secret" if static_finding.get("tool") == "gitleaks" else "vulnerability"
    completed = (ai_report.get("coverage") or {}).get("completed_files")
    if completed is None:
        return "AI coverage unknown; not evidence of a missed issue."
    files = completed.get(pillar, [])
    if _norm(static_finding.get("file")) not in {_norm(p) for p in files}:
        return "Not fully checked by the AI in this category; not an AI miss."
    return "AI completed this category for the file but reported no matching finding."


def compare(ai_report: dict, static_result: dict, model: str = "",
            strategy: str = "") -> dict:
    all_ai = ai_report.get("findings", []) or []
    ai = [f for f in all_ai if f.get("source", "ai") in ("ai", "ai+advisory") and f.get("pillar") != "supply_chain"]
    st = static_result.get("findings", []) or []

    agreed, ai_only = [], []
    matched_static: set[int] = set()

    for a in ai:
        af, al = _norm(a.get("file")), a.get("line")
        hit = None
        for i, s in enumerate(st):
            if i not in matched_static and af and _norm(s.get("file")) == af and _near(al, s.get("line")) and _compatible(a, s):
                hit = i
                break
        loc = f"{a.get('file')}" + (f":{al}" if al else "")
        if hit is not None:
            matched_static.add(hit)
            s = st[hit]
            agreed.append({
                "location": loc,
                "ai": f"{a.get('pillar')} / {a.get('category') or '-'}",
                "static": f"{s.get('tool')} / {s.get('cwe') or s.get('rule')}",
                "detail": _detail(a, "detail"),
            })
        else:
            ai_only.append({
                "location": loc,
                "ai": f"{a.get('pillar')} / {a.get('category') or '-'}",
                "static": "not flagged",
                "detail": _detail(a, "detail"),
                "coverage_note": "No matched static finding; tool coverage and issue taxonomy may differ.",
            })

    static_only = []
    for i, s in enumerate(st):
        if i in matched_static:
            continue
        loc = f"{s.get('file')}" + (f":{s.get('line')}" if s.get("line") else "")
        static_only.append({
            "location": loc,
            "ai": "not flagged",
            "static": f"{s.get('tool')} / {s.get('cwe') or s.get('rule')}",
            "detail": _detail(s, "message"),
            "coverage_note": _ai_coverage(ai_report, s),
        })

    # CWE-level agreement among the ones both flagged
    cwe_match = 0
    for item in agreed:
        a_cwe = item["ai"].split("/")[-1].strip()
        s_cwe = item["static"].split("/")[-1].strip()
        if a_cwe.startswith("CWE-") and s_cwe.startswith("CWE-") and a_cwe == s_cwe:
            cwe_match += 1

    total_unique = len(agreed) + len(ai_only) + len(static_only)
    return {
        "model": model,
        "strategy": strategy,
        "tools_used": static_result.get("tools_used", []),
        "languages": static_result.get("languages", {}),
        "scan_status": static_result.get("scan_status", "unknown"),
        "warnings": [f"AI coverage: {(ai_report.get('coverage') or {}).get('status', 'unknown')}. "
                     "Overlap is not an accuracy metric; the methods have different scope.",
                     f"{len(all_ai) - len(ai)} deterministic finding(s) excluded from independent AI counts."],
        "counts": {
            "ai_total": len(ai),
            "static_total": len(st),
            "agreed": len(agreed),
            "ai_only": len(ai_only),
            "static_only": len(static_only),
            "unique_total": total_unique,
            "agreement_rate": round(len(agreed) / total_unique, 3) if total_unique else 0.0,
            "same_cwe_when_agreed": cwe_match,
        },
        "agreed_items": agreed,
        "ai_only_items": ai_only,
        "static_only_items": static_only,
    }


def summary_text(c: dict) -> str:
    n = c["counts"]
    return (
        f"AI reported {n['ai_total']} finding(s); static tools reported {n['static_total']}.\n"
        f"Matched {n['agreed']} finding pair(s)  |  unmatched AI: {n['ai_only']}  "
        f"|  unmatched static: {n['static_only']}\n"
        f"Finding overlap: {n['agreement_rate']:.0%}. This is not an accuracy score; check coverage."
    )
