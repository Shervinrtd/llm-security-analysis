"""Repository-level layer - orchestrate the four analysers into one audit.

This is the component the project objective describes: "repository collection,
code preprocessing, prompt-based analysis, and risk classification to produce
comprehensive security reports."

Given a repository (a directory of files), it:

  1. walks the file tree and classifies each file       (preprocess / route)
  2. sends each file to the analyser(s) that apply       (dispatch)
        source code        -> vulnerability + malware
        manifests          -> dependency
        config/env/source  -> secrets
  3. aggregates every finding into a repository risk level  (risk classification)
  4. emits a structured + natural-language security report   (report)

The four analysers are called through one uniform interface so the same
orchestrator works with any of them, and so a repo can be scored with the LLM
analysers, the baseline tools, or both for comparison.

    python src/repo_analyze.py --repo <dir> --model stub
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import models as M
import prompts as PR
import cwe_catalog as K
import secrets_evaluate as SEC
import deps_evaluate as DEP
import malware_evaluate as MAL
import manifest_parse as MP
import vuln_intel as VI
import supply_chain as SUP
from audit_runtime import AnalysisError, ScanCancelled, check_cancel, checked_reply, check_boolean_field, checked_items

# ---------------------------------------------------------------- routing
MANIFEST_FILES = {"requirements.txt": "PyPI", "package.json": "npm", "pom.xml": "Maven",
                  "package-lock.json": "npm", "pipfile": "PyPI", "build.gradle": "Maven"}
SECRET_EXTS = {".env", ".yml", ".yaml", ".properties", ".ini", ".cfg", ".json", ".toml"}
CODE_EXTS = set(C.EXT_TO_LANG)      # .c .cpp .java .py .js ...
INSTALL_HOOK_FILES = {"setup.py", "__init__.py"}

# severity -> numeric weight, for aggregating a repo risk score
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "MODERATE": 4, "LOW": 1, None: 3}


@dataclass
class Finding:
    pillar: str                 # vulnerability | malware | secret | dependency
    file: str
    detail: str
    severity: str = "MEDIUM"
    line: int | None = None
    category: str | None = None   # CWE id, technique, secret type, ...
    confidence: str = "medium"
    # --- identification: name the issue rather than only describing it -------
    cve_id: str | None = None     # CVE-YYYY-NNNN, or a GHSA id when no CVE exists
    cwe_id: str | None = None     # weakness class, from the model or the advisory
    novelty: str | None = None    # known | known_location | novel  (code findings)
    fix: str | None = None        # remediation, e.g. "upgrade to 2.20.0"
    summary: str | None = None    # advisory text / novelty explanation
    source: str = "ai"            # ai | advisory | ai+advisory | static
    # --- evidence tier: how the finding was obtained, which is what decides
    #     whether it may drive a verdict ------------------------------------
    #   A  deterministic fact   (install hook present, version in CVE database)
    #   B  corroborated         (model and a static tool agree)
    #   C  model opinion alone  (advisory only - never drives a verdict)
    tier: str = "C"
    # explanation grounding: does the reason cite code that is actually present?
    # a low value means the model likely hallucinated this finding.
    grounded: float | None = None
    function_hash: str | None = None  # exact analysed body, for benchmark identity


@dataclass
class RepoReport:
    repo: str
    n_files: int
    n_analysed: int
    findings: list = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "unknown"
    by_pillar: dict = field(default_factory=dict)
    elapsed_s: float = 0.0
    by_novelty: dict = field(default_factory=dict)   # known / known_location / novel
    identified: int = 0                              # findings carrying a CVE or GHSA id
    coverage_note: str = ""                          # what "known"/"novel" is based on
    # two independent questions, deliberately not merged into one number
    clone_safety: str = "unknown"                    # safe | caution | dangerous
    clone_reason: str = ""
    by_tier: dict = field(default_factory=dict)      # A / B / C evidence counts
    coverage: dict = field(default_factory=dict)
    supply_scan: dict = field(default_factory=dict)
    demo: bool = False


# ---------------------------------------------------------------- preprocessing
def classify_file(path: Path) -> list[str]:
    """Which pillars should inspect this file. A file can go to several."""
    name = path.name.lower()
    ext = path.suffix.lower()
    routes = []
    if name in MANIFEST_FILES:
        routes.append("dependency")
    if ext in CODE_EXTS:
        routes.append("vulnerability")
        # only script-like languages participate in package-malware analysis
        if C.EXT_TO_LANG.get(ext) in ("python", "javascript"):
            routes.append("malware")
    if name == "package.json":
        routes.append("malware")            # install hooks live here
    if ext in SECRET_EXTS or ext in CODE_EXTS or name.startswith(".env"):
        routes.append("secret")
    return routes


SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
             "dist", "build", "vendor", ".idea", ".devcontainer", ".github",
             "site-packages", "third_party", "docs", "doc", "examples", "example"}
# directories whose contents are real code but rarely what a security review is about
LOW_VALUE_DIRS = {"test", "tests", "testing", "spec", "specs", "fixtures",
                  "benchmark", "benchmarks", "migrations", "locale", "i18n"}


def _priority(p: Path) -> int:
    """Lower sorts first. Scanning is capped, so spend the budget where the
    security signal is - a manifest or a source file, not .editorconfig."""
    name = p.name.lower()
    ext = p.suffix.lower()
    parts = {q.lower() for q in p.parts}

    if name in MANIFEST_FILES:
        return 0                                   # cheap and high-yield
    if name.startswith(".env") or name in ("credentials", "secrets.yml"):
        return 1
    if ext in CODE_EXTS:
        if parts & LOW_VALUE_DIRS:
            return 5                               # test code: real, but lower value
        if name in INSTALL_HOOK_FILES:
            return 2                               # setup.py runs on install
        # minified/bundled files are unreadable to a model and burn the budget
        if ".min." in name or name.endswith((".bundle.js", ".pack.js")):
            return 7
        return 3
    if ext in SECRET_EXTS:
        return 4 if not (parts & LOW_VALUE_DIRS) else 6
    return 9


def triage_hints(root: Path, timeout: int = 300) -> dict[str, int]:
    """Which files a free static scanner considers suspicious, path -> hit count.

    This exists because of what the repository benchmark showed: with a file
    budget of 10 on a 1,426-file project, the vulnerable file ranked 1,246th and
    was never read. File TYPE (source vs config) is not enough to order a queue -
    every source file looks alike from the outside, so ties were broken
    alphabetically, which is effectively random.

    Semgrep reads the entire repository in seconds for free. Its findings are far
    too noisy to report as-is, but they are an excellent PRIORITY signal: spend
    the expensive LLM budget on files something already found suspicious. Failure
    is non-fatal - without hints the walk simply falls back to type ordering.
    """
    try:
        import static_tools as ST
        hits: dict[str, int] = {}
        for f in ST.run_semgrep(root, timeout=timeout):
            key = str(f.file).replace("\\", "/")
            hits[key] = hits.get(key, 0) + 1
        return hits
    except Exception:
        return {}


def walk_repo(root: Path, max_files: int, max_bytes: int,
              hints: dict[str, int] | None = None, coverage=None, cancel_event=None) -> list[Path]:
    """The `max_files` most security-relevant files, best first.

    Ordering is (has a static hit, file type, hit count, path). A file another
    tool already flagged jumps the queue, because the budget is the binding
    constraint on what can be found at all.
    """
    hints = hints or {}
    candidates = []
    for p in root.rglob("*"):
        check_cancel(cancel_event)
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if not classify_file(p) or p.name in ("GROUND_TRUTH.json", "GROUND_TRUTH.yaml"):
            continue
        try:
            if p.stat().st_size > max_bytes:
                if coverage is not None:
                    coverage["oversized"] = coverage.get("oversized", 0) + 1
                continue
        except OSError:
            if coverage is not None:
                coverage["unreadable"] = coverage.get("unreadable", 0) + 1
            continue
        prio = _priority(p)
        if prio >= 9:
            continue                               # not routed to any analyser anyway
        try:
            rel = str(p.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel = str(p).replace("\\", "/")
        n_hits = hints.get(rel, 0)
        # manifests stay first (cheap, high yield); among code files, anything a
        # scanner flagged outranks anything it did not
        candidates.append(((0 if prio <= 1 else 1),      # manifests / .env first
                           (0 if n_hits else 1),          # then flagged files
                           prio, -n_hits, rel.lower(), p))
    candidates.sort(key=lambda t: t[:5])
    if coverage is not None:
        coverage["eligible_files"] = len(candidates)
        coverage["file_limit"] = max_files
        coverage["max_bytes"] = max_bytes
        coverage["omitted_by_limit"] = max(0, len(candidates) - max_files)
    return [t[-1] for t in candidates[:max_files]]


# ---------------------------------------------------------------- analysers
def analyse_vulnerability(provider, code: str, lang: str, rel: str,
                          label_space: dict, strategy: str,
                          repo_slug: str | None = None,
                          novelty_scope: str = "audit", train_examples=None,
                          coverage=None, cancel_event=None) -> list[Finding]:
    """Detect, classify (CWE), and say whether the issue is already published.

    The model supplies the CWE. Whether the finding is a rediscovery of a known
    CVE or has no published match is decided by the advisory corpus, not by the
    model - asking an LLM to name a CVE for arbitrary code invites a fabricated
    identifier, which is worse than reporting none.
    """
    from func_extract import extract_functions
    findings = []
    all_funcs = extract_functions(code, lang)
    funcs = all_funcs[:12]
    if coverage is not None:
        coverage["functions_available"] = coverage.get("functions_available", 0) + len(all_funcs)
        coverage["functions_omitted"] = coverage.get("functions_omitted", 0) + max(0, len(all_funcs) - 12)
    if not funcs:
        raise AnalysisError("No supported functions extracted; top-level code was not checked for vulnerabilities.")
    for fn in funcs:
        check_cancel(cancel_event)
        rec = {"code": fn.code, "language": lang}
        examples = PR.sample_examples(train_examples or [], k=4, seed=42, language=lang) if strategy == "few_shot" else []
        if strategy == "few_shot" and not examples:
            raise AnalysisError("Few-shot training examples are unavailable.")
        p = PR.build(strategy, rec, label_space, examples=examples)
        try:
            rep = checked_reply(provider, p.system, p.user, cancel_event)
            obj = check_boolean_field(rep.text, "vulnerable")
            ans = PR.parse_answer(json.dumps(obj))
            if not ans.get("parse_ok") or type(ans.get("vulnerable")) is not bool:
                raise AnalysisError("Vulnerability answer could not be parsed reliably.")
        except AnalysisError as exc:
            if coverage is None:
                raise
            coverage["errors"].append({"file": rel, "pillar": "vulnerability", "line": fn.start_line, "error": str(exc)})
            continue
        if coverage is not None:
            coverage["functions_checked"] = coverage.get("functions_checked", 0) + 1
        if not ans.get("vulnerable"):
            continue

        cwe = ans.get("cwe")
        # grounding of THIS finding's explanation: if the reason cites identifiers
        # that are not in the function, the finding is probably hallucinated
        import interpretability as ITP
        expl = ITP.score_explanation(ans.get("reason") or "", fn.code)
        nov = VI.classify_novelty(fn.code, repo_slug, fn.name, scope=novelty_scope)
        # an exact CVE match carries a curated CWE; trust it over the model's guess
        cwe_final = nov.get("cwe_primary") if nov["novelty"] == "known" else cwe
        # Severity follows the evidence. A published advisory sets its own; an
        # uncorroborated model opinion is MEDIUM, however confidently worded -
        # rating every guess HIGH makes a well-audited project look critical and
        # buries the findings that are actually confirmed.
        sev = _norm_sev(nov.get("severity")) if nov["novelty"] == "known" else None
        sev = sev or "MEDIUM"

        findings.append(Finding(
            pillar="vulnerability", file=rel,
            detail=f"{fn.name}: {ans.get('reason') or ''}",
            severity=sev if sev in SEV_WEIGHT else "MEDIUM", line=fn.start_line,
            category=cwe_final or cwe, confidence="medium",
            cve_id=nov.get("cve_id"),
            cwe_id=cwe_final or cwe,
            novelty=nov["novelty"],
            summary=nov["note"],
            source="ai+advisory" if nov.get("cve_id") else "ai",
            # an exact match to a CVE-patched function is a verifiable fact;
            # an uncorroborated model opinion is not
            tier="A" if nov["novelty"] == "known" else "C",
            grounded=expl["grounded"] if expl["n_refs"] else None,
            function_hash=VI.norm_hash(fn.code)))
    return findings


def analyse_secret(provider, content: str, rel: str) -> list[Finding]:
    f = {"filename": Path(rel).name, "content": content}
    sysmsg, user = SEC.prompt_context(f)
    rep = checked_reply(provider, sysmsg, user)
    lines = set(checked_items(rep.text, "real_secrets", "line", int))
    src = content.splitlines()
    out = []
    for ln in sorted(lines):
        if not 0 < ln <= len(src):
            raise AnalysisError("Secret scan returned a line outside the file.")
        out.append(Finding(pillar="secret", file=rel,
                           detail="Possible hardcoded credential (value redacted). Verify locally; rotate if live.",
                           severity="HIGH", line=ln, confidence="medium",
                           category="CWE-798", cwe_id="CWE-798"))
    return out


def _norm_sev(sev: str | None) -> str | None:
    """One vocabulary in the report. Advisory feeds say MODERATE, CVSS says
    MEDIUM; showing both words in one column just reads as two different things."""
    if not sev:
        return None
    s = str(sev).upper()
    return "MEDIUM" if s == "MODERATE" else s


def _dep_finding(rel: str, dep: dict, adv: dict, source: str) -> Finding:
    ident = VI.identifier(adv)
    ver = dep.get("version") or "unpinned"
    unsure = adv["status"] == "unpinned"
    return Finding(
        pillar="dependency", file=rel,
        detail=(f"{dep['raw_name']} {ver} - "
                + ("version range not pinned; affected if it resolves into the "
                   "vulnerable range" if unsure else f"affected by {ident}")),
        severity=_norm_sev(adv.get("severity")) or ("MEDIUM" if unsure else "HIGH"),
        category=dep["raw_name"], confidence="low" if unsure else "high",
        cve_id=adv.get("cve_id") or adv.get("advisory_id"),
        cwe_id=adv.get("cwe_primary"),
        fix=VI.remediation(adv),
        summary=(adv.get("summary") or "")[:300] or None,
        source=source,
        # a database says this exact version is affected - a fact, not a guess.
        # an unpinned range cannot be confirmed, so it stays advisory.
        tier="A" if adv["status"] == "affected" else "C")


def analyse_dependency(provider, content: str, rel: str, ecosystem: str,
                       strategy: str, include_advisory: bool = True) -> list[Finding]:
    """Flag vulnerable dependencies and name the advisory behind each one.

    The model decides what to flag (that is what the study measures); the
    advisory database supplies the identifier, severity and upgrade target.
    With `include_advisory`, database-confirmed packages the model missed are
    added too, so the report is correct even where the model is not - set it
    to False to measure the model alone.
    """
    parsed_eco, deps = MP.parse(Path(rel).name, content)
    ecosystem = parsed_eco or ecosystem
    by_norm = {d["package"]: d for d in deps}

    case = {"ecosystem": ecosystem, "filename": Path(rel).name, "content": content,
            "dependencies": deps}
    sysmsg, user = (DEP.prompt_cot if strategy == "cot" else DEP.prompt_zero_shot)(case)
    rep = checked_reply(provider, sysmsg, user)
    flagged = checked_items(rep.text, "vulnerable_dependencies", "package", str)

    out: list[Finding] = []
    seen: set[str] = set()

    # 1. what the model flagged, enriched with the advisory behind it
    for name in flagged:
        norm = MP.normalise(ecosystem, name)
        dep = by_norm.get(norm) or {"package": norm, "raw_name": name, "version": None}
        seen.add(norm)
        adv = VI.lookup_dependency(ecosystem, norm, dep.get("version"))
        if adv["status"] in ("affected", "unpinned"):
            out.append(_dep_finding(rel, dep, adv, "ai+advisory"))
        else:
            reason = ("this version is not listed in any advisory we hold"
                      if adv["status"] == "not_affected"
                      else "we hold no advisory data for this package, so this "
                           "could not be confirmed either way")
            out.append(Finding(
                pillar="dependency", file=rel,
                detail=f"{dep['raw_name']} {dep.get('version') or 'unpinned'} - "
                       f"flagged by the model, unconfirmed: {reason}",
                severity="LOW", category=dep["raw_name"], confidence="low",
                novelty="unconfirmed", source="ai"))

    # 2. what the database confirms but the model did not mention
    if include_advisory:
        for dep in deps:
            if dep["package"] in seen:
                continue
            adv = VI.lookup_dependency(ecosystem, dep["package"], dep.get("version"))
            if adv["status"] == "affected":       # only exact hits, never guesses
                out.append(_dep_finding(rel, dep, adv, "advisory"))
    return out


def analyse_supply_chain(root: Path, result=None) -> list[Finding]:
    """Deterministic supply-chain checks over the whole repository.

    Runs once per repo rather than per file, needs no model, and every finding
    is a verifiable fact - which is why these are the findings allowed to decide
    whether the repository is safe to clone.
    """
    res = result if result is not None else SUP.analyse(root)
    return [Finding(pillar="supply_chain", file=f["file"],
                    detail=f["detail"], severity=f["severity"], line=f.get("line"),
                    category=f["kind"], confidence="high",
                    summary=f.get("evidence") or None,
                    source="static", tier="A")
            for f in res["findings"]]


def analyse_malware(provider, content: str, rel: str, strategy: str) -> list[Finding]:
    s = {"filename": Path(rel).name, "content": content}
    sysmsg, user = (MAL.prompt_triage if strategy == "triage" else MAL.prompt_zero_shot)(s)
    rep = checked_reply(provider, sysmsg, user)
    obj = check_boolean_field(rep.text, "malicious")
    mal, tech, parsed = MAL.parse_reply(json.dumps(obj))
    if not parsed or type(mal) is not bool:
        raise AnalysisError("Malware answer could not be parsed reliably.")
    if mal:
        return [Finding(pillar="malware", file=rel,
                        detail=f"malicious behaviour: {tech or 'unspecified'}",
                        severity="CRITICAL", category=tech, confidence="medium")]
    return []


# ---------------------------------------------------------------- aggregation
# How much a finding counts toward the repository score, by how well it is
# corroborated. An unverified model opinion must not outweigh a published CVE,
# and a pile of them must not add up to "critical" on volume alone.
EVIDENCE_WEIGHT = {"known": 2.0, "known_location": 1.0,
                   "novel": 0.5, "unconfirmed": 0.3, None: 1.0}

# Pillars that decide whether the repository is dangerous to CLONE, as opposed
# to dangerous to DEPLOY. Cloning runs install hooks and build scripts; it does
# not run the project's request handlers, so an injection flaw in the code is a
# deployment risk, not a reason to avoid downloading the repository.
CLONE_RISK_PILLARS = {"supply_chain", "malware"}


def clone_verdict(findings: list[dict], coverage=None) -> tuple[str, str]:
    """Is it safe to download and install this repository on your machine?

    Only tier-A evidence may make this verdict negative. A model opinion, however
    confident, is never sufficient to tell someone a repository is malicious.
    """
    facts = [f for f in findings
             if f.get("tier") == "A" and f["pillar"] in CLONE_RISK_PILLARS]
    crit = [f for f in facts if f["severity"] == "CRITICAL"]
    high = [f for f in facts if f["severity"] == "HIGH"]
    if crit:
        kinds = sorted({f.get("category") or f["pillar"] for f in crit})
        return "dangerous", ("Do not install or run before review. High-risk patterns: "
                             f"{', '.join(kinds)} detected ({len(crit)} finding(s)).")
    if high:
        return "caution", (f"{len(high)} supply-chain concern(s) found. Review them "
                           "before installing; inspect any build or install script.")
    if coverage is None or coverage.get("status") != "complete" or not coverage.get("n_scanned"):
        return "unknown", "Supply-chain coverage is incomplete or unavailable; safety has not been established."
    return "safe", "No high-risk patterns found in the inspected files. Pattern checks do not prove installation or execution is safe."


def deploy_verdict(level: str) -> str:
    return {"critical": "Do not deploy until the confirmed issues are resolved.",
            "high": "Review carefully before deploying.",
            "medium": "Some issues found; review the flagged items before relying on this code.",
            "low": "Review the reported concerns; severity and evidence are listed separately.",
            "clean": "No findings in the completed checks; this is not a safety guarantee.",
            "unknown": "Analysis incomplete."}.get(level, "")


def classify_risk(findings: list[dict], n_analysed: int) -> tuple[float, str]:
    """Weighted risk score -> level, weighted by severity AND by evidence.

    `findings` are dicts (asdict of Finding), matching what is stored on the
    report and written to disk.
    """
    if not findings:
        return 0.0, "clean" if n_analysed > 0 else "unknown"
    score = 0.0
    for f in findings:
        w = SEV_WEIGHT.get(f["severity"], 3)
        if f["pillar"] == "malware":
            w *= 2.0            # malware is categorically worse than a latent bug
        score += w * EVIDENCE_WEIGHT.get(f.get("novelty"), 1.0)
    norm = score / max(n_analysed, 1)

    # "critical" requires corroborated evidence, never volume of guesses
    has_malware = any(f["pillar"] == "malware" and f.get("tier") == "A" for f in findings)
    confirmed = [f for f in findings
                 if f.get("tier") == "A"]
    has_confirmed_critical = any(f["severity"] in ("CRITICAL", "HIGH") for f in confirmed)

    if has_malware or (has_confirmed_critical and norm >= 4):
        level = "critical"
    elif has_confirmed_critical:
        level = "high"
    elif norm >= 2:
        level = "medium"
    else:
        level = "low"
    return round(score, 1), level


def natural_language_report(rep: RepoReport) -> str:
    CLONE_LABEL = {"safe": "SAFE TO CLONE", "caution": "CLONE WITH CAUTION",
                   "dangerous": "DO NOT CLONE", "unknown": "CLONE SAFETY UNKNOWN"}
    L = [f"SECURITY AUDIT REPORT",
         f"Repository   : {rep.repo}",
         "",
         f"1. SAFE TO CLONE?  {CLONE_LABEL.get(rep.clone_safety, '?')}",
         f"   {rep.clone_reason}",
         "",
         f"2. SAFE TO DEPLOY? {rep.risk_level.upper()}   (score {rep.risk_score})",
         f"   {deploy_verdict(rep.risk_level)}",
         "",
         f"Files        : {rep.n_analysed} analysed of {rep.n_files}",
         f"Evidence     : {rep.by_tier.get('A', 0)} verified fact(s), "
         f"{rep.by_tier.get('B', 0)} corroborated, {rep.by_tier.get('C', 0)} model opinion(s)",
         ""]
    if not rep.findings:
        L.append("No security issues detected across the four analysis pillars.")
        return "\n".join(L)

    L.append(f"Summary: {len(rep.findings)} finding(s) across "
             f"{len(rep.by_pillar)} categor(y/ies).")
    if rep.by_novelty:
        n = rep.by_novelty
        L.append(f"Identified: {rep.identified} finding(s) carry a published "
                 f"advisory id; {n.get('known', 0)} match a known CVE exactly, "
                 f"{n.get('known_location', 0)} sit in a function with CVE history, "
                 f"{n.get('novel', 0)} have no published match.")
    L.append("")
    order = ["supply_chain", "malware", "secret", "vulnerability", "dependency"]
    titles = {"supply_chain": "SUPPLY-CHAIN ATTACK INDICATORS", "malware": "MALICIOUS CODE",
              "secret": "EXPOSED SECRETS", "vulnerability": "CODE VULNERABILITIES",
              "dependency": "VULNERABLE DEPENDENCIES"}
    NOVEL_TAG = {"known": "KNOWN CVE", "known_location": "CVE HISTORY",
                 "novel": "NOT PREVIOUSLY REPORTED", "unconfirmed": "UNCONFIRMED"}
    # findings are stored as dicts (asdict); read them as dicts here
    by = defaultdict(list)
    for f in rep.findings:
        by[f["pillar"]].append(f)
    for pillar in order:
        items = by.get(pillar)
        if not items:
            continue
        L.append(f"[{titles[pillar]}]  ({len(items)})")
        for f in items[:8]:
            loc = f":{f['line']}" if f.get("line") else ""
            ident = f" {f['cve_id']}" if f.get("cve_id") else ""
            cwe = f" [{f['cwe_id'] or f['category']}]" if (f.get("cwe_id") or f.get("category")) else ""
            tag = f"  <{NOVEL_TAG[f['novelty']]}>" if f.get("novelty") in NOVEL_TAG else ""
            L.append(f"  - {f['file']}{loc}{cwe}{ident}{tag}")
            L.append(f"      {f['detail']}")
            if f.get("fix"):
                L.append(f"      FIX: {f['fix']}")
        if len(items) > 8:
            L.append(f"    ... and {len(items) - 8} more")
        L.append("")
    if rep.coverage_note:
        L.append("Basis for 'known' vs 'not previously reported':")
        L.append(f"  {rep.coverage_note}")
        L.append("")
    L.append("Recommendation:")
    L.append(f"  Cloning  - {rep.clone_reason}")
    L.append(f"  Deploying - {deploy_verdict(rep.risk_level)}")
    return "\n".join(L)


# ---------------------------------------------------------------- driver
def analyse_repo(root: Path, provider, label_space: dict,
                 vuln_strategy: str = "zero_shot", max_files: int = 60,
                 max_bytes: int = 200_000, verbose: bool = True,
                 repo_slug: str | None = None,
                 novelty_scope: str = "audit",
                 use_triage: bool = True, progress=None, cancel_event=None) -> RepoReport:
    t0 = time.time()
    # free static pass first: it costs seconds and decides which files the
    # expensive model budget is spent on
    check_cancel(cancel_event)
    hints = triage_hints(root) if use_triage else {}
    if verbose and hints:
        print(f"  triage: {len(hints)} file(s) flagged by static analysis, prioritised")
    coverage = {"errors": [], "analysed_files": [], "completed_files": {},
                "functions_checked": 0, "functions_omitted": 0,
                "scope_note": "Supported files only; excluded folders and top-level code are outside the vulnerability function scan."}
    files = walk_repo(root, max_files, max_bytes, hints, coverage, cancel_event)
    coverage["selected_files"] = [str(p.relative_to(root)).replace("\\", "/") for p in files]
    train_examples = []
    if vuln_strategy == "few_shot":
        train_path = C.PROCESSED / "train.jsonl"
        if train_path.exists():
            train_examples = [json.loads(line) for line in train_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    findings: list[Finding] = []
    n_analysed = 0

    for index, p in enumerate(files, 1):
        check_cancel(cancel_event)
        rel = str(p.relative_to(root))
        if progress:
            progress(f"File {index}/{len(files)}: {rel}")
        if p.name in ("GROUND_TRUTH.json", "GROUND_TRUTH.yaml"):
            continue                        # evaluation metadata, not repo code
        routes = classify_file(p)
        if not routes:
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            coverage["errors"].append({"file": rel, "pillar": "read", "error": "File could not be read."})
            continue
        if not content.strip():
            coverage["errors"].append({"file": rel, "pillar": "read", "error": "Empty file; no analysis performed."})
            continue
        lang = C.EXT_TO_LANG.get(p.suffix.lower())
        succeeded = False
        for pillar in routes:
            check_cancel(cancel_event)
            before_errors = len(coverage["errors"])
            before_omitted = coverage["functions_omitted"]
            try:
                if pillar == "vulnerability":
                    got = analyse_vulnerability(provider, content, lang, rel, label_space,
                        vuln_strategy, repo_slug, novelty_scope, train_examples, coverage, cancel_event)
                elif pillar == "secret":
                    got = analyse_secret(provider, content, rel)
                elif pillar == "dependency":
                    got = analyse_dependency(provider, content, rel, MANIFEST_FILES.get(p.name.lower(), "PyPI"), "cot")
                else:
                    got = analyse_malware(provider, content, rel, "triage")
                check_cancel(cancel_event)
                findings += got
                if len(coverage["errors"]) == before_errors and coverage["functions_omitted"] == before_omitted:
                    coverage["completed_files"].setdefault(pillar, []).append(rel)
                    succeeded = True
            except ScanCancelled:
                raise
            except Exception as exc:
                error = str(exc) if isinstance(exc, AnalysisError) else f"{type(exc).__name__}: check failed."
                coverage["errors"].append({"file": rel, "pillar": pillar, "error": error})
        if succeeded:
            n_analysed += 1
            coverage["analysed_files"].append(rel)
        if verbose:
            print(f"  {rel:<40} routes={routes} findings={len(findings)}")

    # deterministic supply-chain pass over the whole repo, independent of the model
    check_cancel(cancel_event)
    supply = SUP.analyse(root, cancel_event=cancel_event)
    findings += analyse_supply_chain(root, supply)

    finding_dicts = [asdict(f) for f in findings]
    score, level = classify_risk(finding_dicts, n_analysed)
    incomplete = (not n_analysed or coverage["errors"] or coverage["omitted_by_limit"]
                  or coverage.get("oversized") or coverage.get("unreadable") or coverage["functions_omitted"])
    if supply.get("status") != "complete":
        coverage["scope_note"] += " Supply-chain checks also have incomplete coverage."
        incomplete = True
    coverage["status"] = "partial" if incomplete and n_analysed else "failed" if incomplete else "complete"
    if incomplete and level == "clean":
        level = "unknown"
    by_pillar = dict(Counter(f["pillar"] for f in finding_dicts))
    by_novelty = dict(Counter(f["novelty"] for f in finding_dicts if f.get("novelty")))
    by_tier = dict(Counter(f.get("tier", "C") for f in finding_dicts))
    identified = sum(1 for f in finding_dicts if f.get("cve_id"))
    clone_state, clone_why = clone_verdict(finding_dicts, supply)
    return RepoReport(repo=repo_slug or str(root), n_files=coverage["eligible_files"], n_analysed=n_analysed,
                      findings=finding_dicts, risk_score=score,
                      risk_level=level, by_pillar=by_pillar,
                      elapsed_s=round(time.time() - t0, 1),
                      by_novelty=by_novelty, identified=identified,
                      coverage_note=VI.coverage_note(novelty_scope),
                      clone_safety=clone_state, clone_reason=clone_why,
                      by_tier=by_tier, coverage=coverage, supply_scan=supply,
                      demo=getattr(provider, "kind", "") == "stub")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--model", default="stub")
    ap.add_argument("--label-space", default=str(C.PROCESSED / "label_space.json"))
    ap.add_argument("--vuln-strategy", default="zero_shot")
    ap.add_argument("--max-files", type=int, default=60)
    ap.add_argument("--repo-slug", default="",
                    help="owner/name on GitHub; lets a finding be matched to that "
                         "project's CVE history")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    root = Path(args.repo)
    if not root.is_dir():
        sys.exit(f"not a directory: {root}")
    provider = M.get(args.model)
    if not provider.is_available():
        sys.exit(f"model '{args.model}' has no API key. Available: {M.available()}")
    ls = json.loads(Path(args.label_space).read_text(encoding="utf-8")) \
        if Path(args.label_space).exists() else {"classes": [], "prompt_block": ""}

    print(f"Analysing repository: {root}  (model={args.model})")
    report = analyse_repo(root, provider, ls, args.vuln_strategy, args.max_files,
                          repo_slug=args.repo_slug or None)

    print("\n" + "=" * 66)
    print(natural_language_report(report))
    print("=" * 66)
    print(f"elapsed: {report.elapsed_s}s")

    out = Path(args.out) if args.out else (C.DATA / "results" / f"repo_report_{root.name}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(asdict(report), indent=1), encoding="utf-8")
    print(f"structured report -> {out}")


if __name__ == "__main__":
    main()
