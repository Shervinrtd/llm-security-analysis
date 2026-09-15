"""Supply-chain attack detection - the "is this safe to CLONE" question.

The project objective names four risks: malware insertion, vulnerable
dependencies, exposed secrets, and software supply-chain attacks. The fourth is
listed separately from the third for a reason: a supply-chain attack is not a
CVE in a pinned version, it is code that attacks the person who installs it.

That distinction matters because the two have opposite risk profiles:

    a SQL injection in the repository   hurts the repository's USERS,
                                        and only once it is deployed
    a postinstall script that runs curl hurts YOU, the moment you clone

Everything here is deterministic. A postinstall hook either exists or it does
not; a package name either is or is not one edit away from a popular one. No
model is asked for an opinion, so these findings can carry the verdict without
inheriting an LLM's false-positive rate.

    python src/supply_chain.py --repo <dir>
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import manifest_parse as MP

# ---------------------------------------------------------------------------
# 1. INSTALL HOOKS - code that executes on install, before you run anything
# ---------------------------------------------------------------------------
NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall",
                     "prepare", "prepublish", "preprepare", "postprepare")

# a setup.py that only calls setup() is normal; these make it run code
SETUP_EXEC = re.compile(
    r"\b(cmdclass\s*=|class\s+\w*(?:Install|Develop|EggInfo|Build)\w*\s*\(|"
    r"os\.system|subprocess\.(?:run|call|Popen|check_output)|"
    r"__import__\s*\(|exec\s*\(|eval\s*\()")

GRADLE_EXEC = re.compile(
    r"(doFirst|doLast|exec\s*\{|commandLine|ProcessBuilder|Runtime\.getRuntime)")

# `pull_request_target` on its own is the SUPPORTED way to label a PR or post a
# coverage comment - it is used by django, numpy, black and fastapi for exactly
# that, and flagging it alone produced a false alarm on every one of them.
# The attack ("pwn request") needs the second half: checking out the untrusted
# fork's code and then running it with the repository's secrets in scope.
CI_ON_PR = re.compile(r"pull_request_target|workflow_run")
CI_CHECKS_OUT_PR = re.compile(
    r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)|"
    r"ref:\s*\$\{\{\s*github\.event\.workflow_run\.head_(?:sha|branch)")

# Directories whose contents are exercised, not shipped. A hardcoded IP in a
# test fixture is normal; treating it as exfiltration made 4 of 12 trusted
# projects raise alarms. Findings here are kept visible but can never reach the
# severity that blocks a clone - deleting them outright would hand attackers an
# obvious place to hide a payload.
TEST_PATH = re.compile(
    r"(^|[\\/])(tests?|testing|spec|specs|fixtures?|__tests__|examples?|"
    r"benchmarks?|docs?)([\\/]|$)", re.I)

# Loopback, private and reserved ranges are not exfiltration endpoints - they
# are how software talks to itself in development and tests.
LOCAL_IP = re.compile(
    r"^https?://(?:127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|255\.)")

# ---------------------------------------------------------------------------
# 2. OBFUSCATION / HIDDEN PAYLOAD
# ---------------------------------------------------------------------------
B64_BLOB = re.compile(r"['\"][A-Za-z0-9+/]{120,}={0,2}['\"]")
HEX_BLOB = re.compile(r"['\"](?:\\x[0-9a-fA-F]{2}){40,}['\"]")
CHARCODE = re.compile(r"(?:String\.fromCharCode|chr\s*\()\s*\(?\s*\d+(?:\s*,\s*\d+){15,}")
DYNAMIC_EXEC = re.compile(
    r"\b(eval|exec|execSync|Function|compile)\s*\(|"
    r"child_process\.(?:exec|spawn)|os\.popen|subprocess\.\w+\s*\(")
DECODE_CALL = re.compile(
    r"(b64decode|atob|base64\.decode|Buffer\.from\s*\([^)]*base64|"
    r"codecs\.decode|zlib\.decompress|marshal\.loads|pickle\.loads)")

# ---------------------------------------------------------------------------
# 3. SUSPICIOUS NETWORK ACTIVITY - named explicitly in the objective
# ---------------------------------------------------------------------------
RAW_IP = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?")
SUSPICIOUS_HOST = re.compile(
    r"\b(?:pastebin\.com|paste\.ee|hastebin|ghostbin|transfer\.sh|"
    r"anonfiles|bit\.ly|tinyurl\.com|is\.gd|t\.me|discord(?:app)?\.com/api/webhooks|"
    r"ngrok\.io|trycloudflare\.com|requestbin|webhook\.site|"
    r"burpcollaborator|oastify|interact\.sh)\b", re.I)
# Credential material splits into two very different cases, and conflating them
# is what produces false alarms on ordinary configuration code:
#
#   HIGH_VALUE   files nobody reads by accident. Reading one at all is a signal.
#   BULK_ENV     the WHOLE environment as one object (dict(os.environ),
#                data=process.env). Reading a single named variable
#                - os.environ.get("API_URL") - is normal config and is excluded
#                by the negative lookahead.
# These name a stored secret an attacker steals. "Cookies" as a bare word is NOT
# here: an HTTP client attaching its own cookie jar (socket.io, requests, axios)
# is ordinary, and only reading the BROWSER'S cookie STORE is theft. So the
# browser-store paths are matched by their full path, not by the word alone.
HIGH_VALUE = re.compile(
    r"(SSH_AUTH_SOCK|\.ssh/id_|\.aws/credentials|\.npmrc|\.pypirc|"
    r"\.docker/config\.json|wallet\.dat|"
    r"User Data[\\/].*(Login Data|Cookies)|"          # chrome/edge profile store
    r"cookies\.sqlite|key[34]\.db|logins\.json|"      # firefox credential stores
    r"AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN)")
BULK_ENV = re.compile(r"(?:os\.environ|process\.env)\s*(?![.\[\w])")
NET_SEND = re.compile(
    r"(requests\.(?:post|put|patch)|urllib\.request\.urlopen|http\.client|"
    r"fetch\s*\(|axios\.(?:post|put|patch)|XMLHttpRequest|"
    r"socket\.(?:connect|create_connection)|curl\s|wget\s)")

# ---------------------------------------------------------------------------
# 4. TYPOSQUATTING
# ---------------------------------------------------------------------------
# Popular packages that attackers imitate. Deliberately a small, curated list:
# false "typosquat" alarms on legitimate packages would destroy precision.
POPULAR = {
    "PyPI": ["requests", "urllib3", "numpy", "pandas", "flask", "django", "scipy",
             "pillow", "cryptography", "boto3", "setuptools", "pytest", "click",
             "jinja2", "sqlalchemy", "beautifulsoup4", "selenium", "tensorflow",
             "torch", "scikit-learn", "matplotlib", "colorama", "python-dateutil"],
    "npm": ["react", "lodash", "express", "axios", "chalk", "commander", "debug",
            "moment", "webpack", "babel-core", "typescript", "eslint", "jquery",
            "vue", "angular", "next", "dotenv", "uuid", "yargs", "request",
            "cross-env", "node-fetch", "socket.io", "mongoose"],
    "Maven": ["com.google.guava:guava", "org.apache.commons:commons-lang3",
              "com.fasterxml.jackson.core:jackson-databind", "junit:junit",
              "org.slf4j:slf4j-api", "org.springframework:spring-core"],
}

INSTALL_MANIFESTS = {"package.json", "setup.py", "setup.cfg", "pyproject.toml",
                     "build.gradle", "build.gradle.kts", "pom.xml", "makefile",
                     "Makefile"}


@dataclass
class SupplyFinding:
    kind: str            # install_hook | obfuscation | network | typosquat | ci_risk
    file: str
    detail: str
    severity: str = "HIGH"
    line: int | None = None
    evidence: str = ""
    # every finding here is deterministic, so it is always tier A
    tier: str = "A"


# ------------------------------------------------------------------ helpers
def _lines(text: str) -> list[str]:
    return text.splitlines()


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _edit_distance(a: str, b: str, cap: int = 3) -> int:
    """Damerau-Levenshtein (optimal string alignment).

    Plain Levenshtein scores a swapped pair of letters as 2 edits, which would
    miss 'reqeusts' for 'requests' - and transposition is the single most common
    typosquat. Counting an adjacent swap as one edit catches that family while
    keeping the threshold tight enough to avoid false accusations.
    """
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)     # transposition
        if min(d[i]) > cap:
            return cap + 1
    return d[la][lb]


# ------------------------------------------------------------ 1. install hooks
def check_install_hooks(name: str, text: str, rel: str) -> list[SupplyFinding]:
    out: list[SupplyFinding] = []
    low = name.lower()

    if low == "package.json":
        try:
            obj = json.loads(text)
        except Exception:
            return out
        for hook, cmd in (obj.get("scripts") or {}).items():
            if hook in NPM_INSTALL_HOOKS:
                risky = bool(DYNAMIC_EXEC.search(str(cmd)) or
                             re.search(r"curl|wget|http://|https://|\|\s*(?:sh|bash)", str(cmd)))
                out.append(SupplyFinding(
                    kind="install_hook", file=rel,
                    detail=f"npm '{hook}' script runs on install: {str(cmd)[:120]}",
                    severity="CRITICAL" if risky else "HIGH",
                    evidence=str(cmd)[:200]))

    elif low == "setup.py":
        for m in SETUP_EXEC.finditer(text):
            out.append(SupplyFinding(
                kind="install_hook", file=rel,
                detail=f"setup.py executes code at install time via {m.group(0).strip()}",
                severity="CRITICAL", line=_line_of(text, m.start()),
                evidence=text[max(0, m.start() - 40):m.start() + 90].strip()))
            break                      # one report per file is enough

    elif low in ("build.gradle", "build.gradle.kts"):
        for m in GRADLE_EXEC.finditer(text):
            out.append(SupplyFinding(
                kind="install_hook", file=rel,
                detail=f"Gradle build executes a process via {m.group(0).strip()}",
                severity="HIGH", line=_line_of(text, m.start()),
                evidence=text[max(0, m.start() - 40):m.start() + 90].strip()))
            break

    elif low == "makefile":
        if re.search(r"curl|wget", text) and re.search(r"\|\s*(?:sh|bash)", text):
            out.append(SupplyFinding(
                kind="install_hook", file=rel,
                detail="Makefile pipes a downloaded script straight into a shell",
                severity="CRITICAL"))
    return out


def check_ci(rel: str, text: str) -> list[SupplyFinding]:
    """Workflows that check out AND run untrusted PR code with repository secrets.

    Both halves are required. The trigger alone is a normal, documented pattern;
    the trigger plus an explicit checkout of the fork's head is the pwn-request
    vulnerability.
    """
    trigger = CI_ON_PR.search(text)
    if not trigger:
        return []
    checkout = CI_CHECKS_OUT_PR.search(text)
    if not checkout:
        return []
    return [SupplyFinding(
        kind="ci_risk", file=rel,
        detail=f"workflow uses '{trigger.group(0)}' AND checks out the pull request's "
               f"own code, so an untrusted fork can run commands with this "
               f"repository's secrets",
        severity="HIGH", line=_line_of(text, checkout.start()),
        evidence=checkout.group(0)[:90])]


# ------------------------------------------------------- 2. hidden payloads
def check_obfuscation(text: str, rel: str) -> list[SupplyFinding]:
    """Single signals are weak; it is the COMBINATION that is damning.

    A base64 string is ordinary. A base64 string that gets decoded and handed to
    exec() is a payload. Only the combination is reported, which is what keeps
    the false-positive rate near zero on normal code.
    """
    out: list[SupplyFinding] = []
    has_exec = DYNAMIC_EXEC.search(text)
    has_decode = DECODE_CALL.search(text)

    for rx, label in ((B64_BLOB, "long base64 blob"),
                      (HEX_BLOB, "hex-encoded blob"),
                      (CHARCODE, "character-code array")):
        m = rx.search(text)
        if not m:
            continue
        blob = m.group(0)
        if rx is B64_BLOB and _entropy(blob) < 4.0:
            continue                   # low entropy: a hash or a key, not a payload
        if has_exec or has_decode:
            out.append(SupplyFinding(
                kind="obfuscation", file=rel,
                detail=f"{label} ({len(blob)} chars) in a file that also calls "
                       f"{(has_exec or has_decode).group(0).strip()} - hidden payload pattern",
                severity="CRITICAL", line=_line_of(text, m.start()),
                evidence=blob[:80] + "..."))
        break
    return out


# ------------------------------------------------------- 3. network activity
def check_network(text: str, rel: str) -> list[SupplyFinding]:
    out: list[SupplyFinding] = []
    for m in SUSPICIOUS_HOST.finditer(text):
        out.append(SupplyFinding(
            kind="network", file=rel,
            detail=f"contacts '{m.group(0)}', a host commonly used to stage payloads "
                   f"or receive exfiltrated data",
            severity="CRITICAL", line=_line_of(text, m.start()),
            evidence=m.group(0)))
        break
    for m in RAW_IP.finditer(text):
        if LOCAL_IP.match(m.group(0)):
            continue                       # localhost / private range: not exfiltration
        out.append(SupplyFinding(
            kind="network", file=rel,
            detail=f"hardcoded IP address endpoint {m.group(0)} (bypasses DNS reputation)",
            severity="HIGH", line=_line_of(text, m.start()), evidence=m.group(0)))
        break
    # Exfiltration needs the credential to actually REACH the network call, not
    # merely to appear somewhere in the same file. Requiring co-location inside
    # the call's arguments is what separates `requests.post(url, data=os.environ)`
    # from `os.environ.get("API_URL")` followed by an ordinary request.
    for send in NET_SEND.finditer(text):
        window = text[send.start():send.start() + 300]      # the call's arguments
        hv = HIGH_VALUE.search(window)
        bulk = BULK_ENV.search(window)
        hit = hv or bulk
        if hit:
            what = ("credential file/token " + hv.group(0)) if hv else \
                   "the entire process environment"
            out.append(SupplyFinding(
                kind="network", file=rel,
                detail=f"sends {what} to a network endpoint via "
                       f"{send.group(0).strip()} - data exfiltration pattern",
                severity="CRITICAL", line=_line_of(text, send.start()),
                evidence=window[:90].replace("\n", " ")))
            break

    # reading a high-value credential file at all is worth reporting on its own
    if not any(f.kind == "network" and "exfiltration" in f.detail for f in out):
        m = HIGH_VALUE.search(text)
        if m and NET_SEND.search(text):
            out.append(SupplyFinding(
                kind="network", file=rel,
                detail=f"reads credential material ({m.group(0)}) in a file that also "
                       f"performs network I/O - review how it is used",
                severity="HIGH", line=_line_of(text, m.start()), evidence=m.group(0)))
    return out


# ---------------------------------------------------------- 4. typosquatting
def _is_versioned_sibling(name: str, pop: str) -> bool:
    """`typescript1`, `react-dom2` etc. are legitimate multi-version packages, not
    typos. The difference from the popular name is a trailing digit or a -N/-vN
    suffix, so the edit is an addition at the end rather than a confusable swap."""
    import re as _re
    return bool(_re.fullmatch(_re.escape(pop) + r"[-_]?v?\d+", name))


def check_typosquat(ecosystem: str, deps: list[dict], rel: str,
                    self_names: set[str] | None = None) -> list[SupplyFinding]:
    out: list[SupplyFinding] = []
    popular = POPULAR.get(ecosystem, [])
    self_names = self_names or set()
    for d in deps:
        name = d["package"]
        if name in popular or name in self_names:
            continue                   # it IS the popular package, or the repo itself
        for pop in popular:
            if _is_versioned_sibling(name, pop):
                break                  # e.g. typescript1 - a version pin, not a squat
            dist = _edit_distance(name, pop, cap=2)
            # require a genuine confusable: same length +/-1 and a substitution or
            # transposition, not an added suffix (which is how version pins differ)
            if 0 < dist <= 1 and abs(len(name) - len(pop)) <= 1 and len(pop) >= 4:
                out.append(SupplyFinding(
                    kind="typosquat", file=rel,
                    detail=f"dependency '{d['raw_name']}' is one character away from the "
                           f"popular package '{pop}' - possible typosquat",
                    severity="CRITICAL", evidence=f"{name} vs {pop}"))
                break
    return out


# ------------------------------------------------------------------- driver
SCAN_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".bash", ".ps1",
             ".json", ".yml", ".yaml", ".gradle", ".xml", ".rb", ".pl"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist",
             "build", "vendor", "site-packages"}


def _self_names(root: Path) -> set[str]:
    """Package names this repository publishes as - so it never typosquat-flags
    its own name or its own scoped siblings."""
    names: set[str] = set()
    for pj in list(root.rglob("package.json"))[:50]:
        try:
            obj = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
            if isinstance(obj, dict) and obj.get("name"):
                nm = str(obj["name"]).lower()
                names.add(nm)
                names.add(nm.split("/")[-1])       # de-scope @org/name
        except Exception:
            continue
    return names


def analyse(root: Path, max_files: int = 400, max_bytes: int = 400_000, cancel_event=None) -> dict:
    """Scan a repository for supply-chain attack indicators."""
    findings: list[SupplyFinding] = []
    self_names = _self_names(root)
    n_scanned = 0
    eligible = oversized = unreadable = omitted = 0
    from audit_runtime import check_cancel
    for p in sorted(root.rglob("*")):
        check_cancel(cancel_event)
        if not p.is_file() or any(q in SKIP_DIRS for q in p.relative_to(root).parts):
            continue
        name = p.name
        is_manifest = name in INSTALL_MANIFESTS
        is_ci = ".github" in p.parts and p.suffix.lower() in (".yml", ".yaml")
        if not is_manifest and not is_ci and p.suffix.lower() not in SCAN_EXTS:
            continue
        eligible += 1
        if n_scanned >= max_files:
            omitted += 1
            continue
        try:
            if p.stat().st_size > max_bytes:
                oversized += 1
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unreadable += 1
            continue
        rel = str(p.relative_to(root))
        n_scanned += 1

        found: list[SupplyFinding] = []
        if is_manifest:
            found += check_install_hooks(name, text, rel)
            eco, deps = MP.parse(name, text)
            if deps:
                found += check_typosquat(eco, deps, rel, self_names)
        if is_ci:
            found += check_ci(rel, text)
        found += check_obfuscation(text, rel)
        found += check_network(text, rel)

        # Applied here rather than inside each detector so a new detector cannot
        # forget it and re-introduce test-fixture false alarms.
        if TEST_PATH.search(rel):
            for f in found:
                if f.severity in ("CRITICAL", "HIGH"):
                    f.severity = "LOW"
                    f.detail += " [in a test/example path - not shipped code]"
        findings += found

    dicts = [asdict(f) for f in findings]
    by_kind = dict(Counter(f["kind"] for f in dicts))
    worst = "none"
    for level in ("CRITICAL", "HIGH", "MEDIUM"):
        if any(f["severity"] == level for f in dicts):
            worst = level
            break
    return {"findings": dicts, "n_scanned": n_scanned, "by_kind": by_kind,
            "worst_severity": worst,
            "clone_safe": (not any(f["severity"] in ("CRITICAL", "HIGH") for f in dicts)
                           if n_scanned and not (omitted or oversized or unreadable) else None),
            "status": "complete" if n_scanned and not (omitted or oversized or unreadable) else "partial",
            "eligible_files": eligible, "omitted_by_limit": omitted,
            "oversized": oversized, "unreadable": unreadable,
            "file_limit": max_files, "max_bytes": max_bytes,
            "scope_note": "Pattern checks on supported text files only; dependencies, excluded folders and runtime behaviour are not exhaustively checked."}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    root = Path(args.repo)
    if not root.is_dir():
        sys.exit(f"not a directory: {root}")
    res = analyse(root)
    if args.json:
        print(json.dumps(res, indent=1))
        return
    print(f"\nSUPPLY-CHAIN SCAN — {root}")
    print(f"files inspected: {res['n_scanned']}")
    print(f"clone-safe     : {'YES' if res['clone_safe'] else 'NO'}")
    if not res["findings"]:
        print("\nNo supply-chain attack indicators found.")
        return
    print(f"\n{len(res['findings'])} indicator(s): {res['by_kind']}\n")
    for f in res["findings"]:
        loc = f"{f['file']}" + (f":{f['line']}" if f.get("line") else "")
        print(f"  [{f['severity']:<8}] {f['kind']:<13} {loc}")
        print(f"      {f['detail']}")


if __name__ == "__main__":
    main()
