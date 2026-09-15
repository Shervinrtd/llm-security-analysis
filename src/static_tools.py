"""Language-aware static analysis: detect the language, run the right tool.

Tools wired in (all real, all installed):

    Semgrep   p/security-audit  -> JS/TS, Java, C/C++, Python, Go, PHP, Ruby
                                   (returns CWE ids, so results line up with the LLM's)
    Bandit                      -> Python (deeper, Python-specific checks)
    Gitleaks                    -> hardcoded secrets, any language

Findings from every tool are normalised into one shape so they can be compared
against the LLM's findings field-for-field.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import shutil
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
from audit_runtime import check_cancel

GITLEAKS = C.ROOT / "tools" / ("gitleaks.exe" if sys.platform.startswith("win") else "gitleaks")
PY = sys.executable

# file extension -> language family used for tool routing
LANG_TOOLS = {
    "python": ["semgrep", "bandit"],
    "javascript": ["semgrep"],
    "java": ["semgrep"],
    "c": ["semgrep"],
    "cpp": ["semgrep"],
}
SEMGREP_CONFIG = "p/security-audit"

SEV_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
           "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


class ToolError(RuntimeError):
    """Tool execution or output failure, never a clean scan."""


class ScanFindings(list):
    """List-compatible result, also usable by the existing triage caller."""
    def __init__(self, findings=(), *, status="complete", message="", scanned_files=None):
        super().__init__(findings)
        self.status = status
        self.message = message
        self.scanned_files = scanned_files


def _run(cmd, timeout, allowed=(0,)):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=timeout)
    except FileNotFoundError as exc:
        raise ToolError("Executable not installed or not on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError("Tool timed out; coverage is incomplete.") from exc
    except OSError as exc:
        raise ToolError("Tool could not be started.") from exc
    if result.returncode not in allowed:
        raise ToolError(f"Tool exited with code {result.returncode}; scan did not complete.")
    return result


def _results_json(text):
    try:
        data = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise ToolError("Tool returned invalid or empty JSON.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ToolError("Tool returned an unexpected result schema.")
    return data


@dataclass
class StaticFinding:
    tool: str
    file: str
    line: int | None
    rule: str
    cwe: str | None
    severity: str
    message: str
    language: str | None = None

    def key(self) -> tuple:
        """Identity used when comparing tools: same file + same line region."""
        return (self.file.replace("\\", "/"), self.line or 0)


# ------------------------------------------------------------------ detection
def detect_languages(root: Path, max_files: int = 4000) -> dict[str, int]:
    """Count source files per language, so we know which tools to run."""
    counts: Counter = Counter()
    skip = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor"}
    n = 0
    for p in root.rglob("*"):
        if not p.is_file() or any(part in skip for part in p.relative_to(root).parts):
            continue
        lang = C.EXT_TO_LANG.get(p.suffix.lower())
        if lang:
            counts[lang] += 1
            n += 1
            if n >= max_files:
                break
    return dict(counts)


def tools_for(languages: dict[str, int]) -> list[str]:
    """Which static tools apply, given the languages present."""
    tools: list[str] = []
    for lang in languages:
        for t in LANG_TOOLS.get(lang, []):
            if t not in tools:
                tools.append(t)
    tools.append("gitleaks")          # secrets scanning is language-agnostic
    return tools


# --------------------------------------------------------------------- runners
CWE_RE = re.compile(r"CWE-(\d{1,4})")


def _first_cwe(values) -> str | None:
    if not values:
        return None
    if isinstance(values, str):
        values = [values]
    for v in values:
        m = CWE_RE.search(str(v))
        if m:
            return f"CWE-{int(m.group(1))}"
    return None


def _relative_file(path, root):
    """Preserve tool-relative subdirectories instead of reducing to basename."""
    p = Path(path)
    if p.is_absolute():
        try:
            return str(p.resolve().relative_to(root.resolve()))
        except ValueError:
            return str(p)
    # Some tools prefix relative input roots; others return source-relative paths.
    try:
        return str(p.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(p)


def run_semgrep(root: Path, timeout: int = 900) -> list[StaticFinding]:
    exe = shutil.which("semgrep")
    if not exe:
        local = Path(sys.executable).parent / "Scripts" / "semgrep.exe"
        exe = str(local) if local.exists() else "semgrep"
    cmd = [exe, "scan", "--config", SEMGREP_CONFIG, "--no-git-ignore",
           "--json", "--quiet", "--metrics=off", str(root)]
    r = _run(cmd, timeout)
    data = _results_json(r.stdout)
    out = []
    for res in data.get("results", []):
        meta = (res.get("extra") or {}).get("metadata") or {}
        path = res.get("path", "")
        rel = _relative_file(path, root)
        out.append(StaticFinding(
            tool="semgrep", file=rel, line=(res.get("start") or {}).get("line"),
            rule=str(res.get("check_id", "")).split(".")[-1],
            cwe=_first_cwe(meta.get("cwe")),
            severity=SEV_MAP.get(str((res.get("extra") or {}).get("severity", "")).upper(), "MEDIUM"),
            message=str((res.get("extra") or {}).get("message", "")),
            language=C.EXT_TO_LANG.get(Path(rel).suffix.lower()),
        ))
    errors = data.get("errors", [])
    return ScanFindings(out, status="partial" if errors else "complete",
                        message=f"{len(errors)} tool error(s); some checks failed." if errors else "",
                        scanned_files=(data.get("paths") or {}).get("scanned"))


def run_bandit(root: Path, timeout: int = 600) -> list[StaticFinding]:
    cmd = [PY, "-m", "bandit", "-r", str(root), "-f", "json", "-q"]
    r = _run(cmd, timeout, allowed=(0, 1))
    txt = r.stdout or ""
    start = txt.find("{")
    if start < 0:
        raise ToolError("Bandit returned no JSON result.")
    data = _results_json(txt[start:])
    out = []
    for res in data.get("results", []):
        path = res.get("filename", "")
        rel = _relative_file(path, root)
        cwe = res.get("issue_cwe") or {}
        cid = cwe.get("id") if isinstance(cwe, dict) else None
        out.append(StaticFinding(
            tool="bandit", file=rel, line=res.get("line_number"),
            rule=str(res.get("test_id", "")),
            cwe=(f"CWE-{cid}" if cid else None),
            severity=SEV_MAP.get(str(res.get("issue_severity", "")).upper(), "MEDIUM"),
            message=str(res.get("issue_text", "")),
            language="python",
        ))
    errors = data.get("errors", [])
    return ScanFindings(out, status="partial" if errors else "complete",
                        message=f"{len(errors)} file error(s); some checks failed." if errors else "",
                        scanned_files=[p for p in (data.get("metrics") or {}) if p != "_totals"])


def run_gitleaks(root: Path, timeout: int = 600) -> list[StaticFinding]:
    if not GITLEAKS.exists():
        raise ToolError("Gitleaks executable is missing.")
    with tempfile.TemporaryDirectory(prefix="security_gitleaks_") as temp:
        report = Path(temp) / "redacted.json"
        cmd = [str(GITLEAKS), "detect", "--source", str(root), "--no-git", "--redact",
               "--report-format", "json", "--report-path", str(report), "--exit-code", "0"]
        _run(cmd, timeout)
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ToolError("Gitleaks did not produce a valid report.") from exc
    if not isinstance(data, list):
        raise ToolError("Gitleaks returned an unexpected result schema.")
    out = []
    for f in data:
        rel = f.get("File", "")
        rel = _relative_file(rel, root)
        out.append(StaticFinding(
            tool="gitleaks", file=rel, line=f.get("StartLine"),
            rule=str(f.get("RuleID", "")), cwe="CWE-798",
            severity="HIGH",
            message=f"Hardcoded secret detected ({f.get('RuleID','')})",
            language=C.EXT_TO_LANG.get(Path(rel).suffix.lower()),
        ))
    return ScanFindings(out, message="File inventory unavailable; Gitleaks exclusions still apply.")


RUNNERS = {"semgrep": run_semgrep, "bandit": run_bandit, "gitleaks": run_gitleaks}


def analyse(root: Path, progress=None, cancel_event=None) -> dict:
    """Detect languages, run the matching tools, return normalised findings."""
    langs = detect_languages(root)
    tools = tools_for(langs)
    findings: list[StaticFinding] = []
    per_tool: dict[str, int] = {}
    tool_status = {}

    for t in tools:
        check_cancel(cancel_event)
        if progress:
            progress(f"static: running {t} ...")
        try:
            got = RUNNERS[t](root)
            tool_status[t] = {"status": getattr(got, "status", "complete"),
                              "message": getattr(got, "message", ""),
                              "scanned_files": getattr(got, "scanned_files", None)}
        except Exception as exc:
            got = []
            message = str(exc) if isinstance(exc, ToolError) else "Tool output could not be processed."
            tool_status[t] = {"status": "failed", "error": message, "scanned_files": None}
        check_cancel(cancel_event)
        per_tool[t] = len(got)
        findings.extend(got)
        if progress:
            progress(f"{t}: {tool_status[t]['status']} ({len(got)} findings)")

    return {
        "languages": langs,
        "tools_used": tools,
        "per_tool": per_tool,
        "findings": [asdict(f) for f in findings],
        "n_findings": len(findings),
        "tool_status": tool_status,
        "scan_status": ("complete" if all(s["status"] == "complete" for s in tool_status.values())
                        else "failed" if all(s["status"] == "failed" for s in tool_status.values()) else "partial"),
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    a = ap.parse_args()
    res = analyse(Path(a.path), progress=lambda m: print(" ", m))
    print(json.dumps({k: v for k, v in res.items() if k != "findings"}, indent=1))
    for f in res["findings"][:15]:
        print(f"  {f['tool']:9s} {f['file']}:{f['line']} [{f['cwe']}] {f['rule'][:40]}")
