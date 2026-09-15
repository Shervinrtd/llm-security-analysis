"""Generate clearly labelled, synthetic report examples. No scanners or API calls."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
import pdf_report as PDF
import compare_analysis as CA


def main():
    out = Path(__file__).resolve().parent / "output" / "report-previews"
    out.mkdir(parents=True, exist_ok=True)
    repo = "SYNTHETIC EXAMPLE - review-demo"
    findings = [
        {"file": "src/api/search.py", "line": 42, "pillar": "vulnerability", "severity": "MEDIUM", "tier": "C",
         "category": "CWE-89", "source": "ai", "novelty": "novel",
         "detail": 'search: request text is concatenated into a database query. Confirm whether the database driver parameterizes the value before execution. Literal example: <query user="input"> & other text.',
         "fix": "Use bound query parameters and add a regression test for untrusted input."},
        {"file": "config/settings.py", "line": 18, "pillar": "secret", "severity": "HIGH", "tier": "C",
         "category": "CWE-798", "source": "ai", "detail": "Possible hardcoded credential (redacted)."},
        {"file": "requirements.txt", "line": None, "pillar": "dependency", "severity": "HIGH", "tier": "A",
         "source": "advisory", "category": "example-package", "detail": "Synthetic dependency finding for layout demonstration; no real advisory is asserted.",
         "fix": "Verify the resolved version against the advisory and choose a supported patched release."},
    ]
    coverage = {"status": "partial", "eligible_files": 28, "omitted_by_limit": 22, "oversized": 1,
        "file_limit": 6, "functions_checked": 11, "functions_omitted": 0,
        "errors": [{"file": "src/api/upload.py", "pillar": "vulnerability", "error": "Model request failed; check provider availability or quota."}],
        "completed_files": {"vulnerability": ["src/api/search.py"], "secret": ["config/settings.py"]},
        "scope_note": "Sampled supported files only. Excluded folders, oversized files and top-level vulnerability code are outside this scan."}
    supply = {"status": "complete", "n_scanned": 28, "eligible_files": 28, "omitted_by_limit": 0,
        "scope_note": "Supported text files only. Pattern matches require review of intent and execution context.",
        "findings": [{"file": "package.json", "kind": "install_hook", "severity": "HIGH", "detail": "An install hook invokes a build command. This is a review lead and is not proof of malicious behaviour."}]}
    report = {"n_analysed": 5, "n_files": 28, "risk_level": "high", "coverage": coverage, "supply_scan": supply,
        "clone_safety": "caution", "clone_reason": "Inspect the install hook before installing or running this repository.", "findings": findings}
    calibration = {"n_samples": 8, "results": [
        {"strategy": "few_shot", "f1": .75, "balanced_accuracy": .75, "mcc": .50, "format_adherence": 1.0},
        {"strategy": "zero_shot", "f1": .667, "balanced_accuracy": .625, "mcc": .258, "format_adherence": 1.0}]}
    static = {"scan_status": "partial", "tools_used": ["semgrep", "bandit", "gitleaks"], "languages": {"python": 19, "javascript": 3},
        "per_tool": {"semgrep": 1, "bandit": 0, "gitleaks": 0},
        "tool_status": {"semgrep": {"status": "complete", "scanned_files": ["src/api/search.py"]},
                        "bandit": {"status": "failed", "error": "Tool timed out; coverage is incomplete."},
                        "gitleaks": {"status": "complete", "message": "File inventory unavailable; exclusions apply."}},
        "findings": [{"file": "src/api/search.py", "line": 43, "tool": "semgrep", "cwe": "CWE-89", "severity": "HIGH",
                      "rule": "parameterized-query", "message": "Possible SQL injection. Verify parameter binding at the database boundary."},
                     {"file": "src/legacy/runner.py", "line": 9, "tool": "semgrep", "cwe": "CWE-78", "severity": "HIGH",
                      "rule": "shell-input", "message": "Command string includes external input. Review quoting and shell use."}]}
    static["per_tool"]["semgrep"] = 2
    PDF.build_ai_report(out / "ai-review.pdf", repo, report, calibration, "example-model", "few_shot")
    PDF.build_static_report(out / "static-review.pdf", repo, static)
    PDF.build_clone_report(out / "supply-chain-review.pdf", repo, supply)
    PDF.build_comparison_report(out / "comparison-review.pdf", repo, CA.compare(report, static, "example-model", "few_shot"))
    print(f"Created four synthetic examples in {out}")


if __name__ == "__main__":
    main()
