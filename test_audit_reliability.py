"""Offline regression tests for user-facing audit correctness.

Uses synthetic text and mocked providers; no API calls or benchmark rewrites.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
import models as M
import repo_analyze as RA
import static_tools as ST
import compare_analysis as CA
import supply_chain as SUP
import strategy_select as SS
import pdf_report as PDF
from audit_runtime import AnalysisError, ScanCancelled, check_boolean_field, checked_items


class CleanProvider:
    kind = "fake"
    def __init__(self):
        self.calls = []

    def generate(self, system, user):
        self.calls.append(user)
        if "real_secrets" in user:
            result = {"real_secrets": []}
        elif '"malicious"' in user:
            result = {"malicious": False, "technique": None}
        else:
            result = {"vulnerable": False, "cwe": None, "reason": "No issue."}
        return M.Reply(json.dumps(result), "fake")


class ReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def scan(self, provider=None, **kwargs):
        with patch.object(RA.VI, "coverage_note", return_value="Test corpus only"):
            return RA.analyse_repo(self.root, provider or CleanProvider(), {}, use_triage=False,
                                   verbose=False, **kwargs)

    def test_zero_files_is_unknown(self):
        self.assertEqual(RA.classify_risk([], 0)[1], "unknown")
        report = self.scan()
        self.assertEqual(report.risk_level, "unknown")
        self.assertEqual(report.clone_safety, "unknown")
        self.assertEqual(report.coverage["status"], "failed")

    def test_budget_is_not_full_coverage(self):
        for name in ("a.py", "b.py", "c.py"):
            self.write(name, "def safe(x):\n    return x\n")
        report = self.scan(max_files=1)
        self.assertEqual(report.n_files, 3)
        self.assertEqual(report.coverage["omitted_by_limit"], 2)
        self.assertEqual(report.risk_level, "unknown")
        self.assertEqual(report.coverage["completed_files"]["vulnerability"], ["a.py"])

    def test_failed_model_is_not_a_negative(self):
        self.write("a.py", "def safe(x):\n    return x\n")
        provider = Mock(kind="fake")
        provider.generate.return_value = M.Reply("", "fake", ok=False, error="SECRET_NOT_TO_LOG")
        report = self.scan(provider)
        self.assertEqual(report.n_analysed, 0)
        self.assertEqual(report.risk_level, "unknown")
        self.assertEqual(len(report.coverage["errors"]), 3)
        self.assertNotIn("SECRET_NOT_TO_LOG", str(report.coverage))

    def test_bad_json_verdict_is_not_safe_or_vulnerable(self):
        self.write("a.py", "def safe(x):\n    return x\n")
        provider = Mock(kind="fake")
        provider.generate.return_value = M.Reply('{"vulnerable":"false"}', "fake")
        report = self.scan(provider)
        self.assertEqual(report.risk_level, "unknown")
        self.assertTrue(report.coverage["errors"])

    def test_truncated_dependency_answer_is_failure(self):
        provider = Mock(kind="fake")
        for text in ('{"vulnerable_dependencies":', '{"vulnerable_dependencies": [null]}'):
            with self.subTest(text=text):
                provider.generate.return_value = M.Reply(text, "fake")
                with self.assertRaises(AnalysisError):
                    RA.analyse_dependency(provider, "requests==1.0", "requirements.txt", "PyPI", "zero_shot")

    def test_invalid_secret_entry_is_failure(self):
        provider = Mock(kind="fake")
        for entry in (None, {}, {"line": "oops"}, {"line": True}):
            with self.subTest(entry=entry):
                provider.generate.return_value = M.Reply(json.dumps({"real_secrets": [entry]}), "fake")
                with self.assertRaises(AnalysisError):
                    RA.analyse_secret(provider, "placeholder", "sample.txt")

    def test_final_boolean_object_is_validated(self):
        self.assertFalse(check_boolean_field('Reasoning. ```json\n{"vulnerable": false}\n```', "vulnerable")["vulnerable"])
        for text in ('{"vulnerable": false', '{"vulnerable": false}\n{"vulnerable": "false"}', '{"reason": "none"}'):
            with self.subTest(text=text), self.assertRaises(AnalysisError):
                check_boolean_field(text, "vulnerable")

    def test_code_braces_before_final_answer_are_allowed(self):
        for text in ('The code if (x) { return y; } needs checking.\n{"vulnerable": false}',
                     'Example {"unfinished":\n```json\n{"vulnerable": false}\n```'):
            with self.subTest(text=text):
                self.assertFalse(check_boolean_field(text, "vulnerable")["vulnerable"])

    def test_fenced_nested_findings_remain_complete(self):
        self.assertEqual(checked_items('```json\n{"real_secrets": [{"line": 5, "reason": "example"}]}\n```',
                                      "real_secrets", "line", int), [5])
        self.assertEqual(checked_items('```json\n{"vulnerable_dependencies": [{"package": "example"}]}\n```',
                                      "vulnerable_dependencies", "package", str), ["example"])

    def test_function_limit_disclosed(self):
        self.write("a.py", "\n".join(f"def f{i}():\n    return {i}\n" for i in range(14)))
        report = self.scan()
        self.assertEqual(report.coverage["functions_checked"], 12)
        self.assertEqual(report.coverage["functions_omitted"], 2)
        self.assertEqual(report.coverage["status"], "partial")
        self.assertNotIn("a.py", report.coverage["completed_files"].get("vulnerability", []))

    def test_top_level_code_not_claimed_checked(self):
        self.write("a.py", "print('hello')\n")
        report = self.scan()
        self.assertEqual(report.risk_level, "unknown")
        self.assertNotIn("vulnerability", report.coverage["completed_files"])

    def test_unverified_malware_does_not_force_critical(self):
        f = {"pillar": "malware", "severity": "CRITICAL", "tier": "C", "novelty": None}
        self.assertNotIn(RA.classify_risk([f], 1)[1], ("high", "critical"))
        self.assertEqual(RA.classify_risk([dict(f, tier="A")], 1)[1], "critical")

    def test_historical_cve_is_not_confirmed(self):
        f = {"pillar": "vulnerability", "severity": "HIGH", "tier": "C", "novelty": "known_location", "cve_id": "CVE-0000-0000"}
        self.assertNotIn(RA.classify_risk([f], 1)[1], ("high", "critical"))

    def test_few_shot_uses_real_training_examples(self):
        provider = CleanProvider()
        example = {"code": "def EXAMPLE_MARKER(): pass", "label": 0, "language": "python", "cwe_primary": None}
        RA.analyse_vulnerability(provider, "def f():\n    return 1\n", "python", "a.py", {}, "few_shot", train_examples=[example])
        self.assertIn("EXAMPLE_MARKER", provider.calls[0])
        with self.assertRaises(AnalysisError):
            RA.analyse_vulnerability(provider, "def f():\n    return 1\n", "python", "a.py", {}, "few_shot")

    def test_secret_values_never_in_findings(self):
        provider = Mock()
        provider.generate.return_value = M.Reply('{"real_secrets":[{"line":1}]}', "fake")
        findings = RA.analyse_secret(provider, 'TOKEN="synthetic_private_value"', "settings.py")
        self.assertNotIn("synthetic_private_value", str(findings))
        self.assertEqual(findings[0].line, 1)

    def test_supply_limit_and_oversize_are_disclosed(self):
        self.write("a.py", "print(1)")
        self.write("b.py", "print(2)")
        result = SUP.analyse(self.root, max_files=1)
        self.assertEqual(result["omitted_by_limit"], 1)
        self.assertIsNone(result["clone_safe"])
        self.assertEqual(RA.clone_verdict([], result)[0], "unknown")

    def test_cancel_prevents_new_model_calls(self):
        self.write("a.py", "def f():\n    return 1\n")
        event = threading.Event()
        event.set()
        provider = CleanProvider()
        with self.assertRaises(ScanCancelled):
            self.scan(provider, cancel_event=event)
        self.assertFalse(provider.calls)

    def test_missing_tool_fails_explicitly(self):
        with patch.object(ST.subprocess, "run", side_effect=FileNotFoundError()):
            with self.assertRaises(ST.ToolError):
                ST.run_semgrep(self.root)

    def test_tool_exit_code_and_schema(self):
        for code, stdout in [(2, '{"results":[]}'), (0, ''), (0, '{}'), (0, '[]')]:
            with self.subTest(code=code, stdout=stdout), patch.object(ST.subprocess, "run", return_value=Mock(returncode=code, stdout=stdout)):
                with self.assertRaises(ST.ToolError):
                    ST.run_semgrep(self.root)

    def test_partial_tool_error_preserves_findings(self):
        output = {"results": [{"path": str(self.root / "a.py"), "start": {"line": 2}, "extra": {"message": "Check", "metadata": {"cwe": ["CWE-89"]}}}], "errors": [{"message": "parse error"}]}
        with patch.object(ST.subprocess, "run", return_value=Mock(returncode=0, stdout=json.dumps(output))):
            result = ST.run_semgrep(self.root)
        self.assertEqual(len(result), 1)
        self.assertEqual(result.status, "partial")

    def test_aggregate_failure_is_not_success(self):
        self.write("a.py", "pass")
        with patch.dict(ST.RUNNERS, {name: Mock(side_effect=ST.ToolError("Unavailable")) for name in ST.RUNNERS}):
            result = ST.analyse(self.root)
        self.assertEqual(result["scan_status"], "failed")
        self.assertEqual(result["n_findings"], 0)

    def test_gitleaks_temp_file_unique_and_redacted(self):
        paths = []
        def run(cmd, *args, **kwargs):
            self.assertIn("--redact", cmd)
            path = Path(cmd[cmd.index("--report-path") + 1])
            paths.append(path)
            path.write_text("[]")
            return Mock(returncode=0)
        with patch.object(ST, "GITLEAKS", self.write("gitleaks.exe", "dummy")), patch.object(ST, "_run", side_effect=run):
            ST.run_gitleaks(self.root)
            ST.run_gitleaks(self.root)
        self.assertNotEqual(paths[0], paths[1])
        self.assertTrue(all(not p.exists() for p in paths))

    def test_comparison_is_compatible_one_to_one(self):
        a = {"file": "a.py", "line": 10, "pillar": "vulnerability", "category": "CWE-89"}
        s = {"file": "a.py", "line": 11, "tool": "semgrep", "cwe": "CWE-89"}
        c = CA.compare({"findings": [a, dict(a, line=12)]}, {"findings": [s]})
        self.assertEqual(c["counts"]["agreed"], 1)
        self.assertEqual(c["counts"]["ai_only"], 1)
        c = CA.compare({"findings": [a]}, {"findings": [dict(s, cwe="CWE-798")]})
        self.assertEqual(c["counts"]["agreed"], 0)

    def test_static_nested_relative_location_preserved(self):
        output = {"results": [{"path": "nested/a.py", "start": {"line": 10}, "extra": {"metadata": {"cwe": ["CWE-89"]}}}]}
        with patch.object(ST, "_run", return_value=Mock(stdout=json.dumps(output))):
            finding = ST.run_semgrep(self.root)[0]
        self.assertEqual(finding.file.replace("\\", "/"), "nested/a.py")
        from dataclasses import asdict
        ai = {"findings": [{"file": "nested/a.py", "line": 10, "pillar": "vulnerability", "category": "CWE-89"}]}
        self.assertEqual(CA.compare(ai, {"findings": [asdict(finding)]})["counts"]["agreed"], 1)

    def test_unscanned_static_finding_is_not_an_ai_miss(self):
        c = CA.compare({"findings": [], "coverage": {"completed_files": {"vulnerability": ["a.py"]}}},
            {"findings": [{"file": "b.py", "line": 1, "tool": "semgrep", "cwe": "CWE-89"}]})
        self.assertIn("not an AI miss", c["static_only_items"][0]["coverage_note"])

    def test_zero_completed_pillar_is_known_missing_coverage(self):
        c = CA.compare({"findings": [], "coverage": {"completed_files": {}}},
            {"findings": [{"file": "b.py", "line": 1, "tool": "semgrep", "cwe": "CWE-89"}]})
        self.assertIn("not an AI miss", c["static_only_items"][0]["coverage_note"])

    def test_proximity_without_classification_is_not_agreement(self):
        c = CA.compare({"findings": [{"file": "a.py", "line": 10, "pillar": "vulnerability", "category": "CWE-89"}]},
            {"findings": [{"file": "a.py", "line": 10, "tool": "semgrep", "cwe": None}]})
        self.assertEqual(c["counts"]["agreed"], 0)

    def test_static_findings_not_counted_as_independent_ai(self):
        c = CA.compare({"findings": [{"file": "a.py", "pillar": "supply_chain", "source": "static"}]}, {"findings": []})
        self.assertEqual(c["counts"]["ai_total"], 0)

    def test_calibration_rejects_failed_strategies(self):
        result = {"results": [{"strategy": "zero_shot", "api_errors": 8, "format_adherence": 0, "n": 8, "f1": 1.0}]}
        with patch.object(SS, "calibrate", return_value=result):
            self.assertIsNone(SS.calibrate_many(["fake"])["best_model"])

    def test_refresh_keeps_owned_process(self):
        with patch.dict(M._OLLAMA_STATE, {"proc": "owned", "up": True}, clear=True), patch.object(M, "_load_env_file"):
            M.refresh()
            self.assertEqual(M._OLLAMA_STATE["proc"], "owned")
            self.assertNotIn("up", M._OLLAMA_STATE)

    def test_all_reports_handle_markup_and_full_lists(self):
        nasty = '<img src=x> & <b>literal</b>'
        findings = [{"file": f"src/module_{i}.py", "line": i + 1, "pillar": "vulnerability", "severity": "MEDIUM", "detail": nasty, "tier": "C"} for i in range(45)]
        report = {"findings": findings, "n_analysed": 0, "risk_level": "clean"}
        paths = [self.root / f"{name}.pdf" for name in ("ai", "static", "clone", "comparison")]
        PDF.build_ai_report(paths[0], nasty, report)
        PDF.build_static_report(paths[1], nasty, {"findings": [dict(f, tool="semgrep", message=nasty) for f in findings], "scan_status": "failed"})
        PDF.build_clone_report(paths[2], nasty, {"findings": [], "n_scanned": 0})
        PDF.build_comparison_report(paths[3], nasty, CA.compare(report, {"findings": []}))
        self.assertTrue(all(p.stat().st_size > 1000 for p in paths))
        self.assertEqual(PDF._p(nasty).getPlainText(), nasty)


if __name__ == "__main__":
    unittest.main(verbosity=2)
