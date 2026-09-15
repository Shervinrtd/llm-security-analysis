"""Offline tests for experiment identity, statistics and selection provenance."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).parent/"src"))
import stats
import repo_bench_eval as bench
from research_identity import record_uid, prediction_index
from perturbation_v2 import transform
from experiment_audit import wilson, adjusted_holm


class MethodsTests(unittest.TestCase):
    def test_overloaded_functions_have_distinct_identity(self):
        self.assertNotEqual(record_uid({"sample_id":"same","code":"def f(): return 1"}),
                            record_uid({"sample_id":"same","code":"def f(): return 2"}))

    def test_duplicate_historical_identity_rejected(self):
        with self.assertRaises(ValueError):
            prediction_index([{"sample_id":"same"},{"sample_id":"same"}])

    def test_content_identity_retains_both_overloads(self):
        self.assertEqual(len(prediction_index([{"sample_id":"same","record_uid":"a"},{"sample_id":"same","record_uid":"b"}])),2)

    def test_missing_selected_trace_cannot_support_detection(self):
        case={"targets":[{"file_path":"a.py","func_name":"f"}]}
        report=SimpleNamespace(findings=[{"pillar":"vulnerability","file":"a.py"}])
        with self.assertRaisesRegex(ValueError,"not selected"):
            bench.score_case(case,report,[])

    def test_wrong_overload_does_not_receive_localisation_credit(self):
        case={"targets":[{"file_path":"a.py","func_name":"f","func_hash":"target"}],
              "case_id":"c","repo":"r","cve_id":"CVE-test","language":"python","n_targets":1,"cwe_primary":"CWE-89"}
        report=SimpleNamespace(findings=[{"pillar":"vulnerability","file":"a.py","detail":"f: concern","function_hash":"other","cwe_id":"CWE-89"}],clone_safety="unknown",by_pillar={})
        scored=bench.score_case(case,report,["a.py"])
        self.assertTrue(scored["detected"])
        self.assertFalse(scored["localised"])
        self.assertFalse(scored["cwe_strict"])

    def test_holm_values_not_raw_pvalues(self):
        expected={"a":.03,"b":.06,"c":.2}
        self.assertEqual(stats.holm_adjusted({"a":.01,"b":.03,"c":.2}),expected)
        self.assertEqual(adjusted_holm({"a":.01,"b":.03,"c":.2}),expected)

    def test_zero_failures_has_nonzero_uncertainty(self):
        interval=wilson(0,35)
        self.assertEqual(interval["point"],0)
        self.assertGreater(interval["ci_high"],.09)

    def test_paired_lengths_must_agree(self):
        with self.assertRaises(ValueError):
            stats.mcnemar([1],[1,0],[1])

    def test_large_mcnemar_no_underflow_artifact(self):
        result=stats.mcnemar([1]*600+[0]*600,[0]*600+[1]*600,[1]*1200)
        self.assertEqual(result["p_value"],1)

    def test_cluster_test_does_not_treat_one_repo_as_many_replicates(self):
        r=stats.clustered_accuracy_permutation([1]*50,[0]*50,[1]*50,["same"]*50,n_perm=100)
        self.assertEqual(r["p_value"],1)
        self.assertEqual(r["n_clusters"],1)

    def test_literal_perturbation_preserves_docstrings_and_fstrings(self):
        source='"""module documentation"""\ndef f(x):\n    """function documentation"""\n    return "hello-world", f"value={x}"\n'
        import ast
        result=transform(source)
        tree=ast.parse(result)
        self.assertEqual(ast.get_docstring(tree),"module documentation")
        self.assertEqual(ast.get_docstring(tree.body[1]),"function documentation")
        self.assertIn(" + ",result)

    def test_invalid_perturbation_input_rejected(self):
        with self.assertRaises(SyntaxError):
            transform('def broken(')


if __name__ == "__main__":
    unittest.main()
