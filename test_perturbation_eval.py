import hashlib
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).parent/'src'))
from perturbation_v2 import transform
from perturbation_eval import pairs, strict_prediction, summarise, formatting_pairs


class PairedEvaluationTests(unittest.TestCase):
    def fixture(self):
        source = {'sample_id': 'one', 'language': 'python', 'content': 'x = "abcd"', 'is_malicious': False}
        fixture = dict(sample_id='one', content=transform(source['content']), is_malicious=False,
                       source_sha256=hashlib.sha256(source['content'].encode()).hexdigest(), schema_version=2)
        return source, fixture

    def test_pair_validation(self):
        a,b = self.fixture()
        self.assertTrue(pairs([a],[b])[0][2])
        b['content'] = 'x = "different"'
        with self.assertRaises(ValueError): pairs([a],[b])

    def test_identity_and_truth(self):
        a,b = self.fixture()
        with self.assertRaises(ValueError): pairs([a,a],[b])
        b['is_malicious'] = True
        with self.assertRaises(ValueError): pairs([a],[b])

    def test_hash(self):
        a,b = self.fixture(); b['source_sha256'] = 'wrong'
        with self.assertRaises(ValueError): pairs([a],[b])

    def test_strict_boolean(self):
        self.assertIs(strict_prediction('{"malicious": false}'), False)
        self.assertIsNone(strict_prediction('{"malicious": "false"}'))
        self.assertIsNone(strict_prediction('benign'))

    def test_formatting_control_preserves_ast_and_source(self):
        import ast
        a,b = self.fixture()
        original_content=a['content']
        result=formatting_pairs(pairs([a],[b]))
        self.assertEqual(ast.dump(ast.parse(original_content)),ast.dump(ast.parse(result[0][1]['content'])))
        self.assertFalse(result[0][2])
        self.assertEqual(a['content'],original_content)
        self.assertNotEqual(result[0][1]['content'],b['content'])

    def test_failure_not_negative(self):
        def row(truth,a,b):
            return dict(detector='test', truth=truth, changed_ast=True, family='f',
                        original={'prediction':a}, transformed={'prediction':b})
        s = summarise([row(True,True,False),row(False,False,True),row(True,None,False)])['test']
        self.assertEqual(s['failed_pairs'],1)
        self.assertEqual(s['all_complete_pairs']['original']['recall'],1)
        self.assertEqual(s['all_complete_pairs']['transformed']['false_positive_rate'],1)


if __name__ == '__main__': unittest.main()
