"""Prospective Python string-splitting perturbation, never executed.

Only ordinary string literals change. Docstrings, f-strings and match patterns
are retained. A static round-trip verifies the AST after folding literal string
concatenations. This is a constrained lexical experiment, not broad evasion.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path


class SplitStrings(ast.NodeTransformer):
    def visit_Constant(self, node):
        if type(node.value) is str and len(node.value) >= 4:
            cut = len(node.value)//2
            return ast.copy_location(ast.BinOp(ast.Constant(node.value[:cut]), ast.Add(), ast.Constant(node.value[cut:])), node)
        return node

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Constant) and type(node.value.value) is str:
            return node  # preserves module/class/function docstrings
        return self.generic_visit(node)

    def visit_JoinedStr(self, node):
        return node

    def visit_Match(self, node):
        return node


class FoldStrings(ast.NodeTransformer):
    def visit_BinOp(self, node):
        node = self.generic_visit(node)
        if isinstance(node.op, ast.Add) and isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant):
            if type(node.left.value) is str and type(node.right.value) is str:
                return ast.copy_location(ast.Constant(node.left.value + node.right.value), node)
        return node


def transform(source):
    original = ast.parse(source)
    changed = SplitStrings().visit(copy.deepcopy(original))
    result = ast.unparse(ast.fix_missing_locations(changed)) + "\n"
    rebuilt = ast.parse(result)
    canon = lambda tree: ast.dump(FoldStrings().visit(tree), include_attributes=False)
    if canon(copy.deepcopy(original)) != canon(rebuilt):
        raise ValueError("Literal-folded AST changed")
    return result


def main():
    root = Path(__file__).resolve().parents[1]
    source = root/"data/processed/malware_benchmark.jsonl"
    destination = root/"output/experiment-audit/perturbation-v2.jsonl"
    rows = [json.loads(l) for l in source.open(encoding="utf-8") if l.strip()]
    counts = {"python_validated":0,"unsupported_language":0,"syntax_rejected":0}
    destination.parent.mkdir(parents=True,exist_ok=True)
    with destination.open("w",encoding="utf-8") as fh:
        for row in rows:
            if row.get("language") != "python":
                counts["unsupported_language"] += 1
                continue
            try:
                transformed = transform(row["content"])
            except (SyntaxError,ValueError):
                counts["syntax_rejected"] += 1
                continue
            counts["python_validated"] += 1
            fh.write(json.dumps({"sample_id":row["sample_id"],"source_sha256":hashlib.sha256(row["content"].encode()).hexdigest(),
                 "content":transformed,"is_malicious":row["is_malicious"],"validation":"literal-folded AST equality", "schema_version":2})+"\n")
    (destination.with_suffix(".summary.json")).write_text(json.dumps(counts,indent=2),encoding="utf-8")
    print(counts)


if __name__ == "__main__":
    main()
