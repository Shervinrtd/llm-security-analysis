"""Step C - Extract functions from source files with tree-sitter.

Given a file's text and a language, return every top-level callable (function,
method, constructor) with its 1-based line span, name and source text.

"Top-level" means: a function node that is NOT nested inside another function
node. This yields the unit a developer actually reviews - a Java method rather
than its enclosing class, a Python def rather than an inner helper, a JS
function rather than an inline callback.
"""
from __future__ import annotations

import importlib
import sys
from dataclasses import dataclass
from pathlib import Path

from tree_sitter import Language, Parser

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C

_MODULES = {
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "java": "tree_sitter_java",
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
}
_PARSERS: dict[str, Parser] = {}

NAME_NODE_TYPES = {"identifier", "field_identifier", "property_identifier",
                   "qualified_identifier", "type_identifier", "destructor_name",
                   "operator_name"}


def get_parser(lang: str) -> Parser:
    if lang not in _PARSERS:
        mod = importlib.import_module(_MODULES[lang])
        _PARSERS[lang] = Parser(Language(mod.language()))
    return _PARSERS[lang]


@dataclass
class Function:
    name: str
    start_line: int      # 1-based, inclusive
    end_line: int        # 1-based, inclusive
    code: str
    lang: str

    @property
    def loc(self) -> int:
        return self.end_line - self.start_line + 1


def _first_name(node) -> str | None:
    """Depth-first search for the first identifier-ish token in a subtree."""
    if node is None:
        return None
    if node.type in NAME_NODE_TYPES:
        return node.text.decode("utf-8", errors="replace")
    for ch in node.children:
        got = _first_name(ch)
        if got:
            return got
    return None


def _c_style_name(node) -> str | None:
    """C/C++: walk the declarator chain (pointer/parenthesized) to the name."""
    decl = node.child_by_field_name("declarator")
    seen = 0
    while decl is not None and seen < 12:
        seen += 1
        if decl.type == "function_declarator":
            return _first_name(decl.child_by_field_name("declarator")) or _first_name(decl)
        nxt = decl.child_by_field_name("declarator")
        if nxt is None:
            break
        decl = nxt
    return _first_name(decl) if decl is not None else None


def _js_name(node) -> str | None:
    """JS: use the declared name, else the variable/property it is assigned to."""
    direct = node.child_by_field_name("name")
    if direct is not None:
        return direct.text.decode("utf-8", errors="replace")
    parent = node.parent
    if parent is not None:
        if parent.type in ("variable_declarator", "assignment_expression",
                           "pair", "public_field_definition"):
            for field in ("name", "left", "key", "property"):
                n = parent.child_by_field_name(field)
                if n is not None:
                    return n.text.decode("utf-8", errors="replace")
    return None


def function_name(node, lang: str) -> str:
    if lang in ("c", "cpp"):
        name = _c_style_name(node)
    elif lang == "javascript":
        name = _js_name(node)
    else:                       # java, python
        n = node.child_by_field_name("name")
        name = n.text.decode("utf-8", errors="replace") if n is not None else None
    return name or "<anonymous>"


def extract_functions(source: str, lang: str) -> list[Function]:
    """Return every top-level (non-nested) function in `source`."""
    if lang not in _MODULES:
        return []
    parser = get_parser(lang)
    data = source.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(data)
    except Exception:
        return []

    wanted = C.FUNC_NODE_TYPES[lang]
    found: list = []

    def walk(node, inside_func: bool):
        is_func = node.type in wanted
        if is_func and not inside_func:
            found.append(node)
        for ch in node.children:
            walk(ch, inside_func or is_func)

    walk(tree.root_node, False)

    lines = source.splitlines()
    out: list[Function] = []
    for node in found:
        s = node.start_point[0] + 1          # tree-sitter rows are 0-based
        e = node.end_point[0] + 1
        if e < s or s < 1 or e > len(lines):
            continue
        code = "\n".join(lines[s - 1:e])
        out.append(Function(
            name=function_name(node, lang),
            start_line=s, end_line=e, code=code, lang=lang,
        ))
    out.sort(key=lambda f: f.start_line)
    return out


def functions_touching(funcs: list[Function], changed_lines: set[int]) -> list[Function]:
    """Subset of `funcs` whose line span contains at least one changed line."""
    if not changed_lines:
        return []
    return [f for f in funcs
            if any(f.start_line <= ln <= f.end_line for ln in changed_lines)]


def changed_within(func: Function, changed_lines: set[int]) -> list[int]:
    """Changed line numbers, re-based to 1 = first line of the function."""
    return sorted(ln - func.start_line + 1
                  for ln in changed_lines
                  if func.start_line <= ln <= func.end_line)


__all__ = ["Function", "extract_functions", "functions_touching",
           "changed_within", "get_parser", "function_name"]
