"""Score the QUALITY of an LLM's explanation, not just its verdict.

The project objective lists "interpretability of results" as one of four things
the study examines, alongside detection and false positives. It is also the
main thing an LLM offers over a static tool: Semgrep says "CWE-89, line 42";
the LLM says *why*. But an explanation is only worth having if it is TRUE, and a
confident, fluent, wrong explanation is worse than none - it actively misleads a
reviewer into trusting a bad finding.

So this measures whether an explanation is grounded in the code it describes,
using checks that need no human labelling:

    grounded     the code-like things it cites (identifiers, API calls) actually
                 appear in the code. The direct hallucination check.
    specific     it refers to at least one concrete element of THIS code, rather
                 than generic boilerplate ("this function may be vulnerable").
    mechanism    (labelled data only) the mechanism it describes matches the true
                 weakness class - catches "right verdict, wrong reason".
    located      (labelled data only) a line it cites is near the real flaw.

The composite is deliberately conservative: an explanation that invents
identifiers is scored as bad interpretability even if the verdict was correct,
because that is exactly the failure a reviewer needs to be warned about.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# What counts as a CODE reference is deliberately high-precision: only things
# that are unambiguously code, never ordinary prose. Counting an English verb
# like "writes" as a hallucinated identifier would punish good explanations, so
# a plain lower-case word is NOT treated as a code reference - it must be
# backticked, a call site, dotted, underscored, or camelCase.
# models quote code with backticks OR 'single' / "double" quotes - all three
# are code references and must be grounded, so all three are extracted the same way
QUOTED = re.compile(r"`([^`]+)`|'([^']{2,40})'|\"([^\"]{2,40})\"")
CALL_SITE = re.compile(r"\b([a-zA-Z_]\w*)\(")                  # foo( - no space, so
                                                               # prose like "Entity (XXE)"
                                                               # is not read as a call
DOTTED = re.compile(r"\b([a-zA-Z_]\w*\.[a-zA-Z_]\w*)\b")       # os.system
SNAKE = re.compile(r"\b([a-zA-Z]\w*_\w+)\b")                   # buf_len, is_valid
CAMEL = re.compile(r"\b([a-z]+[A-Z]\w+)\b")                    # camelCase
LINE_REF = re.compile(r"\bline\s+(\d+)", re.I)

# words that look like identifiers but are ordinary security English, so their
# absence from the code is not hallucination
STOPWORDS = {
    "the", "this", "that", "code", "function", "method", "input", "output",
    "user", "data", "value", "variable", "string", "vulnerability", "vulnerable",
    "attacker", "attack", "security", "issue", "malicious", "example", "return",
    "without", "which", "could", "would", "should", "because", "sanitize",
    "sanitized", "sanitization", "validate", "validated", "validation", "check",
    "checked", "checking", "properly", "unsafe", "safe", "risk", "buffer",
    "overflow", "injection", "execute", "executed", "execution", "command",
    "request", "response", "server", "client", "system", "memory", "allocation",
    "pointer", "null", "array", "index", "length", "size", "bounds", "content",
    "file", "path", "directory", "call", "calls", "called", "parameter",
    "argument", "object", "class", "field", "session", "token", "password",
    "credential", "network", "socket", "process", "payload", "reason", "field",
}

# minimal mechanism vocabulary per weakness family, for the alignment check.
# Keyed by CWE id; grouped so parent/child share vocabulary.
CWE_MECHANISM = {
    "CWE-89": {"sql", "query", "injection", "statement", "database"},
    "CWE-78": {"command", "shell", "os", "exec", "system", "injection"},
    "CWE-79": {"script", "html", "xss", "escap", "sanitiz", "cross-site", "browser"},
    "CWE-22": {"path", "traversal", "directory", "../", "file", "canonical"},
    "CWE-787": {"bound", "overflow", "write", "buffer", "memory", "index", "out-of"},
    "CWE-125": {"bound", "read", "buffer", "memory", "index", "out-of", "over-read"},
    "CWE-476": {"null", "pointer", "dereference", "nullptr", "none"},
    "CWE-190": {"integer", "overflow", "wrap", "arithmetic", "size", "multipl"},
    "CWE-416": {"free", "use-after", "dangling", "freed", "released", "pointer"},
    "CWE-20": {"validat", "input", "check", "sanitiz", "malformed", "untrusted"},
    "CWE-352": {"csrf", "cross-site", "request", "forgery", "token"},
    "CWE-918": {"ssrf", "server-side", "request", "url", "internal", "fetch"},
    "CWE-94": {"code", "inject", "eval", "exec", "dynamic"},
    "CWE-434": {"upload", "file", "extension", "type", "executable"},
    "CWE-798": {"hardcoded", "credential", "password", "key", "secret", "embedded"},
    "CWE-611": {"xml", "xxe", "entity", "external", "dtd"},
    "CWE-502": {"deserial", "pickle", "unmarshal", "object", "untrusted"},
    "CWE-287": {"authentic", "login", "bypass", "credential", "session"},
    "CWE-269": {"privilege", "permission", "escalat", "access"},
}


def _tokens(reason: str) -> set[str]:
    """High-confidence code references in the explanation, lower-cased.

    A backticked snippet is split into its identifiers (`strcpy(buf, s)` yields
    strcpy, buf, s); everything else must already look like code by its shape.
    """
    toks: set[str] = set()
    for m in QUOTED.finditer(reason):
        quoted = m.group(1) or m.group(2) or m.group(3) or ""
        # a quoted phrase of ordinary words ('the input value') is prose, not code;
        # only treat it as a code reference if it looks like an identifier/snippet
        if re.search(r"[_(].|[a-z][A-Z]|^\W*[a-zA-Z_]\w*\W*$", quoted):
            for ident in re.findall(r"[a-zA-Z_]\w*", quoted):
                toks.add(ident.lower())
    for rx in (CALL_SITE, DOTTED, SNAKE, CAMEL):
        for m in rx.finditer(reason):
            toks.add(m.group(1).lower())
    # backticked or call-site heads keep their leading identifier too
    heads = set()
    for t in list(toks):
        head = t.split(".", 1)[0]
        if head:
            heads.add(head)
    return {t for t in (toks | heads) if len(t) > 2 and t not in STOPWORDS}


def _code_terms(code: str) -> set[str]:
    return {t.lower() for t in re.findall(r"[a-zA-Z_]\w*", code)}


def score_explanation(reason: str, code: str,
                      true_cwe: str | None = None,
                      true_lines: list[int] | None = None) -> dict:
    """Interpretability sub-scores and a composite in [0, 1] for one explanation."""
    reason = (reason or "").strip()
    if not reason:
        return {"grounded": 0.0, "specific": 0.0, "mechanism": None,
                "located": None, "hallucinated_refs": 0, "n_refs": 0,
                "composite": 0.0, "empty": True}

    refs = _tokens(reason)
    code_terms = _code_terms(code)

    # grounded: fraction of cited code-tokens that really occur in the code
    if refs:
        present = {t for t in refs if t in code_terms or
                   any(t in ct or ct in t for ct in code_terms if len(ct) > 3)}
        grounded = len(present) / len(refs)
        hallucinated = len(refs) - len(present)
    else:
        grounded, hallucinated = 0.0, 0        # cited nothing concrete
        present = set()

    # specific: did it anchor to THIS code at all (a real identifier, or a line)?
    specific = 1.0 if (present or LINE_REF.search(reason)) else 0.0

    # mechanism: only meaningful when we know the true class
    mechanism = None
    if true_cwe:
        vocab = CWE_MECHANISM.get(true_cwe)
        if vocab:
            low = reason.lower()
            mechanism = 1.0 if any(v in low for v in vocab) else 0.0

    # located: a cited line near a true vulnerable line
    located = None
    if true_lines:
        cited = [int(m.group(1)) for m in LINE_REF.finditer(reason)]
        if cited:
            located = 1.0 if any(abs(c - t) <= 3 for c in cited
                                 for t in true_lines) else 0.0

    # composite: grounding and specificity always count; mechanism/location add
    # weight only when checkable. Grounding dominates - a hallucinated
    # explanation cannot be rescued by naming the right mechanism.
    parts = [("grounded", grounded, 0.5), ("specific", specific, 0.2)]
    if mechanism is not None:
        parts.append(("mechanism", mechanism, 0.2))
    if located is not None:
        parts.append(("located", located, 0.1))
    wsum = sum(w for _, _, w in parts)
    composite = round(sum(v * w for _, v, w in parts) / wsum, 4)

    return {"grounded": round(grounded, 4), "specific": specific,
            "mechanism": mechanism, "located": located,
            "hallucinated_refs": hallucinated, "n_refs": len(refs),
            "composite": composite, "empty": False}


def aggregate(scores: list[dict]) -> dict:
    """Mean sub-scores over many explanations, ignoring undefined dimensions."""
    scored = [s for s in scores if not s.get("empty")]
    n = len(scored)
    if not n:
        return {"n": 0}

    def mean(key):
        vals = [s[key] for s in scored if s.get(key) is not None]
        return round(sum(vals) / len(vals), 4) if vals else None

    return {
        "n": n,
        "n_empty": sum(1 for s in scores if s.get("empty")),
        "grounded": mean("grounded"),
        "specific": mean("specific"),
        "mechanism": mean("mechanism"),
        "located": mean("located"),
        "composite": mean("composite"),
        "mean_hallucinated_refs": round(
            sum(s["hallucinated_refs"] for s in scored) / n, 3),
        "explanations_with_hallucination": sum(
            1 for s in scored if s["hallucinated_refs"] > 0),
    }


if __name__ == "__main__":       # self-check on hand-built cases
    good_code = "int copy(char *d, const char *s){ char buf[16]; strcpy(buf, s); return 0; }"
    cases = [
        ("grounded+specific+mechanism",
         "The `strcpy` call writes into the fixed 16-byte `buf` without checking "
         "the length of `s`, a classic buffer overflow.", good_code, "CWE-787", None),
        ("hallucinated (invents validateInput)",
         "The function calls `validateInput` which fails to sanitize the request "
         "before the database query.", good_code, "CWE-787", None),
        ("generic boilerplate",
         "This function may be vulnerable to a security issue and should be "
         "reviewed.", good_code, "CWE-787", None),
        ("empty", "", good_code, "CWE-787", None),
    ]
    for label, reason, code, cwe, lines in cases:
        s = score_explanation(reason, code, cwe, lines)
        print(f"{label:<34} composite={s['composite']}  grounded={s['grounded']}  "
              f"specific={s['specific']}  mech={s['mechanism']}  "
              f"halluc={s['hallucinated_refs']}")
