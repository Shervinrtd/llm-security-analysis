"""Prompting strategies for multi-class CWE vulnerability detection.

The core set is locked in the Project Scope Note:

    zero_shot     - direct question, no examples          (baseline in all 7 papers)
    few_shot      - k labelled in-context examples        (Tamberg & Bahsi; Steenhoek)
    cot_8step     - eight-step manual-code-review checklist (best custom prompt, paper 1)
    dataflow      - source -> sink -> sanitizer tracing   (tied-best custom prompt, paper 1)

Stretch strategies (gated on free-tier throughput, since they multiply calls):

    self_consistency - run the base prompt k times, take the majority
    rci              - answer, self-criticise, then revise

Every strategy asks for the SAME strict JSON answer shape, so scoring never has
to guess what the model meant:

    {"vulnerable": true/false, "cwe": "CWE-###" or null, "reason": "..."}
"""
from __future__ import annotations

import json
import random
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import cwe_catalog as K

ANSWER_SPEC = (
    'Answer with ONE JSON object and nothing else:\n'
    '{"vulnerable": <true|false>, "cwe": "<CWE-ID or null>", "reason": "<one or two sentences>"}\n'
    'Set "cwe" to null when "vulnerable" is false. Choose "cwe" from the candidate list.'
)

SYSTEM = (
    "You are a security code reviewer performing defensive analysis. "
    "You identify security weaknesses so they can be fixed. "
    "Be precise: only report a vulnerability you can justify from the code shown."
)


@dataclass
class Prompt:
    system: str
    user: str
    strategy: str
    n_calls: int = 1          # how many model calls this strategy consumes


def _code_block(rec: dict) -> str:
    lang = rec.get("language", "")
    return f"```{lang}\n{rec['code']}\n```"


def _candidates(label_space: dict, max_items: int = 40) -> str:
    block = label_space.get("prompt_block")
    if block:
        return "\n".join(block.splitlines()[:max_items])
    return K.prompt_options([c["cwe"] for c in label_space.get("classes", [])], max_items)


# --------------------------------------------------------------------- core

def zero_shot(rec: dict, label_space: dict) -> Prompt:
    user = (
        f"Analyse this {rec.get('language','')} function for security vulnerabilities.\n\n"
        f"{_code_block(rec)}\n\n"
        f"Candidate weakness types:\n{_candidates(label_space)}\n\n"
        f"{ANSWER_SPEC}"
    )
    return Prompt(SYSTEM, user, "zero_shot")


def few_shot(rec: dict, label_space: dict, examples: list[dict], k: int = 4) -> Prompt:
    shots = []
    for ex in examples[:k]:
        ans = {
            "vulnerable": bool(ex["label"]),
            "cwe": ex.get("cwe_primary") if ex["label"] else None,
            "reason": "Example answer.",
        }
        shots.append(
            f"Example ({ex.get('language','')}):\n```{ex.get('language','')}\n"
            f"{ex['code'][:1200]}\n```\nAnswer: {json.dumps(ans)}"
        )
    user = (
        "Analyse the final function for security vulnerabilities. "
        "The examples show the expected answer format.\n\n"
        + "\n\n".join(shots)
        + f"\n\nNow analyse this {rec.get('language','')} function:\n{_code_block(rec)}\n\n"
        f"Candidate weakness types:\n{_candidates(label_space)}\n\n{ANSWER_SPEC}"
    )
    return Prompt(SYSTEM, user, "few_shot")


def cot_8step(rec: dict, label_space: dict) -> Prompt:
    """Eight-step review checklist - paper 1's best-performing custom prompt."""
    user = (
        f"Review this {rec.get('language','')} function step by step, as a security "
        f"engineer would.\n\n{_code_block(rec)}\n\n"
        "Work through these steps, briefly:\n"
        "1. Summarise what the function does.\n"
        "2. Identify where untrusted input can enter.\n"
        "3. Trace how that data flows through the function.\n"
        "4. Check which protections (bounds checks, NULL checks, sanitisers, "
        "escaping, parameterised queries) are already present.\n"
        "5. Decide whether any risky path is actually reachable.\n"
        "6. Assess error and edge-case handling.\n"
        "7. Check for hardcoded secrets or unsafe defaults.\n"
        "8. Give your verdict.\n\n"
        f"Candidate weakness types:\n{_candidates(label_space)}\n\n"
        f"After your reasoning, end your reply with the JSON verdict.\n{ANSWER_SPEC}"
    )
    return Prompt(SYSTEM, user, "cot_8step")


def dataflow(rec: dict, label_space: dict) -> Prompt:
    """Source -> sink -> sanitiser tracing - paper 1's other top custom prompt."""
    user = (
        f"Perform a data-flow security analysis of this {rec.get('language','')} function.\n\n"
        f"{_code_block(rec)}\n\n"
        "List, briefly:\n"
        "A. SOURCES  - where untrusted or externally controlled data enters.\n"
        "B. SINKS    - where that data is used in a security-sensitive operation "
        "(memory write, query, command, file path, output).\n"
        "C. SANITISERS - any validation, bounds check, escaping or encoding applied "
        "between a source and a sink.\n"
        "D. UNSANITISED PATHS - any source-to-sink path with no adequate sanitiser.\n\n"
        "A function is vulnerable only if at least one unsanitised source-to-sink "
        "path exists and is reachable.\n\n"
        f"Candidate weakness types:\n{_candidates(label_space)}\n\n"
        f"After your analysis, end your reply with the JSON verdict.\n{ANSWER_SPEC}"
    )
    return Prompt(SYSTEM, user, "dataflow")


# ----------------------------------------------------------------- stretch

def self_consistency(rec: dict, label_space: dict, base: str = "cot_8step",
                     k: int = 3) -> Prompt:
    p = build(base, rec, label_space)
    return Prompt(p.system, p.user, f"self_consistency({base},k={k})", n_calls=k)


RCI_CRITIQUE = (
    "Review your previous answer critically. Did you miss an existing check "
    "(bounds, NULL, sanitiser)? Did you assume input is attacker-controlled without "
    "evidence? Did you name the most specific correct CWE? "
    "List concrete problems with your answer."
)
RCI_REVISE = f"Now give your corrected final answer.\n{ANSWER_SPEC}"


def rci(rec: dict, label_space: dict, base: str = "cot_8step") -> Prompt:
    """Recursive criticism & improvement: 3 calls (answer, critique, revise)."""
    p = build(base, rec, label_space)
    return Prompt(p.system, p.user, f"rci({base})", n_calls=3)


# ------------------------------------------------------------------ registry

CORE = ["zero_shot", "few_shot", "cot_8step", "dataflow"]
STRETCH = ["self_consistency", "rci"]


def build(strategy: str, rec: dict, label_space: dict,
          examples: list[dict] | None = None) -> Prompt:
    if strategy == "zero_shot":
        return zero_shot(rec, label_space)
    if strategy == "few_shot":
        return few_shot(rec, label_space, examples or [])
    if strategy == "cot_8step":
        return cot_8step(rec, label_space)
    if strategy == "dataflow":
        return dataflow(rec, label_space)
    if strategy == "self_consistency":
        return self_consistency(rec, label_space)
    if strategy == "rci":
        return rci(rec, label_space)
    raise ValueError(f"unknown strategy: {strategy}")


# ------------------------------------------------------------------ parsing

JSON_RE = re.compile(r"\{[^{}]*\"vulnerable\"[^{}]*\}", re.S)
CWE_RE = re.compile(r"CWE[-_ ]?(\d{1,4})", re.I)

# Real deviations observed in the literature, e.g. paper 4 reports GPT-4-turbo
# emitting  vulnerability: **YES** | vulnerability type: **CWE-89**
# so the fallback must tolerate markdown emphasis and the "vulnerability" noun.
VERDICT_YES_RE = re.compile(r"vulnerab\w*\s*[:=]\s*[*_`\s]*(yes|true)\b", re.I)
VERDICT_NO_RE = re.compile(r"vulnerab\w*\s*[:=]\s*[*_`\s]*(no|false)\b", re.I)
YES_RE = re.compile(r"\b(is|are)\s+vulnerable\b", re.I)
NO_RE = re.compile(r"\b(not vulnerable|no vulnerability|not exploitable)\b", re.I)


def parse_answer(text: str) -> dict:
    """Recover {vulnerable, cwe, reason} from a model reply.

    Models drift from the requested format (papers 4 and 6 both report this), so
    we fall back through: strict JSON -> last JSON-ish object -> regex cues.
    `parse_ok` records which path was used, so format-following can be reported
    rather than silently patched over.
    """
    out = {"vulnerable": None, "cwe": None, "reason": "", "parse_ok": False}
    if not text:
        return out

    # 1. a clean JSON object
    for chunk in reversed(JSON_RE.findall(text)):
        try:
            obj = json.loads(chunk)
            out["vulnerable"] = bool(obj.get("vulnerable"))
            cwe = obj.get("cwe")
            if cwe and str(cwe).lower() not in ("null", "none", ""):
                m = CWE_RE.search(str(cwe))
                out["cwe"] = f"CWE-{int(m.group(1))}" if m else None
            out["reason"] = str(obj.get("reason", ""))[:600]
            out["parse_ok"] = True
            return out
        except Exception:
            continue

    # 2. fenced JSON block
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    for chunk in reversed(fenced):
        try:
            obj = json.loads(chunk)
            out["vulnerable"] = bool(obj.get("vulnerable"))
            m = CWE_RE.search(str(obj.get("cwe") or ""))
            out["cwe"] = f"CWE-{int(m.group(1))}" if m else None
            out["reason"] = str(obj.get("reason", ""))[:600]
            out["parse_ok"] = True
            return out
        except Exception:
            continue

    # 2b. TRUNCATED JSON: "thinking" models sometimes get cut off mid-answer,
    #     leaving a valid start like  {"vulnerable": true, "cwe": "CWE-787", ...
    #     with no closing brace. Salvage the two fields we actually need.
    vt = re.search(r'"vulnerable"\s*:\s*(true|false)', text, re.I)
    if vt:
        out["vulnerable"] = vt.group(1).lower() == "true"
        cm = re.search(r'"cwe"\s*:\s*"?(CWE[-_ ]?\d{1,4})', text, re.I)
        if cm:
            n = re.search(r"\d{1,4}", cm.group(1))
            out["cwe"] = f"CWE-{int(n.group())}" if n else None
        rm = re.search(r'"reason"\s*:\s*"([^"]*)', text)
        out["reason"] = (rm.group(1) if rm else text.strip())[:600]
        out["parse_ok"] = True
        return out

    # 3. loose textual cues. Order matters: an explicit "vulnerability: NO"
    #    verdict must beat an incidental "is vulnerable" earlier in the prose.
    if VERDICT_NO_RE.search(text):
        out["vulnerable"] = False
    elif VERDICT_YES_RE.search(text):
        out["vulnerable"] = True
    elif NO_RE.search(text):
        out["vulnerable"] = False
    elif YES_RE.search(text):
        out["vulnerable"] = True

    if out["vulnerable"]:
        # prefer a CWE stated near a "type"/"cwe" cue, else the first mentioned
        m = re.search(r"(?:type|cwe)\D{0,20}CWE[-_ ]?(\d{1,4})", text, re.I) or CWE_RE.search(text)
        if m:
            out["cwe"] = f"CWE-{int(m.group(1))}"
    out["reason"] = text.strip()[:600]
    return out


def sample_examples(train_recs: list[dict], k: int = 4, seed: int = 0,
                    language: str | None = None) -> list[dict]:
    """Balanced few-shot examples, preferring the same language as the query."""
    pool = [r for r in train_recs if not language or r.get("language") == language]
    if len(pool) < k:
        pool = train_recs
    vuln = [r for r in pool if r["label"] == 1]
    safe = [r for r in pool if r["label"] == 0]
    rng = random.Random(seed)
    out: list[dict] = []
    for i in range(k):
        src = vuln if (i % 2 == 0 and vuln) else (safe or vuln)
        if src:
            out.append(rng.choice(src))
    return out


__all__ = ["Prompt", "build", "parse_answer", "sample_examples", "CORE", "STRETCH",
           "ANSWER_SPEC", "SYSTEM"]
