"""Static-only validity checks and prospective split plan; never executes samples."""
import ast
import hashlib
import itertools
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from experiment_audit import ROOT, read_rows
from research_identity import record_uid
from make_splits import split_groups
import obfuscate


TEST_PATH = re.compile(r"(^|/)(tests?|testing|fixtures?|examples?|benchmarks?)(/|$)|(^|/)test_[^/]+|[^/]+_test\.[^/]+$", re.I)
TOKENS = re.compile(r"[A-Za-z_$][\w$]*|\d+(?:\.\d+)?|[^\s]", re.UNICODE)
KEYWORDS = set("if else for while return def class import from try except catch throw new public private static void int char bool null None true false const let var function async await switch case break continue in is not and or with as sizeof struct enum include".split())


def shingles(code):
    # Deliberately heuristic: identifier/literal normalisation can over-group code.
    tokens = TOKENS.findall(code)
    normal = [t if t in KEYWORDS or not t[0].isalnum() and t[0] not in "_$" else "ID" if not t[0].isdigit() else "NUM" for t in tokens]
    return {hashlib.blake2b(" ".join(normal[i:i+5]).encode(), digest_size=8).digest() for i in range(max(0,len(normal)-4))}


def syntax_ok(text):
    try:
        ast.parse(text)
        return True
    except (SyntaxError, ValueError, MemoryError):
        return False


def main():
    processed = ROOT/"data"/"processed"
    outdir = ROOT/"output"/"experiment-audit"
    outdir.mkdir(parents=True,exist_ok=True)
    splits = {s: read_rows(processed/f"{s}.jsonl") for s in ("train","val","test")}
    rows = [r for v in splits.values() for r in v]
    # Connected components join BOTH repo and CVE, plus exact function hashes.
    parent = list(range(len(rows)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    seen = {}
    for i,r in enumerate(rows):
        for key in ("repo","cve_id","func_hash","pair_id"):
            if not r.get(key):
                continue
            value = (key,r[key])
            if value in seen:
                parent[find(i)] = find(seen[value])
            else:
                seen[value] = i
    grouped = [dict(r, repo=str(find(i))) for i,r in enumerate(rows)]
    assignment = split_groups(grouped,"repo",.2,.1,42,stratify_language=True)
    planned = defaultdict(list)
    with (outdir/"prospective_assignments.jsonl").open("w",encoding="utf-8") as fh:
        for i,r in enumerate(rows):
            split = assignment[str(find(i))]
            item = {"sample_id":r["sample_id"],"record_uid":record_uid(r),"split":split,
                    "component":find(i),"candidate_test_path": bool(TEST_PATH.search(r["file_path"].replace("\\","/")))}
            fh.write(json.dumps(item)+"\n")
            planned[split].append(r)
    overlaps = {}
    for a,b in itertools.combinations(planned,2):
        overlaps[f"{a}/{b}"] = {key:len({r[key] for r in planned[a] if r.get(key)} & {r[key] for r in planned[b] if r.get(key)}) for key in ("repo","cve_id","func_hash","pair_id")}
    if any(n for d in overlaps.values() for n in d.values()):
        raise AssertionError("Prospective grouping leaked a protected identity")
    # Limited fuzzy screen: all test functions, candidate retrieval by rare shingles.
    train = splits["train"] + splits["val"]
    train_sets = [shingles(r["code"]) for r in train]
    inverted = defaultdict(list)
    for i,s in enumerate(train_sets):
        if len(s) >= 20:
            for sh in s:
                inverted[sh].append(i)
    hits = []
    n_eligible = 0
    for r in splits["test"]:
        s = shingles(r["code"])
        if len(s) < 20:
            continue
        n_eligible += 1
        rare = sorted((sh for sh in s if sh in inverted), key=lambda sh:(len(inverted[sh]),sh))[:8]
        candidates = Counter(i for sh in rare for i in inverted[sh])
        for i,_ in candidates.most_common(100):
            other = train_sets[i]
            if min(len(s),len(other))/max(len(s),len(other)) < .85:
                continue
            sim = len(s & other)/len(s | other)
            if sim >= .85:
                hits.append({"test_uid":record_uid(r),"development_uid":record_uid(train[i]),
                             "test_repo":r["repo"],"development_repo":train[i]["repo"],"jaccard":sim})
                break
    # Reproduce textual transformations, parse Python only; no eval/exec/import of samples.
    malware = read_rows(processed/"malware_benchmark.jsonl")
    mal = [r for r in malware if r["is_malicious"]][:80]
    benign = [r for r in malware if not r["is_malicious"]][:25]
    syntax = {}
    for name,items in (("malicious_80",mal),("benign_25",benign)):
        c = Counter()
        for i,r in enumerate(items,1):
            if r.get("language") != "python":
                c["non_python_not_parsed"] += 1
                continue
            original = syntax_ok(r["content"])
            transformed = syntax_ok(obfuscate.obfuscate(r["content"],level=3,seed=i))
            c["python_items"] += 1
            c["original_parseable"] += original
            c["transformed_parseable"] += transformed
            c["parseable_original_became_invalid"] += original and not transformed
        syntax[name] = dict(c)
    result = {"prospective_plan": {"n_records":len(rows),"n_components":len({find(i) for i in range(len(rows))}),
               "sizes":{s:len(v) for s,v in planned.items()},"overlaps":overlaps,
               "candidate_test_path_records":sum(bool(TEST_PATH.search(r["file_path"].replace("\\","/"))) for r in rows),
               "warning":"Assignments only, not new evaluation. No historical labels or splits replaced. Test-path flags require review; do not imply labels are false. Prior exposure persists after re-splitting."},
              "fuzzy_screen": {"n_test_eligible":n_eligible,"n_test_with_candidate":len(hits),"threshold":.85,
                  "method":"Identifier-normalised token 5-shingle Jaccard; eight rare-shingle candidate retrieval, top 100 candidates per test item; >=20 distinct shingles.",
                  "warning":"Heuristic candidates, not confirmed semantic duplicates. Can over-group unrelated code and miss duplicates; requires manual adjudication.","candidates":hits},
              "syntax_only_perturbation_audit":syntax,
              "syntax_warning":"AST parsing only, no samples executed. Passing syntax does not establish semantic equivalence; historical transform/version provenance is incomplete."}
    (outdir/"validity_checks.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps({**result,"fuzzy_screen":{k:v for k,v in result["fuzzy_screen"].items() if k!="candidates"}},indent=2))


if __name__ == "__main__":
    main()
