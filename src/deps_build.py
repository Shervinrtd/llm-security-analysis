"""Pillar 4, step 2 - generate dependency-manifest test cases with ground truth.

Each test case is a realistic project manifest (requirements.txt / package.json /
pom.xml) whose dependency list mixes:

    VULNERABLE  package pinned to a version an advisory says is affected
    PATCHED     the SAME kind of package pinned to its fixed version

Including patched pins is deliberate. A benchmark made only of vulnerable pins
can be beaten by a system that flags any package name it recognises from an
advisory feed. Requiring it to separate `lodash==4.17.11` (vulnerable) from
`lodash==4.17.21` (patched) tests whether it reasons about the *version*.

    python src/deps_build.py --n 200 --ecosystems PyPI,npm,Maven
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import cwe_catalog as K


# ------------------------------------------------------------ manifest writers
def write_requirements(deps: list[dict]) -> str:
    lines = ["# Project dependencies", ""]
    lines += [f"{d['package']}=={d['version']}" for d in deps]
    return "\n".join(lines) + "\n"


def write_package_json(deps: list[dict], name: str) -> str:
    obj = {
        "name": name,
        "version": "1.0.0",
        "description": "Sample application",
        "main": "index.js",
        "dependencies": {d["package"]: d["version"] for d in deps},
    }
    return json.dumps(obj, indent=2) + "\n"


def write_pom(deps: list[dict], name: str) -> str:
    body = []
    for d in deps:
        pkg = d["package"]
        gid, _, aid = pkg.partition(":")
        if not aid:
            gid, aid = "com.example", pkg
        body.append("    <dependency>\n"
                    f"      <groupId>{gid}</groupId>\n"
                    f"      <artifactId>{aid}</artifactId>\n"
                    f"      <version>{d['version']}</version>\n"
                    "    </dependency>")
    return ("<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            f"  <artifactId>{name}</artifactId>\n"
            "  <version>1.0.0</version>\n"
            "  <dependencies>\n" + "\n".join(body) + "\n  </dependencies>\n</project>\n")


WRITERS = {
    "PyPI": ("requirements.txt", lambda d, n: write_requirements(d)),
    "npm": ("package.json", write_package_json),
    "Maven": ("pom.xml", write_pom),
}


# ------------------------------------------------------------------- building
def all_vulnerable_versions(adv: list[dict]) -> dict[tuple, set]:
    """Every version ever marked affected, per (ecosystem, package).

    Needed because a package usually has SEVERAL advisories. A version that
    fixes advisory A may still be affected by advisory B, so "the fix version
    of this advisory" is NOT the same as "a safe version". Labelling those as
    patched put 14% mislabelled negatives into the first build of this
    benchmark - precisely the label-noise problem we criticise in other
    datasets, so it is checked explicitly here.
    """
    m: dict[tuple, set] = defaultdict(set)
    for r in adv:
        for v in r.get("vulnerable_versions") or []:
            m[(r["ecosystem"], r["package"])].add(v)
    return m


def safe_versions(rec: dict, everything: dict[tuple, set]) -> list[str]:
    """Fix versions that are not affected by ANY advisory for this package."""
    bad = everything.get((rec["ecosystem"], rec["package"]), set())
    return [v for v in (rec.get("fixed_versions") or []) if v not in bad]


def build_manifests(adv: list[dict], n_cases: int, ecosystems: list[str],
                    min_deps: int, max_deps: int, vuln_ratio: float,
                    seed: int) -> list[dict]:
    rng = random.Random(seed)
    everything = all_vulnerable_versions(adv)

    by_eco: dict[str, list[dict]] = defaultdict(list)
    for r in adv:
        if r["ecosystem"] not in ecosystems:
            continue
        if not r.get("vulnerable_versions"):
            continue
        clean = safe_versions(r, everything)
        if not clean:                     # no provably-safe version -> unusable
            continue
        r = dict(r, safe_versions=clean)
        by_eco[r["ecosystem"]].append(r)

    # one advisory per package, so a manifest never lists the same package twice
    for eco in by_eco:
        best: dict[str, dict] = {}
        for r in by_eco[eco]:
            cur = best.get(r["package"])
            if cur is None or (r.get("cwe_primary") and not cur.get("cwe_primary")):
                best[r["package"]] = r
        by_eco[eco] = list(best.values())

    cases: list[dict] = []
    per_eco = max(1, n_cases // max(len(ecosystems), 1))

    for eco in ecosystems:
        pool = by_eco.get(eco, [])
        if len(pool) < max_deps + 5:
            print(f"  !! {eco}: only {len(pool)} usable packages, skipping")
            continue
        fname, writer = WRITERS[eco]

        for i in range(per_eco):
            k = rng.randint(min_deps, max_deps)
            picked = rng.sample(pool, k)
            n_vuln = max(1, round(k * vuln_ratio))

            deps, truth = [], []
            for j, rec in enumerate(picked):
                is_vuln = j < n_vuln
                version = (rng.choice(rec["vulnerable_versions"]) if is_vuln
                           else rng.choice(rec["safe_versions"]))
                deps.append({"package": rec["package"], "version": version})
                truth.append({
                    "package": rec["package"],
                    "version": version,
                    "vulnerable": is_vuln,
                    "advisory_id": rec["advisory_id"] if is_vuln else None,
                    "cve_id": rec["cve_id"] if is_vuln else None,
                    "cwe_primary": rec["cwe_primary"] if is_vuln else None,
                    "cwe_name": K.name_of(rec["cwe_primary"]) if (is_vuln and rec["cwe_primary"]) else None,
                    "severity": rec["severity"] if is_vuln else None,
                    "summary": rec["summary"] if is_vuln else None,
                })
            order = list(range(len(deps)))
            rng.shuffle(order)                       # don't leak position
            deps = [deps[o] for o in order]
            truth = [truth[o] for o in order]

            proj = f"sample-app-{eco.lower()}-{i+1}"
            content = writer(deps, proj)
            cases.append({
                "manifest_id": hashlib.md5(f"{eco}|{i}|{seed}".encode()).hexdigest()[:16],
                "ecosystem": eco,
                "language": {"PyPI": "python", "npm": "javascript", "Maven": "java"}[eco],
                "filename": fname,
                "project_name": proj,
                "content": content,
                "n_dependencies": len(deps),
                "n_vulnerable": sum(1 for t in truth if t["vulnerable"]),
                "dependencies": truth,
            })
    return cases


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--advisories", default=str(C.INTERIM / "dep_advisories.json"))
    ap.add_argument("--out", default=str(C.PROCESSED / "deps_benchmark.jsonl"))
    ap.add_argument("--n", type=int, default=300, help="total manifests")
    ap.add_argument("--ecosystems", default="PyPI,npm,Maven")
    ap.add_argument("--min-deps", type=int, default=8)
    ap.add_argument("--max-deps", type=int, default=20)
    ap.add_argument("--vuln-ratio", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    adv = json.loads(Path(args.advisories).read_text(encoding="utf-8"))
    ecos = [e.strip() for e in args.ecosystems.split(",") if e.strip()]
    print(f"Generating {args.n} manifests across {ecos}")

    cases = build_manifests(adv, args.n, ecos, args.min_deps, args.max_deps,
                            args.vuln_ratio, args.seed)

    out = Path(args.out)
    with out.open("w", encoding="utf-8") as fh:
        for c in cases:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")

    total_deps = sum(c["n_dependencies"] for c in cases)
    total_vuln = sum(c["n_vulnerable"] for c in cases)
    cwes = Counter(d["cwe_primary"] for c in cases for d in c["dependencies"]
                   if d["vulnerable"] and d["cwe_primary"])
    print(f"\nmanifests            : {len(cases)}")
    print(f"  by ecosystem       : {dict(Counter(c['ecosystem'] for c in cases))}")
    print(f"dependency entries   : {total_deps}")
    print(f"  vulnerable pins    : {total_vuln}")
    print(f"  patched pins       : {total_deps - total_vuln}")
    print(f"distinct CWEs        : {len(cwes)}")
    print(f"top CWEs             : {cwes.most_common(6)}")
    print(f"\nWrote -> {out}")


if __name__ == "__main__":
    main()
