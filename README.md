# LLM-Based Open-Source Security Analysis — Four Pillars + Repository Auditor

This project evaluates Large Language Models as semantic security analysers for
open-source repositories, across the four threat categories named in the project
objective, and orchestrates them into a repository-level auditing system.

The comprehensive [project report](output/pdf/LLM%20Security%20Analysis%20-%20Project%20Report.pdf)
describes the implementation, completed experiments and scientific boundaries.
See [limitations and resolutions](research/LIMITATIONS_AND_RESOLUTIONS.md) for
implemented measurement fixes and work that still needs new data or human review.

| Pillar | Benchmark | Real baseline tool | Modules |
|---|---|---|---|
| 1. **Vulnerabilities** | 35,952 functions, 5 language labels, 196 CWEs | Matched accuracy baseline pending | `nvd_collect` `osv_collect` `patch_fetch` `func_extract` `build_dataset` `evaluate` |
| 2. **Malware** | 300 package samples, 6 techniques | GuardDog YARA rules | `malware_build` `malware_evaluate` |
| 3. **Secrets** | 300 files, 5 hard-negative kinds | Gitleaks 8.30.1 | `secrets_build` `secrets_evaluate` |
| 4. **Dependencies** | 300 manifests, 3 ecosystems | OSV database lookup | `deps_collect` `deps_build` `deps_evaluate` |
| **Repository layer** | 56 verified reconstructed cases, 48 repositories; synthetic smoke fixtures | — | `repo_analyze` |

Shared infrastructure: `models` (7 free-tier LLM providers + offline stub),
`prompts` (6 strategies), `cwe_catalog` (CWE names + hierarchy), `config`.

Each pillar has a labelled benchmark and an evaluation harness. Labels and
baseline comparisons have category-specific limitations: the vulnerability
study does not yet include a matched conventional-tool accuracy benchmark, and
the dependency lookup shares its source with the benchmark labels. The report
defines the evaluation units and supported conclusions. Stub-model runs test
the workflow; real inference requires a configured local model or provider.

---

## Pillar 1 — Vulnerabilities (the largest component)

Reproducible collection pipeline: **function-level, multi-class (CWE) vulnerability
detection across Java, C/C++, Python and JavaScript, using real-world CVE fix
commits.** It does not reuse a single prior benchmark, but rebuilds a corpus from
primary sources (NVD + OSV + GitHub) using one consistent methodology across all
four languages.

---

## Why build rather than reuse

| Prior dataset | Languages | Limitation for us |
|---|---|---|
| Juliet (used by Tamberg & Bahsi) | Java, C/C++ | Synthetic, artificially 50/50 balanced |
| SVEN (used by *To Err Is Machine*) | C/C++ | Single language, binary labels only |
| SecVulEval | C/C++ | Single language |
| BigVul / CVEfixes / DiverseVul | mostly C/C++ | High duplication rates (3–19%), language-skewed |

No existing corpus covers our four target languages under one schema, and none of the
Python/JavaScript ecosystems are well represented. Hence a fresh, uniform collection.

---

## Pipeline

```
NVD API ──▶ nvd_collect.py ──▶ cve_candidates.json
                                      │
                                      ▼
GitHub .patch ──▶ patch_fetch.py ──▶ diff hunks + pre/post file contents
                                      │
                                      ▼
tree-sitter ──▶ func_extract.py ──▶ functions with line spans
                                      │
                                      ▼
                  build_dataset.py ──▶ dataset.jsonl
                                      │
                                      ▼
                     finalize.py ──▶ + CWE names        (cwe_catalog.py)
                                     + label_space.json
                                     + dataset_report.txt (report_stats.py)
                                     + train/val/test.jsonl (make_splits.py)
```

| Module | Role |
|---|---|
| `nvd_collect.py` | CVE metadata. Two modes: `--mode cwe` (targeted, efficient) or `--mode date` (full sweep) |
| `osv_collect.py` | **Language-targeted** collection via OSV package ecosystems (Maven→Java, npm→JS, PyPI→Python) |
| `patch_fetch.py` | Commit diffs + pre/post file reconstruction |
| `func_extract.py` | tree-sitter function extraction for all 5 parsers |
| `build_dataset.py` | Labelling, filtering, de-duplication |
| `cwe_catalog.py` | CWE id → name, and the parent/child hierarchy for fair grading |
| `report_stats.py` | Statistics + integrity assertions |
| `make_splits.py` | Leakage-safe train/val/test splitting |
| `finalize.py` | Runs the whole post-processing chain |
| `sample_for_review.py` | Stratified sample exported as an HTML sheet for manual label verification |

### Key design decisions

**1. We never call `api.github.com`.**
It is capped at 60 requests/hour unauthenticated, which would make collection
impossible without every user holding a token. Instead we use two plain web endpoints
that are not subject to that cap:
`github.com/<repo>/commit/<sha>.patch` and `raw.githubusercontent.com/<repo>/<sha>/<path>`.

**2. The pre-fix file is reconstructed, not fetched.**
Rather than resolving each commit's parent (an extra API call per commit), we
**reverse-apply** the diff hunks to the post-fix file. A unified diff carries every
removed line verbatim, so this is exact. The reconstruction is verified: each hunk's
context and added lines must match the fetched file, otherwise the sample is discarded
rather than trusted (`reverse_apply` returns `None`).

**3. Language is resolved from changed file extensions, not from NVD.**
NVD does not record the language of a vulnerability. Only the actual patched files
tell us reliably, so language assignment happens after the patch is fetched.

**4. "Top-level function" is the extraction unit.**
A function node not nested inside another function — i.e. a Java *method* (not its
class), a Python `def` (not an inner helper), a JS function (not an inline callback).
This matches the unit a developer actually reviews.

**5. Untouched functions are capped per file.**
Without a cap, a single large file can donate 100+ negative samples and dominate the
corpus (observed: 138 from one file). Capped at `MAX_UNCHANGED_PER_FILE` and sampled
deterministically (seeded by repo/sha/path, so runs are reproducible).

**6. Two collection routes, because NVD alone skews the corpus.**
NVD does not record a vulnerability's language, so `nvd_collect.py` must download every
patch before it can tell what language it is. That produced a corpus 83% C/C++ — too
thin in Java/JS/Python to support a per-language claim. `osv_collect.py` fixes this by
pulling from OSV, where advisories are grouped by **package ecosystem** (Maven→Java,
npm→JavaScript, PyPI→Python) and carry their CWE inline. Both routes emit the same
candidate schema, so `build_dataset.py` consumes either unchanged.

**7. Splits are stratified per language.**
Balancing splits on the total vulnerable count alone left Java with only 13 test
positives out of 261 available — enough to sink any per-language claim by pure chance.
`make_splits.py` now tracks a per-language quota, bringing every language to its full
share (Java 13 → 52).

---

## Record schema

One JSON object per function, per line:

| Field | Meaning |
|---|---|
| `label` | `1` = vulnerable, `0` = safe |
| `cwe_primary`, `cwe_ids` | CWE label(s) — **the multi-class target**; `null`/`[]` when `label=0` |
| `version` | `pre` (vulnerable), `post` (patched), `unchanged` (untouched function in same file) |
| `pair_id` | Links a `pre`/`post` pair — supports the "can the model tell them apart?" analysis |
| `language`, `language_family` | `c`/`cpp`/`java`/`python`/`javascript`; family merges c+cpp |
| `code`, `func_name`, `loc` | The function source, its name, and line count |
| `changed_lines_in_func` | Changed lines rebased to the function (groundwork for future statement-level work) |
| `cve_id`, `cve_published`, `cve_description`, `cvss_score`, `cvss_severity` | CVE provenance |
| `repo`, `commit_sha`, `commit_message`, `file_path` | Code provenance |
| `func_hash` | Whitespace-normalised MD5, used for de-duplication |

`cve_published` is retained deliberately: it enables a later
**training-cutoff leakage audit** (split by disclosure date vs. a model's cutoff)
without re-collecting anything.

---

## Usage

```bash
pip install requests tree-sitter tree-sitter-c tree-sitter-cpp \
            tree-sitter-java tree-sitter-python tree-sitter-javascript

# 1. Collect CVEs that have a GitHub fix commit (cached; safe to re-run)
python src/nvd_collect.py --mode cwe --max-pages 2      # targeted (recommended)
python src/nvd_collect.py --mode date --start 2021 --end 2024   # or full sweep

# 2. Build the labelled dataset
python src/build_dataset.py

# 3. Enrich, derive label space, report, and split - all in one
python src/finalize.py --data data/processed/dataset.jsonl
```

`finalize.py` produces everything the experiment consumes:

- `dataset.jsonl` — every record, now carrying `cwe_name`
- `label_space.json` — the CWE classes, their counts, each class's lenient-match
  set, and a ready-to-paste `prompt_block` for multi-class prompts
- `dataset_report.txt` — statistics + integrity assertions
- `train.jsonl` / `val.jsonl` / `test.jsonl` — leakage-safe splits

Optional: set `NVD_API_KEY` to cut NVD request spacing from 6.5s to 0.7s
(request a free key at <https://nvd.nist.gov/developers/request-an-api-key>).

Everything network-fetched is cached under `data/cache/`, so re-runs cost no requests
and the build is deterministic.

---

## Filtering rules (`config.py`)

Adapted from SecVulEval's methodology and the scope note:

- single-commit fixes only; commits touching more than `MAX_FILES_PER_COMMIT` files are dropped (usually refactors)
- commit-message noise markers (`merge`, `typo`, `reformat`, `bump version`, …) are skipped
- functions outside `[MIN_FUNC_LOC, MAX_FUNC_LOC]` are dropped
- a `pre`/`post` pair whose normalised text is identical is dropped (the change was outside the function)
- global de-duplication on `func_hash`, keeping vulnerable samples preferentially

## Integrity guarantees

`report_stats.py` asserts, and the pilot run confirms:
no empty code, no vulnerable sample without a CWE, no safe sample carrying a CWE,
no `loc` mismatch, no duplicate `func_hash`, no incomplete or identical `pre`/`post` pair.

---

## Measuring label quality

Commit-derived labels are noisy by construction, so the corpus ships with a way
to *measure* that noise rather than assume it away:

```bash
python src/sample_for_review.py --n 100 --seed 42
```

This writes `label_review.html` — a stratified sample (spread across languages
and CWEs) showing each vulnerable function beside its fix diff and CVE context,
with a verdict selector: *correct* / *vulnerable but wrong CWE* / *not actually
vulnerable* / *unclear*. Reviewer decisions export to CSV from the page.

Two reviewers on the same sample gives an inter-rater agreement figure
(Cohen's kappa) and a label-accuracy estimate for the paper — the same evidence
SecVulEval provided for its own context annotations.

## Known limitations (for the paper's threats-to-validity section)

- **Label inheritance.** A `pre` function is labelled with the CVE's CWE, but a commit may touch functions that are not themselves the root cause. This is the standard assumption in commit-derived datasets (BigVul, CVEfixes, SecVulEval) and is a known source of label noise — quantify it with `sample_for_review.py` rather than asserting the labels are clean.
- **`unchanged` ≠ provably safe.** Untouched functions are assumed non-vulnerable; they may contain undisclosed flaws. Same assumption as prior work.
- **Yield is language-skewed.** C/C++ dominates NVD's commit-linked CVEs; Java/JS/Python need proportionally more CVEs processed to reach comparable counts.
- **Multi-commit fixes are excluded**, so vulnerabilities fixed across several commits are under-represented.
