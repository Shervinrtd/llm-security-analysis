# Measurement Reliability in LLM-Assisted Repository Security Analysis: An Empirical Case Study

Alireza Shahidiani

University of Bologna, MSc in Artificial Intelligence

Research manuscript draft | 15 September 2026

## Abstract

Large language models (LLMs) can produce contextual security assessments, but their usefulness depends on the validity of both their predictions and the experiments used to evaluate them. We present a Python framework for repository-level analysis of code vulnerabilities, malicious code, exposed secrets and vulnerable dependencies, together with an empirical evaluation combining historical predictions and instrumented follow-up runs. A patch-derived corpus contains 35,952 functions associated with 3,472 CVEs. On a 582-record vulnerability sensitivity set with unambiguous identities, four model-prompt configurations achieve F1 scores of 0.273–0.307 and Matthews correlation coefficients of 0.057–0.097. Only the Qwen zero-shot versus chain-of-thought accuracy contrast survives correction across six comparisons, including a repository-block sensitivity analysis. In 56 verified repository cases, the scanner selects 17 target files and raises vulnerability alarms in target files in 14 cases; exact-function localisation succeeds in seven cases. A paired experiment on 339 Python samples finds little response to combined AST reserialisation and string-literal splitting: Qwen recall changes from 80.3% to 80.9%, while the installed YARA subset remains at 83.1%. Qwen produces fewer benign false alarms on this synthetic set. A methodological audit exposes ambiguous sample identities, residual CVE overlap and malformed historical perturbations. The contribution is a documented set of measurement failure modes and corrected operational measurements; reviewer benefit and general adversarial robustness are not established.

Keywords: large language models; vulnerability detection; software supply-chain security; repository analysis; empirical evaluation.

## 1. Introduction

Open-source security assessment requires several different judgements. A function may contain an exploitable defect, a package may perform deliberately harmful actions, a file may expose a credential, or a dependency may match a published advisory. These tasks share an operational setting but have different ground truth, units of analysis and acceptable evidence. Combining them under one aggregate accuracy score risks obscuring the behaviour that matters to a developer.

LLMs offer a common natural-language interface for these tasks. However, plausible explanations are not sufficient evidence that a finding is correct. Surveys identify substantial variation in datasets, language coverage and evaluation methods [1], while empirical research documents difficulty with the semantic distinctions needed for vulnerability detection [2]. A repository workflow adds further uncertainty: a detector cannot assess code that its selection stage never reaches, and unreviewed alarms elsewhere in a repository cannot automatically be counted as false positives.

This paper contributes an empirical analysis of measurement reliability within one LLM-assisted security project. Its central question is how operational definitions and evidence provenance constrain the conclusions that can be drawn from a working scanner. The framework supplies the setting, rather than a new detection algorithm. The contributions are (i) documented identity, coverage and transformation-validity failures; (ii) corrected, traceable operational measurements and repository-aware sensitivity analyses; and (iii) a separation of demonstrated findings from untested reviewer benefit and generalisation. The failure modes are not claimed to be newly discovered in the field; the contribution is their concrete interaction and measured consequences in this case study.

We ask four research questions. RQ1: What detection performance is observed across the four categories and the repository workflow? RQ2: How do model and prompting choices affect vulnerability prediction? RQ3: How do detectors respond to a combined AST-reserialisation and literal-splitting transformation? RQ4: What evidence supports the reliability of dataset labels, explanations and evaluation measurements?

## 2. Related work

Sheng et al. [1] organise LLM vulnerability-detection research around models, methods, datasets and evaluation challenges, including cross-language and repository-level analysis. Our study examines a concrete multi-category implementation and makes the limits of its measurements explicit rather than attempting a comprehensive survey.

Steenhoek et al. [2] investigate vulnerability detection as a code-reasoning task and report difficulties distinguishing subtle security-relevant semantic changes. Their findings motivate our separation of fluent explanations from demonstrated prediction correctness. We do not compare our scores directly with theirs because the corpora, models and evaluation protocols differ.

SecVulEval [3] emphasises fine-grained C/C++ vulnerability localisation, richer context and benchmark quality. Our corpus spans additional languages but principally uses function-level labels. The repository follow-up requires exact-body localisation; it does not provide statement-level evaluation or independently establish the correctness of every label. These distinctions prevent interpreting broad language coverage as evidence of a stronger benchmark.

Our malware baseline uses installed YARA rules associated with GuardDog. The full GuardDog project is a package-analysis tool [4]; matching a local rule subset against synthetic snippets is a narrower task. We therefore identify the evaluated baseline by its actual scope throughout the paper.

## 3. Analysis framework

The framework collects repository content, preprocesses files and functions, dispatches category-specific analysers, and aggregates findings into a user-facing security report. Static-guided triage orders files before bounded LLM analysis. The repository experiment uses a 25-file budget. Reports retain locations, categories, explanatory text and evidence strength so that users can inspect the basis for a warning.

Vulnerability analysis operates on extracted functions and produces a binary judgement with CWE information. Malware analysis asks whether code exhibits harmful intent rather than merely using networking, subprocess or environment-variable APIs. Secrets analysis distinguishes candidate credentials from benign contextual examples. Dependency analysis checks listed components against vulnerability information and records invented package names separately. These outputs are not interchangeable labels.

The application separates installation-related risk from vulnerabilities affecting downstream users. Evidence tiers distinguish deterministic tool output, corroborated findings and unverified model opinions. This is a decision policy, not a proof that deterministic findings are correct or that false-positive rates are bounded. The system provides review assistance; this evaluation does not establish autonomous deployment safety.

Future evaluation records use content-backed identities and record source hashes. Repository measurements retain the actual selected-file list and analysed function hashes. The harnesses checkpoint completed results, refuse overwriting existing runs and store manifests. These engineering controls improve traceability without changing the underlying model weights. The shared strategy prompts were preserved during the corrective work.

## 4. Study design

### 4.1 Data and units of analysis

The vulnerability corpus is reconstructed from public vulnerability-fixing commits using reverse-applied patches and function extraction. It contains 35,952 functions: 5,136 labelled vulnerable and 30,816 labelled safe, drawn from 1,489 repositories and associated with 3,472 CVEs and 196 CWE categories. C, C++, Java, Python and JavaScript are represented. A reconstruction hash verifies the identity of the recovered text; it does not verify that the function is the site of the vulnerability. Post-fix and unchanged functions are treated as negatives by construction, not independent security adjudication.

The historical train, validation and test partitions contain 26,108, 3,542 and 6,302 records. Repository, pair and normalised exact-hash overlap checks pass. Four CVE identities nevertheless overlap training and test, and one overlaps training and validation. A heuristic five-token-shingle screen identifies 12 candidate near-duplicates among 5,741 eligible test functions at Jaccard similarity at least 0.85. This limited candidate search is neither exhaustive nor manually adjudicated. Disjoint repositories do not establish absence from model pretraining.

Historical auxiliary experiments evaluate 300 synthetic malware/benign samples, 300 secrets files and 300 dependency manifests containing 4,243 listed entries. The malware generator produced 400 samples; only 300 were included in its historical evaluation. Synthetic families and decorative variants are correlated. Secrets metrics concern labelled candidate items within files, and dependency metrics concern listed entries, so their denominators differ from malware classification. The controlled Python follow-up uses 339 eligible items from the 400-sample malware corpus and must not be treated as a rerun on the same 300-item population.

### 4.2 Models, prompts and baselines

The vulnerability comparison uses Qwen2.5-Coder and a Google model recorded under the project alias `gemini-flash`, each with zero-shot and eight-step chain-of-thought prompting. Precise historical cloud snapshot identifiers are not fully preserved; the alias should not be interpreted as a reproducible model-version specification. Local inference used a consumer GPU reported as an NVIDIA RTX 4050 with 6 GB memory. We make no controlled speed or cost comparison.

Auxiliary comparisons use the installed GuardDog-associated YARA subset, Gitleaks, and an OSV-derived lookup oracle. The dependency benchmark and oracle share advisory-derived ground truth; oracle agreement measures internal consistency rather than independent real-world coverage. Best-observed auxiliary LLM configurations are selected descriptively on the evaluated results, not by an independent validation procedure. No matched conventional vulnerability-baseline experiment is claimed.

The new perturbation run records `qwen2.5-coder:7b`, temperature 0 and an 800-token output budget, with the existing malware zero-shot prompt. YARA version 4.5.4 compiles 51 of 54 installed rule files; three failures are retained in the manifest. The comparison therefore applies to those compiled rules. The excluded files are capability-network-lolbas.yar, capability-process-hooks.yar and threat-process-sysinfo.yar. Their names alone do not establish which benchmark outcomes they would affect; no corrected-rule counterfactual run was performed. Cache reuse is enabled and recorded per response.

### 4.3 Identity correction and statistical analysis

Each historical 600-row vulnerability configuration contains only 598 distinct legacy sample IDs. Repeated or overloaded function names create ambiguity when predictions are linked to corpus metadata. Eighteen rows per configuration cannot be mapped unambiguously and are excluded from a declared post-hoc sensitivity set of 582 records across 167 repositories. Exclusion avoids guessing which body generated a response; it does not guarantee that the retained set is representative. Invalid predictions and identity errors are separate concerns.

We report confusion counts, precision, recall, F1, balanced accuracy and Matthews correlation coefficient (MCC). Precision is TP/(TP+FP), recall is TP/(TP+FN), and F1 is 2TP/(2TP+FP+FN). Balanced accuracy averages sensitivity and specificity. MCC uses all four confusion counts. An always-negative accuracy baseline makes the class imbalance explicit.

For vulnerability predictions, 2,000 repository-cluster bootstrap resamples provide percentile 95% intervals. Exact McNemar tests compare paired correctness, not F1, with Holm adjustment across all six configuration pairs. A supplementary repository-block permutation analysis performs 10,000 swaps with seed 42 and a plus-one Monte Carlo correction, followed by the same six-comparison adjustment. It assumes exchangeability within independent repository blocks under the null. All these analyses are post-hoc; their scope does not extend to confirmatory claims about other models or datasets.

Repository and auxiliary results are descriptive. Cases within a repository and snippets within a template family are not independent replicates. We do not claim statistical superiority from their point estimates or infer equivalence from a nonsignificant test.

### 4.4 Instrumented follow-up experiments

The repository benchmark attempts 60 recorded repository/CVE cases by reconstructing vulnerable snapshots from fixing commits. All target functions must pass reconstruction verification before scoring. Selection is read from the deployed scanner's saved trace. A target-file alarm hit means at least one vulnerability finding occurs anywhere in any target file; it need not identify the benchmark defect. Exact-body localisation means a finding is attached to a matching target function body, not that its explanation identifies the correct bug. CWE agreement adds a category match but is not independent adjudication. An alarm hit without recorded selection is rejected as an invariant violation.

The paired experiment combines AST reserialisation with splitting ordinary Python string literals into concatenations, preserving docstrings, formatted strings and match constructs. Reserialisation can change formatting and remove comments. There is no reserialisation-only arm for every sample; consequently the experiment does not isolate the causal effect of literal splitting. Original and transformed programs are parsed; after folding literal concatenations their ASTs must agree. Inputs are never executed. This validation does not cover source introspection or every observable behaviour. Original/transformed evaluation order is randomised with seed 42, and both detectors process both arms. Malicious recall and benign false-positive rate are separate endpoints. Failed model replies remain missing rather than being interpreted as benign, and complete-pair counts are disclosed.

## 5. Results

### 5.1 Vulnerability detection and prompting

Table 1 reports the identity-unambiguous sensitivity set (106 positive and 476 negative labels); confusion counts appear in Table 5 in Appendix A. F1 remains near 0.30, and MCC indicates modest discrimination. The always-negative classifier achieves 81.8% accuracy, exceeding every evaluated configuration while detecting no vulnerabilities. Raw accuracy alone would therefore be an unsuitable headline measure.

{{VULNERABILITY_TABLE}}

Qwen zero-shot accuracy is 63.9%, compared with 58.2% for chain-of-thought, a difference of 5.67 percentage points. This contrast survives the exact paired test with Holm-adjusted p=0.00268 and the repository-block sensitivity analysis with adjusted p=0.02820. The other five contrasts do not survive correction. This result concerns accuracy: Qwen chain-of-thought increases true positives from 46 to 53 but also increases false positives from 150 to 190. It is not evidence that chain-of-thought universally reduces vulnerability recall or reasoning ability.

Table 6 in Appendix A gives the numerical exclusion sensitivities. Removing test/example/fixture paths retains 469 records; excluding development-seen CVEs retains 575. These analyses are separate exclusions, not a combined clean test set. They are exploratory, and the data do not establish equivalence between model families. Label noise and incomplete context remain plausible contributors to poor performance, but this experiment does not isolate their causal effects.

### 5.2 Auxiliary security categories

Table 2 summarises historical descriptive comparisons. Malware results favour Qwen on F1 but favour YARA on recall. The secrets result shows a different trade-off: the LLM recovers more labelled secrets but produces many more false positives. These task-specific differences argue against treating a single system as the best security analyser across categories.

{{AUXILIARY_TABLE}}

The strongest observed dependency LLM configuration has listed-entry F1 of 0.232, compared with 1.000 for the shared-source oracle. This does not validate perfect dependency detection outside the benchmark. Another scoring issue arises when models name packages absent from the manifest. Qwen's dependency chain-of-thought output contains 329 such package predictions, versus 14 for zero-shot. Counting the former as additional false positives reduces its listed-entry F1 of 0.108 to an all-reported F1 of 0.087. Reporting only listed-entry scores would hide this part of the review burden.

### 5.3 Repository-level performance

The instrumented run scores 56 cases across 48 repositories; four attempted cases fail reconstruction. The scanner selects target files in 17 cases and records target-file alarm hits in 14. Exact-body localisation succeeds in seven cases, with strict CWE agreement in three (Table 3). No detection-without-selection violation occurs.

{{REPOSITORY_TABLE}}

The 82.4% conditional rate applies to the selected subset, which is not random. It does not prove that changing ranking would recover all remaining vulnerabilities. A causal ranking claim would require a controlled selection intervention with comparable budgets and labels. The observed mean of 31.68 off-target alarms per case is unadjudicated review burden, not a measured false-positive count.

An earlier evaluator recomputed selection with an unranked file walk even though the scanner used static-guided ordering. The resulting historical selection and conditional-detection rates are withdrawn. The instrumented alarm-hit rates replace those operational measurements; they do not retroactively validate the old trace. The new body-based localisation definition is also stricter than historical function-name matching. The saved run contains aggregate case outcomes and selected paths, but not individual finding explanations. Therefore the 14 hits cannot be independently adjudicated as correct defect detections from this run file alone. A case-level review index is supplied with the artifact; no human verdict has been fabricated.

### 5.4 Restricted Python perturbation

Both detectors complete all 339 pairs with no failed predictions. The set contains 178 malicious and 161 benign items. There are 312 AST-changed pairs and 27 formatting-only controls. Qwen changes two verdicts: one additional malicious sample becomes positive and one benign false alarm disappears. YARA changes none (Table 4).

{{PERTURBATION_TABLE}}

The changed-AST subset contains all 178 malicious samples and 134 benign samples. Qwen benign false positives change from 1/134 to 0/134; YARA remains at 63/134. The all-pair result is therefore not solely an artefact of including unchanged ASTs. Nevertheless, this combined transformation produces few output changes in either system and is not a broad adversarial evaluation.

Of 678 Qwen responses, 255 are cache hits. They count as available predictions, not independent repetitions. Cache reuse preserves available outputs but is not an independent model trial. Cache hits are reported separately by arm in Appendix A; the experiment does not estimate repeat-run variability. The original and transformed measurements are paired observations on synthetic code; observed zero false positives after transformation does not guarantee a zero population error rate. Compared with YARA, Qwen produces fewer benign alarms but misses slightly more malicious items.

### 5.5 Label and explanation reliability

A diversity-oriented, round-robin review of 50 vulnerable-labelled cards produces 20 correct labels, 13 wrong-CWE judgements, 12 not-vulnerable judgements and five unclear cases in the primary human pass. The sample excludes negative labels and orphaned positives and is not a probability sample of the corpus. Thus 12/50 cannot be presented as a population label-error estimate.

A secondary LLM review agrees exactly across the four verdict categories on 68% of cards, with Cohen's kappa 0.521. Grouping correct and wrong-CWE into a vulnerable category yields 86% agreement when unclear remains a separate category. Removing every case where either reviewer is unclear gives 42/42 binary agreement, but eight exclusions must accompany that number. Review timing and blinding were not recorded, so independence is not established. Disagreements are not uniformly in one direction.

For Qwen explanations, weighted identifier grounding is 0.521 across 451 findings, and 1.8% of explanations mention at least one identifier absent from the analysed function. These are textual heuristics, not measures of explanation correctness or causal faithfulness. A separate 35-repository corpus yields no clone-unsafe verdicts but some lower-severity alarms on 11 repositories. Because that corpus was reused during detector development, it does not establish held-out false-positive performance.

## 6. Discussion

We propose a workflow in which category-specific tools and LLM findings remain inspectable rather than collapsing into a general safety verdict. Its practical benefit to reviewers has not been measured. The synthetic malware comparison suggests a useful role for contextual discrimination between harmful intent and legitimate capability use. The secrets and dependency results show why that advantage cannot be assumed for other tasks. The study has not tested whether a combined system improves performance over each component under a common adjudicated protocol.

Measurement reliability is itself consequential. A content hash can establish reconstruction identity without validating a security label. A plausible function name can link predictions to the wrong overloaded body. A conditional success rate can look operationally informative even when its selection trace does not describe the deployed pipeline. These failures are preventable through explicit identity and coverage invariants, but implementing those invariants does not repair every historical observation.

Transformation validity is similarly important. Static parsing of the current historical regex procedure finds that 52 of 70 malicious Python inputs and 20 of 21 benign Python inputs become invalid. Historical transformed-source hashes are absent, so this is an audit of the current documented procedure rather than a proven byte-identical replay. The original experiment cannot establish evasion on working code. The new constrained transformation avoids that defect, yet reveals little sensitivity: static validity removes one measurement defect, but neither isolates the intervention nor guarantees adversarial strength. A future three-arm comparison of original, reserialised-only and reserialised-plus-split code would separate these effects.

The main operational implication is to separate coverage, detection and adjudication. An analysis report should state what was selected, what completed, which evidence supports a finding, and what remains unverified. Improving presentation and checkpoint reliability is valuable, but neither should be confused with better security detection.

## 7. Threats to validity

Construct validity is limited by patch-derived labels, assumed negatives, synthetic malware families, synthetic credential contexts and an advisory-derived oracle. Target-file flags do not establish exploitation, and name or body localisation does not prove that the identified reasoning is correct. Explanation grounding cannot substitute for human assessment.

Internal validity is limited by post-hoc identity exclusions and statistical choices, shared CVEs across partitions, heuristic rather than exhaustive near-duplicate screening, and code changes between historical and follow-up runs. Reviewers were not demonstrably blinded. Cached model responses are not fresh samples, and exact historical model/tool provenance is incomplete. Consequently, runtime differences across runs are not controlled performance evidence.

External validity is limited by the selected repositories, small numbers of independent groups, synthetic templates and incomplete model coverage. The corpus's observed class balance does not estimate real-world prevalence. Repository disjointness and new lexical variants do not establish unseen threats during pretraining. The study contains no independently held-out threat-family experiment or production deployment assessment.

Statistical conclusions must remain endpoint-specific. The paired significance tests concern vulnerability correctness under the stated sampling assumptions; no analogous confirmatory superiority test is reported for auxiliary categories. A small p-value does not establish large practical benefit, and failure to reject a difference does not establish equivalence. Future work should prioritise matched conventional vulnerability baselines, fresh repository alarm adjudication, human explanation review and independently designed threat families over additional unstructured model sweeps.

## 8. Reproducibility and research practice

The project preserves historical datasets and predictions and adds explicit run manifests for the follow-up experiments. The repository run is `data/results/repo_bench_v2/20260915-022618`; the paired run is `data/results/perturbation_v2/20260915-025616`. Each includes predictions, a summary and a manifest. The historical audit is `output/experiment-audit/audit.json`. Report gathering pins these runs and checks completed status, paired identities, relevant hashes and robustness-summary recomputation.

The paper's numerical tables and supplementary evidence are generated from `output/report_build/report_data.json`; the manuscript template and build script accompany the draft. Fifty-seven offline regression tests passed before the completed follow-up runs. These tests validate engineering behaviour rather than detection accuracy. No public archival release or external artifact evaluation is claimed. A release would require a separate review of source redistribution conditions and a stable repository/archive identifier.

Malware fixtures are inert and analysed statically; no attack code is executed by the paired evaluation. Secrets examples are synthetic. LLM assistance was used in software development, manuscript drafting and methodological cross-checking. It is not treated as an independent human adjudicator. The author remains responsible for checking the manuscript, confirming authorship and applying the eventual venue's disclosure requirements.

## 9. Conclusion

This study evaluates an LLM-assisted repository security framework across four categories while examining the reliability of the measurements themselves. Vulnerability performance remains modest; the repository scanner raises alarms in target files in 14 of 56 verified cases. On synthetic Python pairs, Qwen produces fewer benign false alarms than the installed YARA subset, while YARA has slightly higher malicious recall and both show little response to the combined transformation. These observations characterise this experimental system; reviewer assistance remains an intended application, not an evaluated benefit. General superiority, autonomous safety and adversarial robustness are not established. Reliable evaluation requires valid identities, explicit coverage, appropriate units of analysis and labels whose evidential limits remain visible.

## Appendix A. Experimental configuration and supplementary results

Historical sampling is reconstructed against saved identities, not asserted from a missing command log. Applying the current evaluator's random sampling rule with seed 42 and limit 600 reproduces the saved Qwen zero-shot sample-ID multiset. This supports the selection reconstruction but does not recover ambiguous function identities. The sample contains 173 Java, 164 Python, 145 C, 83 JavaScript and 35 C++ records. The historical malware prediction-ID set exactly matches the first 300 records of the saved 400-record benchmark, consistent with the evaluator's prefix-limit rule. Why that budget was chosen is not recorded.

The current repository builder shuffles candidates within language and selects round-robin with a repository cap. The follow-up consumes the existing 60-case benchmark file rather than rebuilding it; the original builder invocation is not fully archived. Scored language counts are 12 each for C, C++, JavaScript and Python, and eight for Java. Selection is therefore not a representative random sample of public repositories. The strict reconstruction exclusions are reported as coverage loss, not counted as model errors.

Table 5. Confusion counts on the 582-record vulnerability sensitivity set (106 positive and 476 negative labels).

{{COUNTS_TABLE}}

Table 6. Separate post-hoc exclusion sensitivities. Each entry reports n / F1 / MCC / accuracy; no re-inference is involved.

{{SENSITIVITY_TABLE}}

Table 7. Recoverable configuration and missing provenance. Historical details are distinguished from instrumented settings.

| Experiment | Verified configuration | Remaining limitation |
| --- | --- | --- |
| Vulnerability | Four model/prompt configurations; 600 historical rows each; reconstructed seed-42 sample | Exact cloud snapshot and historical commands missing; 18 identity-ambiguous rows excluded |
| Historical auxiliary | 300 malware items, 300 secrets files, 300 dependency manifests; best-observed configuration labelled | No independent best-model selection; original rule/version provenance incomplete |
| Repository follow-up | Qwen zero-shot; 25-file budget; 60 attempted, 56 scored; selected paths and source hashes saved | No individual finding explanations in run output; no matched static vulnerability baseline |
| Paired Python | Qwen 7B, temperature 0, 800 tokens; YARA 4.5.4; 51 compiled rules; 339 pairs; seed 42 | Combined formatting/literal intervention; synthetic labels; cached responses |

The malicious Python set covers eight generator labels: backdoor (48), suspicious-network (30), exec-base64 (17), download-executable (17), code-execution (17), exfiltrate-sensitive-data (17), reverse-shell (17), and obfuscation (15). The 161 benign records have no corresponding technique label. These are generator labels, not proof of eight independent causal mechanisms or one-to-one benign twins. Family-level results and per-arm cache counts are supplied in the supplementary evidence file.

Prompt reproduction uses the frozen src/prompts.py zero_shot and cot_8step builders, their shared system instruction and JSON answer specification, and the saved label-space candidate block. The exact current prompt-source snapshot is supplied with hashes in output/paper/method_sources/. Current source is not automatically proof of exact historical source. Malware and paired runs use the zero-shot prompt in src/malware_evaluate.py. Historical parsing code is also supplied; the new paired parser accepts a JSON boolean malicious field, rejects string booleans and malformed answers, and records failed pairs separately. Historical parser behaviour differs and must not be silently replaced when reproducing old summaries.

The supplement lists deterministic representative disagreement cases with labels and prediction outcomes. They are error examples relative to benchmark labels, not independently adjudicated security defects. The 14 target-file hit cards require recovered finding evidence and a named human reviewer before a correct-defect count can be reported. A zero-shot/CoT trade-off in seven additional true positives and 40 additional false positives is directly supported by the confusion counts; attributing it to better or worse semantic reasoning would require further evidence.

To reproduce the manuscript, run python research/paper/prepare_revision.py and then python research/paper/build_paper.py from the project root. The generated manuscript and PDF are accompanied by a paper manifest, supplementary evidence, method-source snapshots and the pending adjudication index. The source and result files retain their original locations; no fresh detector run is implied by these build commands.

## References

[1] Ze Sheng, Zhicheng Chen, Shuning Gu, Heqing Huang, Guofei Gu, and Jeff Huang. 2025. LLMs in Software Security: A Survey of Vulnerability Detection Techniques and Insights. arXiv:2502.07049v2. https://arxiv.org/abs/2502.07049v2

[2] Benjamin Steenhoek, Md Mahbubur Rahman, Monoshi Kumar Roy, Mirza Sanjida Alam, Hengbo Tong, Swarna Das, Earl T. Barr, and Wei Le. 2025. To Err is Machine: Vulnerability Detection Challenges LLM Reasoning. arXiv:2403.17218v2 (first submitted 2024). https://arxiv.org/abs/2403.17218v2

[3] Md Basim Uddin Ahmed, Nima Shiri Harzevili, Jiho Shin, Hung Viet Pham, and Song Wang. 2025. SecVulEval: Benchmarking LLMs for Real-World C/C++ Vulnerability Detection. arXiv:2505.19828. https://arxiv.org/abs/2505.19828

[4] Datadog. GuardDog: a CLI tool to identify malicious PyPI and npm packages. Project documentation, accessed 15 September 2026. https://github.com/DataDog/guarddog
