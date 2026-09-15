"""Build the REVISED MSc-level scientific project report (PDF).

Portable: all paths derived from this file's location. Run after gather.py
and charts.py, in order:

    python research/report/gather.py
    python research/report/charts.py
    python research/report/build_report_v2.py

This is a methodological-audit revision, not a new-results report: point
estimates for malware/secrets/dependencies are unchanged from the original
run; what changes is which claims are supported by them, and the
vulnerability / repository-benchmark / label-review sections are replaced
with the corrected reanalysis in output/experiment-audit/audit.json. See
REVISION_NOTES.md for the full list of changes against the original PDF,
which is left untouched at its original path.
"""
import json
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, PageTemplate, Paragraph,
                                Spacer, Table, TableStyle, Image, KeepTogether,
                                PageBreak)
from PIL import Image as PImage

ROOT = Path(__file__).resolve().parents[2]
SP = ROOT / "output" / "report_build"
D = json.loads((SP / "report_data.json").read_text(encoding="utf-8"))
A = D.get("audit", {})
OUT = ROOT / "output" / "pdf" / "LLM Security Analysis - Scientific Report - Revised.pdf"

INK = colors.HexColor("#111827"); ACC = colors.HexColor("#0B2E36")
ACC2 = colors.HexColor("#12414B"); GREY = colors.HexColor("#4B5563")
LINE = colors.HexColor("#D1D5DB"); LIGHT = colors.HexColor("#F3F4F6")
GOOD = colors.HexColor("#2A8C79"); CORAL = colors.HexColor("#C0392B")
AMBER = colors.HexColor("#B45309")

ss = getSampleStyleSheet()
TITLE = ParagraphStyle("TT", parent=ss["Title"], fontName="Helvetica-Bold",
                       fontSize=20, textColor=ACC, leading=25, alignment=TA_LEFT, spaceAfter=6)
SUBT = ParagraphStyle("ST", parent=ss["Normal"], fontName="Helvetica",
                      fontSize=12, textColor=GREY, leading=15.5, spaceAfter=4)
H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontName="Helvetica-Bold",
                    fontSize=14, textColor=ACC, spaceBefore=14, spaceAfter=6, leading=17, keepWithNext=True)
H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                    fontSize=11.5, textColor=ACC2, spaceBefore=10, spaceAfter=4, leading=14, keepWithNext=True)
BODY = ParagraphStyle("BODY", parent=ss["Normal"], fontName="Times-Roman",
                      fontSize=10.5, leading=15.5, alignment=TA_JUSTIFY, spaceAfter=7,
                      textColor=INK)
CELL = ParagraphStyle("CE", parent=ss["Normal"], fontName="Times-Roman", fontSize=8.7, leading=11.6)
CELLB = ParagraphStyle("CB", parent=CELL, fontName="Times-Bold")
CELLH = ParagraphStyle("CH", parent=ss["Normal"], fontName="Helvetica-Bold",
                       fontSize=8.7, leading=11.6, textColor=colors.white)
CAP = ParagraphStyle("CAP", parent=ss["Normal"], fontName="Helvetica", fontSize=8.5,
                     textColor=GREY, leading=11.5, alignment=TA_LEFT, spaceAfter=11, spaceBefore=3)
SMALL = ParagraphStyle("SM", parent=ss["Normal"], fontName="Helvetica", fontSize=8.5,
                       textColor=GREY, leading=12)
REF = ParagraphStyle("REF", parent=ss["Normal"], fontName="Times-Roman", fontSize=9,
                     leading=13, leftIndent=10, firstLineIndent=-10, spaceAfter=4)
NOTEBOX = ParagraphStyle("NB", parent=BODY, fontSize=9.3, leading=13, textColor=colors.white,
                         alignment=TA_LEFT, spaceAfter=0)

story = []
FIG = [0]; TAB = [0]


def h1(t): story.append(Paragraph(t, H1))
def h2(t): story.append(Paragraph(t, H2))
def para(t): story.append(Paragraph(t, BODY))
def sp(h=6): story.append(Spacer(1, h))
def bullet(t): story.append(Paragraph("• " + t, BODY))


def figure(name, width_mm, caption):
    ip = SP / name
    if not ip.exists():
        raise FileNotFoundError(f"Required report chart missing: {ip}. Run charts.py first.")
    FIG[0] += 1
    w, h = PImage.open(ip).size
    W = width_mm * mm
    H = W * h / w
    block = [Image(str(ip), width=W, height=H),
             Paragraph(f"<b>Figure {FIG[0]}.</b> {caption}", CAP)]
    story.append(KeepTogether(block))


def tnum(caption):
    TAB[0] += 1
    story.append(Paragraph(f"<b>Table {TAB[0]}.</b> {caption}", ParagraphStyle("tablecaption", parent=CAP, keepWithNext=True)))


def table(headers, rows, widths):
    data = [[Paragraph(h, CELLH) for h in headers]]
    for r in rows:
        data.append([c if hasattr(c, "style") else Paragraph(str(c), CELL) for c in r])
    st = [("BACKGROUND", (0, 0), (-1, 0), ACC),
          ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
          ("LINEBELOW", (0, 0), (-1, 0), 0.6, ACC),
          ("LINEBELOW", (0, -1), (-1, -1), 0.6, LINE),
          ("LINEBELOW", (0, 1), (-1, -2), 0.3, LINE),
          ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
          ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    caption = story.pop() if story and isinstance(story[-1], Paragraph) and story[-1].style.name == 'tablecaption' else None
    if caption is not None:
        caption.style = CAP
        data.insert(0, [caption] + [''] * (len(headers) - 1))
        st = [(op, (a[0], a[1] + 1 if a[1] >= 0 else a[1]),
                    (b[0], b[1] + 1 if b[1] >= 0 else b[1]), *args)
              for op, a, b, *args in st]
        st += [('SPAN', (0, 0), (-1, 0)), ('LEFTPADDING', (0, 0), (-1, 0), 0),
               ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
               ('NOSPLIT', (0, 0), (-1, min(2, len(data)-1)))]
    block = Table(data, colWidths=widths, repeatRows=(1,) if caption is not None else 1,
                  style=TableStyle(st))
    story.append(block)
    sp(11)


def notebox(text):
    inner = Table([[Paragraph(text, NOTEBOX)]], colWidths=[170 * mm])
    inner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), ACC2),
                               ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                               ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.append(inner); sp(10)


ds = D["dataset"]
vuln = A.get("vulnerability", {})
pw = A.get("pairwise_accuracy", {})
rb = A.get("repository_benchmark", {})
lrv = A.get("label_review", {})
lrd = D.get("label_review_derived", {})
tc = A.get("trusted_corpus", {})
def best_per_model(entries):
    result = {}
    for entry in entries:
        if entry["model"] not in result or entry["f1"] > result[entry["model"]]["f1"]:
            result[entry["model"]] = entry
    return result

mal_rows = best_per_model(D["results"].get("malware", []))
sec_rows = best_per_model(D["results"].get("secrets", []))
dep_rows = best_per_model(D["results"].get("deps", []))
ev = D.get("evasion", {})
interp = D.get("interp_derived", {})
split_overlap = A.get("split_overlap", {})
vc = D.get("validity_checks", {})
pv2 = D.get("perturbation_v2", {})

# ==================================================== TITLE BLOCK
story.append(Spacer(1, 4))
story.append(Paragraph("Large Language Models as Semantic Analysers for the "
                       "Security Assessment of Open-Source Software Repositories", TITLE))
story.append(Paragraph("An empirical evaluation of LLM-assisted security analysis across "
                       "code vulnerabilities, malicious code, exposed secrets and vulnerable dependencies", SUBT))
sp(6)
rule = Table([[""]], colWidths=[170 * mm], rowHeights=[2])
rule.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 1.2, ACC)]))
story.append(rule)
sp(6)
meta = Table([
    [Paragraph("<b>Author</b>", CELL), Paragraph("Alireza Shahidiani", CELL)],
    [Paragraph("<b>Programme</b>", CELL), Paragraph("MSc Artificial Intelligence — Research Project / Internship", CELL)],
    [Paragraph("<b>Date</b>", CELL), Paragraph(datetime.now().strftime("%d %B %Y") + " (revised edition)", CELL)],
    [Paragraph("<b>Status</b>", CELL), Paragraph("Revises the original scientific report of the same project; the "
                                                  "original is preserved unchanged (see Provenance Appendix).", CELL)],
], colWidths=[30 * mm, 140 * mm])
meta.setStyle(TableStyle([("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
story.append(meta)
sp(12)

# ==================================================== ABSTRACT
h1("Abstract")
para(
    "This study evaluates LLM-assisted security assessment across code vulnerabilities, synthetic "
    "malware, secrets and dependencies. A patch-derived corpus contains 35,952 functions associated "
    "with 3,472 CVEs. Historical experiments compare Qwen2.5-Coder and Gemini with specialist "
    "baselines; a subsequent methodological audit reanalyses the saved results without new model calls. "
    "Eighteen identity-ambiguous rows are excluded from each 600-row vulnerability configuration. "
    "On the remaining 582 records, F1 ranges from 0.273 to 0.307 and MCC from 0.057 to 0.097. "
    "Repository-cluster confidence intervals show substantial uncertainty. One of six item-level "
    "accuracy comparisons survives Holm correction; a repository-level permutation sensitivity "
    "also supports this contrast (adjusted p = 0.028). No model equivalence is established. The repository benchmark "
    "records target-file flags in 14 of 56 cases; its historical selection metric is invalid and "
    "cannot establish a file-ranking bottleneck. On synthetic malware, observed F1 is higher for "
    "Qwen zero-shot than for the installed YARA subset (0.898 versus 0.772), while recall is lower "
    "(0.819 versus 0.852); these differences are descriptive. A diversity-oriented 50-card review "
    "finds 12 non-vulnerable labels and 13 wrong-CWE judgements, without supporting a population "
    "noise estimate. Further checks expose shared CVE identities across splits and severe syntax "
    "failures in the current historical perturbation procedure. The revision supplies corrected "
    "reporting, stronger experiment identities and traces, prospective grouped splits, and a "
    "constrained Python perturbation instrument. New follow-up runs select 17/56 target files and "
    "detect 14/17 selected cases. On 339 valid Python pairs, Qwen recall changes from 80.3% to "
    "80.9%, while YARA recall stays at 83.1%. These restricted results do not establish general "
    "robustness. Independent label adjudication and new held-out data remain necessary.")

# ==================================================== 1 INTRO
h1("1. Introduction")
para(
    "Open-source software has become a foundational component of modern systems: the majority of "
    "contemporary applications incorporate third-party code, most of it obtained from public "
    "repositories such as GitHub. This reuse accelerates development but enlarges the attack surface. "
    "Adversaries increasingly target the software supply chain directly — publishing malicious "
    "packages, typosquatting popular names, or planting install-time payloads — while conventional "
    "risks such as latent vulnerabilities, hard-coded secrets and outdated dependencies remain "
    "pervasive. Traditional detection relies on signature matching and static analysis, which are "
    "precise for catalogued patterns but limited against novel, obfuscated or semantically subtle "
    "threats.")
para(
    "Large Language Models offer a qualitatively different capability: an approximate semantic "
    "understanding of source code and developer intent. This motivates the central research question "
    "of this project — <i>to what extent can freely available LLMs perform automated, repository-level "
    "security assessment, and how do they compare with the specialist tools currently in use?</i> This "
    "revised edition additionally treats the project's own measurement methodology as an object of "
    "scrutiny: several claims in the original edition outran what the underlying data supported, and "
    "the purpose of this document is to state precisely what is and is not established.")
h2("1.1 Research questions")
for q in [
    "<b>RQ1.</b> How do LLMs compare with specialist baselines across the four threat categories "
    "(vulnerabilities, malware, secrets, vulnerable dependencies)?",
    "<b>RQ2.</b> Does model choice or prompting strategy materially affect vulnerability-detection "
    "performance at the free tier?",
    "<b>RQ3.</b> How robust are LLM- and signature-based detectors to textual adversarial perturbation?",
    "<b>RQ4.</b> How grounded are LLM-generated explanations in the code they describe, and what is "
    "the observed false-alarm behaviour on a trusted-repository development set?"]:
    story.append(Paragraph(q, BODY))
h2("1.2 Contributions")
for c in [
    "A multi-language vulnerability benchmark reconstructed from published patches, with "
    "repository-disjoint and exact-hash-disjoint (not near-duplicate-verified) train/validation/test "
    "partitions, and a disclosed record of residual CVE-ID overlap.",
    "A repository-analysis system introducing an evidence-tier model and a separation of clone-safety "
    "from deployment-safety verdicts.",
    "An empirical comparison of two free LLMs against specialist baselines, reported with cluster-"
    "bootstrap confidence intervals and Holm-corrected paired significance tests over the full set of "
    "pairwise comparisons actually run.",
    "A self-audit methodology: a documented process that re-examined the original claims against the "
    "raw prediction logs, found specific statistical and sampling defects, and reports the corrected "
    "and withdrawn claims explicitly (Section 6.5, Section 10)."]:
    story.append(Paragraph("• " + c, BODY))

# ==================================================== 2 BACKGROUND
h1("2. Background and Threat Model")
para(
    "We consider four threat categories, treated as distinct because they carry different risk "
    "semantics and demand different evidence. Crucially, we further distinguish <i>clone-safety</i> "
    "(whether acquiring and installing a repository executes hostile code) from <i>deployment-safety</i> "
    "(whether the code contains latent weaknesses), as a repository may be safe under one criterion and "
    "unsafe under the other.")
tnum("The four threat categories and the specialist baseline adopted for each.")
table(["Category", "Description", "Specialist baseline"],
      [[Paragraph("<b>Vulnerabilities</b>", CELL), "Exploitable weaknesses in first-party code (e.g. injection, memory-safety, authentication flaws).", "— (semantic task)"],
       [Paragraph("<b>Malware</b>", CELL), "Deliberately hostile logic: backdoors, exfiltration, reverse shells, install hooks.", "GuardDog YARA rule subset (installed rules only)"],
       [Paragraph("<b>Secrets</b>", CELL), "Credentials or keys committed to source.", "Gitleaks (regex)"],
       [Paragraph("<b>Dependencies</b>", CELL), "Reliance on component versions with published advisories.", "OSV database lookup (in-corpus oracle, see 6.1)"]],
      [34 * mm, 96 * mm, 40 * mm])
para(
    "Signature and static tools excel where the threat is enumerable but degrade against novelty and "
    "obfuscation. The hypothesis under test is that a semantic analyser complements these tools, "
    "particularly for malicious-intent and context-dependent cases; Sections 6–7 test this against "
    "baselines whose own scope and provenance are stated explicitly rather than assumed.")



# ==================================================== 3 DATASET
h1("3. Dataset Construction")
para(
    "Each example is derived from a published security fix rather than manual or heuristic annotation, "
    "so the label originates from an external advisory. This does not make the label automatically "
    "correct for the specific function extracted (Section 3.5): a fix commit can touch files that "
    "accompany, rather than contain, the actual flaw.")
h2("3.1 Construction methodology")
para(
    "For each catalogued vulnerability we resolve the fixing commit, extract the modified function via "
    "tree-sitter parsing, and reverse-apply the patch to reconstruct the pre-fix state. This yields "
    "matched pairs: the function before the fix, labelled <i>vulnerable</i>, and after, labelled "
    "<i>safe</i>. Reconstruction correctness is verified against a recorded hash of the resulting text; "
    "this hash check establishes that the reconstruction matches the intended pre-fix source, not that "
    "the reconstructed function is itself vulnerable — those are different properties, and only the "
    "first is checked automatically. Post-fix and file-unchanged functions are treated as negatives by "
    "assumption (they are not independently confirmed safe), following common practice in commit-"
    "derived corpora but carrying the same caveat.")
h2("3.2 Composition and distribution")
para(
    f"The corpus comprises <b>{ds['total']:,}</b> labelled functions — <b>{ds['vulnerable']:,}</b> "
    f"vulnerable and <b>{ds['safe']:,}</b> safe — drawn from <b>{ds['repos']:,}</b> repositories and "
    f"<b>{ds['cves']:,}</b> distinct CVEs, spanning <b>{ds['cwe_types']}</b> CWE categories. The class "
    "imbalance (approximately 1:6) reflects the extraction and negative-sampling procedure and "
    "is preserved rather than rebalanced; it is not claimed to estimate real-world defect prevalence, "
    "which depends on the sampling of CVEs and repositories, not on this corpus alone.")
figure("chart_labels.png", 88, "Class distribution of the vulnerability corpus.")
figure("chart_languages.png", 150,
       "Per-language sample counts, stratified by class. Java, Python and C dominate; C++ is the "
       "smallest stratum, which bears on the interpretation of per-language results in Section 6.")
figure("chart_cwe.png", 150,
       "The ten most frequent CWE categories. The distribution is broad rather than concentrated, "
       "exposing detectors to heterogeneous weakness types.")
h2("3.3 Partitioning and leakage control")
para(
    "The corpus is partitioned into training, validation and test sets, grouped by repository so that "
    "no repository straddles a split, and de-duplicated by a whitespace-normalised exact hash of the "
    "function text. Both of these are confirmed with zero overlap between every split pair (train/val, "
    "train/test, val/test) on <code>repo</code>, <code>pair_id</code> and <code>func_hash</code>. This "
    "is a real but limited guarantee: it rules out identical-after-whitespace duplicates and same-"
    "repository leakage, but does <b>not</b> establish that no near-duplicate function (renamed "
    "variables, reordered statements, copy-pasted boilerplate across different repositories) crosses a "
    "split boundary. A heuristic screen has since been run (identifier-normalised 5-token-shingle "
    f"Jaccard &gt;= 0.85): of {vc.get('fuzzy_screen', {}).get('n_test_eligible', 'n/a')} eligible test "
    f"functions, {vc.get('fuzzy_screen', {}).get('n_test_with_candidate', 'n/a')} have at least one "
    "near-duplicate candidate in the training/validation data (e.g. structurally similar functions "
    "shared between unrelated repositories). These are unconfirmed heuristic candidates, not manually "
    "verified leakage, and the method can both over-group unrelated code and miss true duplicates; it "
    "narrows, but does not close, this risk. Grouping by "
    "repository does not fully constrain grouping by CVE: the audit found the fixing commits for "
    f"<b>{split_overlap.get('train/test', {}).get('cve_id', '?')} CVE IDs shared between train and "
    f"test</b>, and <b>{split_overlap.get('train/val', {}).get('cve_id', '?')} between train and "
    "validation</b> (the same CVE can be fixed by commits in more than one repository). This does not by "
    "itself mean any function was seen twice, but it means the train/test split is not CVE-disjoint, "
    "only repository- and function-text-disjoint, which should be stated precisely rather than implied "
    "away. Separately, strategy calibration reads the validation split, never the test split, and the "
    "known-CVE recognition index used by the repository benchmark is built from train and validation "
    "text, excluding test records. These controls are regression-tested but do not exclude shared CVE identities or control "
    "for whether the underlying LLMs were exposed to any of these CVE fix commits during their own "
    "pretraining, which is unknown and out of scope to verify.")
figure("chart_splits.png", 150, "Train/validation/test partition sizes.")
tnum("Dataset partitions and their role in the experimental protocol.")
table(["Partition", "Size", "Role"],
      [["Training", f"{ds['splits'].get('train', '-'):,}" if ds.get('splits') else "-", "In-context (few-shot) exemplars."],
       ["Validation", f"{ds['splits'].get('val', '-'):,}" if ds.get('splits') else "-", "Prompting-strategy selection (never used for reporting)."],
       ["Test", f"{ds['splits'].get('test', '-'):,}" if ds.get('splits') else "-", "Function-level evaluation; auxiliary benchmarks are separate."]],
      [34 * mm, 26 * mm, 110 * mm])
h2("3.4 Auxiliary benchmarks")
para(
    "Three focused benchmarks support the remaining categories, constructed and sampled independently "
    "of the main function-level split above; their results (Section 6.1) characterise these separate "
    "benchmarks, not the held-out vulnerability test set. Each malicious sample in the malware benchmark "
    "is drawn from a generator family; benign generators use overlapping APIs for legitimate purposes, without recorded one-to-one twins. All malware samples "
    "are inert synthetic fixtures with non-routable placeholder endpoints and were never executed; "
    "templated generation produces exact-text uniqueness across samples but the templates and decorative "
    "variants are correlated in structure, which is a weaker property than genuine semantic diversity "
    "and is not claimed as such.")
tnum("Auxiliary benchmark sizes.")
table(["Benchmark", "Size generated", "Design note"],
      [["Malware", f"{D['benchmarks'].get('malware_benchmark','-')} samples", "Synthetic malicious and benign generators; no recorded one-to-one twin pairing. See 6.1 for evaluated counts."],
       ["Secrets", f"{D['benchmarks'].get('secrets_benchmark','-')} samples", "Real-looking secrets vs. placeholders/test fixtures; synthetic credentials, not live-credential validity."],
       ["Dependencies", f"{D['benchmarks'].get('deps_benchmark','-')} manifests", "Pins compared against the same advisory database (OSV) used to build the baseline — see 6.1."]],
      [34 * mm, 34 * mm, 102 * mm])

h2("3.5 Label quality audit")
para(
    "Section 3.1 notes that hash verification checks reconstruction fidelity, not the truth of the "
    "vulnerability label. That risk was measured, not assumed away, on a sample of 50 vulnerable-"
    "labelled functions drawn by <b>diversity-oriented round-robin sampling</b> across language and CWE "
    "category (seed 42) — a sampling design chosen to expose the review to varied cases, which means the "
    "resulting rates describe <b>this sample</b>, not an unweighted, corpus-wide label-noise estimate. "
    "The sample covers vulnerable-labelled (<code>pre</code>) functions with a paired post-fix "
    "counterpart only; negative-labelled functions and any function whose pair was orphaned by "
    "deduplication were not reviewed and are not covered by this audit.")
para(
    "Two passes reviewed the same 50 cards against the function code, the fix diff, and the CVE "
    "description: the author, applying MITRE's CWE mapping guidance directly, and a separate LLM "
    "external to every model under evaluation in this study. These are reported as a primary and a "
    "secondary review pass, not as independent blinded raters: the author's pass was conducted on cards "
    "for which an LLM-generated verdict already existed, and the timing and blinding of that pass "
    "relative to seeing the LLM's verdicts were not recorded, so no blinding claim is made. Verdicts: "
    "<i>Correct</i> (label and CWE both right), <i>Wrong CWE</i> (genuinely vulnerable, weakness category "
    "not the best fit), <i>Not actually vulnerable</i> (the sampled function is not itself the site of "
    "the flaw), or <i>Unclear</i> (the visible diff cannot establish the label either way).")
if lrv:
    hc = lrv.get("counts", {}).get("human", {}); lc = lrv.get("counts", {}).get("llm", {})
    n50 = lrv.get("n_shared", 50)
    tnum("Label-review verdicts on 50 round-robin-sampled cases: primary (human) versus secondary "
         "(LLM-based) review pass.")
    table(["Verdict", f"Human (n={n50})", f"LLM (n={n50})"],
          [["Correct", f"{hc.get('CORRECT',0)}  ({hc.get('CORRECT',0)/n50:.0%})", f"{lc.get('CORRECT',0)}  ({lc.get('CORRECT',0)/n50:.0%})"],
           ["Wrong CWE", f"{hc.get('WRONG_CWE',0)}  ({hc.get('WRONG_CWE',0)/n50:.0%})", f"{lc.get('WRONG_CWE',0)}  ({lc.get('WRONG_CWE',0)/n50:.0%})"],
           ["Not actually vulnerable", f"{hc.get('NOT_VULNERABLE',0)}  ({hc.get('NOT_VULNERABLE',0)/n50:.0%})", f"{lc.get('NOT_VULNERABLE',0)}  ({lc.get('NOT_VULNERABLE',0)/n50:.0%})"],
           ["Unclear", f"{hc.get('UNCLEAR',0)}  ({hc.get('UNCLEAR',0)/n50:.0%})", f"{lc.get('UNCLEAR',0)}  ({lc.get('UNCLEAR',0)/n50:.0%})"]],
          [66 * mm, 52 * mm, 52 * mm])
    figure("chart_label_noise.png", 150, "Label-review verdict breakdown, human (primary) versus "
           "LLM-based (secondary) review pass, on the 50 round-robin-sampled cards.")
    noise = hc.get("NOT_VULNERABLE", 0) / n50
    cwe_err = (hc.get("NOT_VULNERABLE", 0) + hc.get("WRONG_CWE", 0)) / n50
    para(
        f"On the human (primary) pass, <b>{noise:.0%}</b> of these 50 sampled cases are not actually "
        f"vulnerable, and <b>{cwe_err:.0%}</b> combine that with wrong-CWE cases into a broader CWE-error "
        "rate. These are unweighted rates over a diversity-sampled, not randomly-drawn, set of 50 cases "
        "and are reported descriptively rather than with a corpus-wide confidence interval, since the "
        "sampling design does not support one. Reviewer notes indicate the dominant source of the "
        "\"not actually vulnerable\" cases is functions from files that merely accompany a fix commit — "
        "most often test files — rather than random labelling error.")
    if lrd:
        tnum("Human/LLM inter-rater agreement on the same 50 cards, with an explicit treatment of "
             "the Unclear verdict.")
        table(["Agreement measure", "Value", "n"],
              [["Exact four-way match (Correct / Wrong CWE / Not vulnerable / Unclear)",
                f"{lrd['exact_4way_agreement']:.0%}", str(lrd["n_shared"])],
               ["Three-way match, Unclear kept as its own category (vulnerable / not-vulnerable / unclear)",
                f"{lrd['three_way_agreement_incl_unclear']:.0%}", str(lrd["n_shared"])],
               ["Binary vulnerable-vs-not, restricted to cases where NEITHER rater said Unclear",
                f"{lrd['binary_agreement_excluding_unclear_either_rater']['rate']:.0%}" if lrd['binary_agreement_excluding_unclear_either_rater']['rate'] is not None else "-",
                str(lrd['binary_agreement_excluding_unclear_either_rater']['n'])],
               ["Cohen's kappa (four-way)", f"{lrd['cohen_kappa_4way']:.2f}", str(lrd["n_shared"])]],
              [110 * mm, 30 * mm, 30 * mm])
        rev = lrd.get("direction_reversal_cells", [])
        rev_txt = ("the disagreements cannot be reduced to a single direction: one card is human Unclear / "
                   "LLM Not actually vulnerable, and another is human Wrong CWE / LLM Unclear")
        para(
            f"Agreement is strongest where it matters most: excluding the "
            f"{50 - lrd['binary_agreement_excluding_unclear_either_rater']['n']} cases where either rater "
            "answered Unclear, the two passes agree on vulnerable-vs-not-vulnerable in "
            f"<b>{lrd['binary_agreement_excluding_unclear_either_rater']['rate']:.0%}</b> of the remaining "
            f"{lrd['binary_agreement_excluding_unclear_either_rater']['n']} cases. Treating Unclear as its "
            f"own third category over all 50 cases, agreement falls to {lrd['three_way_agreement_incl_unclear']:.0%}; "
            f"the full four-way exact match (which additionally requires CWE-category agreement) is "
            f"{lrd['exact_4way_agreement']:.0%} (Cohen's kappa = {lrd['cohen_kappa_4way']:.2f}, moderate). "
            "In most disagreement cells the human pass is stricter than the LLM pass (downgrading a "
            f"case the LLM called Correct), but this is not universal: {rev_txt}. CWE-category correctness "
            "is accordingly reported as a materially softer, more contestable property of this dataset "
            "than whether a function is vulnerable at all, and the two should not be collapsed into one "
            "label-quality number.")



# ==================================================== 4 METHOD
h1("4. System Architecture and Methodology")
h2("4.1 Analysis pipeline")
para(
    "The system performs repository acquisition, file triage, per-analyser dispatch and evidence-"
    "weighted risk aggregation. File triage is static-guided: a fast Semgrep pass reorders the file "
    "queue so that the bounded LLM budget is spent on the most security-relevant files first — Section "
    "6.3 explains why historical selection coverage under the 25-file budget cannot be reliably reconstructed. "
    "Findings are assigned an evidence tier — (A) deterministic fact, (B) corroborated by two "
    "independent methods, (C) unverified model opinion — and by design only tier-A evidence may produce "
    "a clone-unsafe verdict. This is a design choice intended to make false clone-unsafe verdicts rare; "
    "it is not a proof that bounds the false-positive rate, since tier-A detectors are themselves pattern "
    "matchers that can misfire (Section 7.1), and the trusted-repository corpus used to check this was "
    "reused repeatedly during detector development rather than held out.")
h2("4.2 Prompting strategies and calibration")
para(
    "Four prompting strategies are considered: zero-shot, few-shot, an eight-step chain-of-thought "
    "checklist, and dataflow (source–sink) tracing. Because the optimal strategy is model-dependent "
    "and cannot be chosen on the target repository (where ground truth is absent), it is selected on "
    "the validation split by measured F1 for interactive audits. The reported historical experiment instead compared two fixed strategies on the test subset; it does not validate all four strategies or a validation-selected winner.")
h2("4.3 Evaluation metrics")
para(
    "Binary detection is reported using precision, recall, F1, balanced accuracy and the Matthews "
    "Correlation Coefficient (MCC). Given the roughly 1:6 class imbalance in the vulnerability test set "
    "(Section 6.2), raw accuracy and F1 alone are shown to be poor summaries — a trivial always-negative "
    "predictor scores highly on accuracy while scoring zero on F1 — so MCC and balanced accuracy are "
    "treated as the primary skill indicators for that task specifically.")
h2("4.4 Statistical protocol")
para(
    "Point estimates are accompanied by 95% confidence intervals from percentile bootstrap resampling. "
    "For the vulnerability task, an additional repository-cluster bootstrap is used (resampling whole "
    "repositories rather than individual functions) to account for correlated errors among functions "
    "drawn from the same codebase — the ordinary per-function bootstrap in the original edition did not "
    "account for this clustering and is superseded by the cluster version wherever both are available "
    "(Section 6.2). Paired model and strategy comparisons use the exact McNemar test, applied to <b>"
    "prediction correctness (accuracy), not to F1</b>, over the shared set of items with unambiguous "
    "sample identity; Holm–Bonferroni correction is applied across the full family of comparisons "
    "actually run. A non-significant result is reported as exactly that — insufficient evidence of a "
    "difference at the tested sample size — not as evidence of equivalence.")
para("To assess dependence in the paired tests as well, a post-hoc randomisation sensitivity swaps "
     "the two systems' labels jointly within each repository, preserving its correlated errors. "
     "The absolute accuracy difference is compared with 10,000 random repository-level swaps "
     "(seed 42, plus-one Monte Carlo p-value), followed by Holm adjustment across six comparisons. "
     "This assumes exchangeability of system labels within independent repository blocks under the null; "
     "it does not remove label noise, selection bias or cross-repository similarities.")

# ==================================================== 5 SETUP
h1("5. Experimental Setup")
tnum("Models and baselines under evaluation.")
table(["System", "Provider / type", "Role"],
      [["Qwen2.5-Coder 7B", "Alibaba (local, GPU)", "LLM under test — free, unmetered"],
       ["Gemini Flash Lite", "Google (cloud)", "LLM under test — free tier, daily quota"],
       ["GuardDog (installed rule subset)", "Datadog (YARA)", "Malware baseline — not the full package scanner"],
       ["Gitleaks", "Signature (regex)", "Secrets baseline"],
       ["OSV lookup", "Database oracle", "Dependency baseline — shares its advisory source with the benchmark's own ground truth (6.1)"]],
      [50 * mm, 50 * mm, 70 * mm])
para(
    "Local inference was executed on a single consumer GPU (NVIDIA RTX 4050, 6 GB). All model responses "
    "are cached by content hash, so re-running the same configuration replays saved outputs rather than "
    "producing new stochastic samples — this makes the pipeline resumable and reproducible in the "
    "narrow sense of returning the same numbers, but the reported figures are a single realised sample "
    "of model behaviour, not repeated independent trials. Exact model snapshot identifiers/timestamps "
    "for the cloud model, the installed GuardDog rule-set revision, and the exact code version in use at "
    "the time of each historical run were not all recorded, and the application code has changed since "
    "these experiments ran (Section 9); these results should be read as a frozen historical record, not "
    "as guaranteed to reproduce bit-for-bit from the current codebase. Results in this report reflect a "
    "medium-scale protocol (600 raw vulnerability items per configuration, of which 582 have unambiguous "
    "sample identity — Section 6.2; 300 items per auxiliary benchmark, subject to the same-evaluated-"
    "count caveats in Section 6.1).")



# ==================================================== 6 RESULTS
h1("6. Results")
h2("6.1 Cross-category comparison")
para(
    "The following table and chart report descriptive F1 for the best-observed LLM configuration against each "
    "category's baseline. No paired significance test was computed for malware, secrets or dependencies "
    "(the vulnerability model/strategy comparisons in Section 6.2 have one), "
    "so differences in this table are reported as observed point estimates, not as tested claims of "
    "superiority.")
tnum("Best-observed LLM configuration vs. specialist baseline, by threat category (descriptive).")
mal_llm = max((v for k, v in mal_rows.items() if k != "guarddog_yara"), key=lambda e: e.get("f1", 0), default={})
mal_base = mal_rows.get("guarddog_yara", {})
sec_llm = max((v for k, v in sec_rows.items() if k != "gitleaks"), key=lambda e: e.get("f1", 0), default={})
sec_base = sec_rows.get("gitleaks", {})
dep_llm = max((v for k, v in dep_rows.items() if k != "osv_lookup"), key=lambda e: e.get("f1", 0), default={})
dep_base = dep_rows.get("osv_lookup", {})


def pr_str(e):
    if all(k in e for k in ('tp', 'fp', 'fn')):
        tp, fp, fn = (e[k] for k in ('tp', 'fp', 'fn'))
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0
        return f"{precision:.3f} / {recall:.3f} / {f1:.3f}"
    return f"{e.get('precision', 0):.3f} / {e.get('recall', 0):.3f} / {e.get('f1', 0):.3f}"


table(["Category", "Baseline (P / R / F1)", "LLM best (P / R / F1)", "Outcome (descriptive)"],
      [[Paragraph("<b>Malware</b>", CELL), pr_str(mal_base), Paragraph(f"<b>{pr_str(mal_llm)}</b>", CELL),
        "Higher F1, but recall below baseline; baseline = installed rule subset on synthetic snippets, no significance test"],
       [Paragraph("<b>Secrets</b>", CELL), pr_str(sec_base), pr_str(sec_llm), "Baseline F1 higher; LLM higher recall, lower precision"],
       [Paragraph("<b>Dependencies</b>", CELL), pr_str(dep_base), pr_str(dep_llm), "Oracle far exceeds LLM (in-corpus oracle, see note below)"],
       [Paragraph("<b>Vulnerabilities</b>", CELL), "—", "see Section 6.2 (582-row sensitivity set)", "Weak; below trivial baseline on raw accuracy (6.2)"]],
      [28 * mm, 42 * mm, 46 * mm, 54 * mm])
figure("chart_results.png", 150,
       "F1 by threat category: specialist baseline/oracle (grey) versus best-observed LLM configuration "
       "(green). Descriptive; see text for recall and significance caveats.")
n_mal_eval = sum(mal_base.get(k, 0) for k in ("tp", "fp", "tn", "fn"))
para(
    f"The malware result is directionally positive on F1 (0.898 vs. 0.772) but the LLM's recall (0.819) "
    f"is <b>below</b> the baseline's (0.852); precision is where the LLM configuration gains. The baseline "
    "here is only the YARA rules installed locally, not GuardDog's full package-reputation scanner, and "
    "the installed rule-set's version/revision was not recorded historically, so this is a rule-subset "
    f"comparison, not a claim about GuardDog's real-world capability. {n_mal_eval} of the "
    f"{D['benchmarks'].get('malware_benchmark', '?')} generated malware samples were actually scored "
    "(the remainder were generated but not included in this evaluation run); template-based generation "
    "gives exact-text uniqueness but correlated structure across variants, which is a weaker property "
    "than semantic diversity. The specific configuration reported as \"best\" (zero-shot over a triage "
    "variant) was chosen by comparing evaluation-set results directly, which is exploratory model "
    "selection, not a validation-set-calibrated choice as used for the vulnerability task (Section 4.2). "
    "For dependencies, the OSV baseline and the benchmark's own ground-truth labels are both derived from "
    "OSV advisory data, so its near-perfect score demonstrates internal consistency with its own source, "
    "not proof that a live OSV lookup would catch every real-world vulnerable dependency. For secrets, the "
    "synthetic credentials used here measure pattern detection, not whether a flagged string is a live, "
    "exploitable credential.")

h2("Dependency prompting strategies")
tnum("Dependency extraction by model and strategy (300 manifests; 4,243 listed entries). The last column additionally counts unlisted package predictions as false positives.")
dependency_rows = []
for entry in D["results"].get("deps", []):
    if entry["model"] == "osv_lookup":
        continue
    tp, fp, fn = entry["tp"], entry["fp"], entry["fn"]
    hallucinations = entry["hallucinated_packages"]
    adjusted = 2*tp/(2*tp+fp+fn+hallucinations) if 2*tp+fp+fn+hallucinations else 0
    dependency_rows.append([entry["model"], entry["strategy"], f"{entry['f1']:.3f}", str(hallucinations), f"{adjusted:.3f}"])
table(["Model", "Strategy", "Listed-entry F1", "Unlisted predictions", "All-reported F1"], dependency_rows,
      [44*mm,30*mm,32*mm,32*mm,32*mm])
para("The historical dependency F1 excluded invented package names from its false-positive count. "
     "The additional all-reported F1 above includes those names and makes that omission visible. "
     "Qwen's chain-of-thought run reports 329 unlisted packages versus 14 for zero-shot (23.5 times as many), "
     "while improving listed-entry F1 from 0.020 to 0.108. Its all-reported F1 is approximately 0.087. "
     "The two Gemini configurations each have one unlisted prediction. These are descriptive aggregate "
     "comparisons; no manifest-cluster significance test is claimed.")

h2("6.2 Vulnerability detection: model and strategy analysis")
para(
    "The original 600-row-per-configuration evaluation was reanalysed against the raw prediction logs. "
    "Of the 600 rows per configuration, 18 share a sample identity with another row (the scoring "
    "dictionary keys on sample ID, and duplicate IDs silently overwrite each other), leaving <b>582 rows "
    "with unambiguous identity</b> per configuration. The excluded 18 cannot be attributed back to a "
    "specific original prediction with confidence, so they are dropped rather than guessed at; this "
    "changes point estimates only slightly (the following table) but is the set used for the cluster-bootstrap "
    "confidence intervals below, since a valid cluster (repository) grouping requires unambiguous rows.")
tnum("Vulnerability detection, historical 600-row descriptive figures alongside the 582-row unambiguous "
     "sensitivity reanalysis with 95% repository-cluster bootstrap CIs (167 repository clusters).")
rows = []
order = sorted(vuln.items(), key=lambda kv: -kv[1]["metrics"]["f1"])
for name, e in order:
    disp = name.replace("local-qwen-coder", "Qwen2.5-Coder").replace("gemini-flash", "Gemini").replace("/", " · ")
    m = e["metrics"]; hm = e["historical_metrics"]; cb = e["cluster_bootstrap"]
    rows.append([Paragraph(disp, CELL),
                 f"{hm['f1']:.3f} (n=600)",
                 f"{m['f1']:.3f} (n=582)",
                 f"[{cb['f1']['ci_low']:.3f}, {cb['f1']['ci_high']:.3f}]",
                 f"{m['mcc']:.3f}\n[{cb['mcc']['ci_low']:.3f}, {cb['mcc']['ci_high']:.3f}]",
                 f"{m['accuracy']:.3f}"])
table(["Model · strategy", "Historical F1", "Sensitivity F1", "F1 95% cluster-CI", "MCC [95% cluster-CI]", "Accuracy"],
      rows, [40 * mm, 24 * mm, 24 * mm, 30 * mm, 30 * mm, 20 * mm])
ag_acc = vuln.get(order[0][0], {}).get("always_negative_accuracy", 0.818)
para(
    f"A trivial classifier that always predicts \"safe\" scores <b>{ag_acc:.1%} accuracy</b> on this same "
    "582-row set — higher than every tested model/strategy configuration's raw accuracy (58–64%) — while "
    "scoring F1 = 0, since it recovers no true positives at all. This is why accuracy is not used as the "
    "headline skill metric for this task: on an imbalanced set, a model can score below a content-free "
    "baseline on accuracy while still doing genuinely better than chance at the thing that matters "
    "(finding the vulnerable functions), which is what MCC and balanced accuracy are designed to "
    "reflect. All four configurations show a small positive MCC (0.06–0.10 point estimate); the cluster-"
    "bootstrap CIs for MCC include values close to zero for three of the four configurations, so this "
    "should be read as \"modest estimated discrimination with substantial uncertainty\" rather than a strong capability claim.")
tnum("Pairwise accuracy comparisons (exact McNemar on 582 shared items), raw and Holm-corrected p-values "
     "shown separately across all six comparisons actually run.")
prows = []
for key, e in pw.items():
    disp = key.replace("local-qwen-coder", "Qwen").replace("gemini-flash", "Gemini")
    sig = "significant (Holm)" if e.get("p_holm", 1) < 0.05 else "not significant (Holm)"
    prows.append([Paragraph(disp, CELL), f"{e['accuracy_a']:.3f}", f"{e['accuracy_b']:.3f}",
                  f"{e['p_raw']:.5f}", f"{e['p_holm']:.5f}", sig])
table(["Comparison (A vs. B)", "Acc. A", "Acc. B", "p (raw)", "p (Holm, m=6)", "Result"],
      prows, [58 * mm, 18 * mm, 18 * mm, 24 * mm, 26 * mm, 26 * mm])
tnum("Repository-level permutation sensitivity for paired accuracy (10,000 swaps, 167 repository blocks; Holm family size six).")
cluster_rows = []
for key, entry in pw.items():
    perm = entry["repository_permutation"]
    cluster_rows.append([key.replace("local-qwen-coder", "Qwen").replace("gemini-flash", "Gemini"),
                         f"{perm['accuracy_difference']:+.3f}", f"{perm['p_value']:.4f}", f"{perm['p_holm']:.4f}"])
table(["Comparison (A vs. B)", "Accuracy A-B", "p (block swap)", "p (Holm)"],cluster_rows,[84*mm,30*mm,28*mm,28*mm])
para("The Qwen zero-shot versus chain-of-thought contrast remains significant under the repository-block "
     "sensitivity (raw p = 0.0047, adjusted p = 0.0282); the other five comparisons do not. "
     "This is evidence under the stated resampling assumptions, not a universal prompting effect.")
para(
    "Only one of six comparisons survives Holm correction across the full family actually tested: "
    "chain-of-thought <b>significantly reduces</b> Qwen2.5-Coder's accuracy relative to its own zero-shot "
    "baseline (p<sub>raw</sub> = 0.00045, p<sub>Holm</sub> = 0.0027). One further comparison (Qwen CoT vs. "
    "Gemini CoT) is significant at the uncorrected 0.05 threshold (p<sub>raw</sub> = 0.048) but is not "
    "significant once corrected for testing six hypotheses (p<sub>Holm</sub> = 0.24) — reporting only the "
    "raw value here would have been misleading. McNemar tests prediction <i>accuracy</i>, not F1; it does "
    "not test whether two configurations are practically equivalent, and the absence of a significant "
    "difference in the other five comparisons is reported as inconclusive at this sample size, not as "
    "evidence that the compared configurations perform the same.")

h2("6.3 Historical repository-level evaluation")
para(
    "60 repository/CVE cases were attempted by downloading fix commits and reverse-applying the patches; 56 cases were "
    "verified by function hash, and scanned by the deployed pipeline (with its static-guided file "
    "triage) under a bounded 25-file budget. A later audit of the evaluation harness found that the "
    "historical <i>selected</i> field — whether the scanner looked at the vulnerable file — was "
    "recomputed after the fact using a plain file walk, <b>without</b> the triage ordering the deployed "
    "scanner actually applies; two of the 56 verified cases are recorded as detected without being "
    "recorded as selected, which is only possible if the selection trace is wrong. <b>The file-selection "
    "rate and the detection-given-selection rate reported in the original edition are therefore "
    "withdrawn</b> as invalid operational measures; they are not repeated here.")
if rb:
    r = rb.get("rates", {})
    tnum(f"Repository-level results that remain valid as descriptive counts (n = {rb.get('n_cases', 56)} "
         f"verified cases across {rb.get('n_repositories', '?')} distinct repositories; 95% CIs are "
         "Wilson intervals for a binomial proportion).")
    def _row(label, e):
        return [label, f"{e['successes']}/{e['n']}", f"{e['point']:.1%}", f"[{e['ci_low']:.1%}, {e['ci_high']:.1%}]"]
    table(["Outcome (descriptive count, no causal file-selection claim)", "Count", "Rate", "95% CI"],
          [_row("Vulnerability finding recorded in the true target file", r.get("detected", {})),
           _row("Historical function-name localisation proxy", r.get("localised", {})),
           _row("Strict CWE match", r.get("cwe_strict", {}))],
          [92 * mm, 22 * mm, 22 * mm, 34 * mm])
    para(
        f"With {rb.get('n_cases', 56)} cases drawn from only {rb.get('n_repositories', '?')} distinct "
        "repositories, some repositories contribute more than one case, so these counts are not fully "
        "independent trials either; the Wilson intervals above treat them as such and should be read as "
        "approximate. No claim is made here about why a file was or was not scanned, since that trace is "
        "the part found to be unreliable. A structural, non-LLM control run exists but covered only 7 of "
        "the 60 benchmark cases with 0 detections; at that sample size this is consistent with, but does "
        "not establish, any particular detection rate for a non-LLM baseline, and no causal conclusion is "
        "drawn from it.")

h2("6.4 Reanalysis summary")
tnum("Original claim versus the corrected finding from this audit, by area (see the Provenance Appendix "
     "for the source file and exact figures cited).")
table(["Area", "Original claim", "Revised finding"],
      [["Vulnerability model comparison", "Models \"statistically indistinguishable\" (p = 0.14), F1 approximately  0.30 headline",
        "582/600 unambiguous rows used; raw accuracy is below a trivial always-negative baseline (81.8%); MCC/balanced accuracy are the supported skill metrics; only 1 of 6 Holm-corrected comparisons is significant"],
       ["Repository benchmark", "\"85.7% detection given selection\", \"25.0% file-selection rate\"",
        "Selection trace invalid (computed without triage); both rates withdrawn. Valid descriptive counts retained: 14/56 detected, 7/56 localised, 3/56 CWE-matched, 48 repositories"],
       ["Malware", "LLM \"significantly outperforms\" the signature baseline",
        "Higher observed F1 but lower recall than baseline; no significance test computed; baseline is a rule subset, not the full scanner; claim of outperformance removed"],
       ["Label-quality audit", "\"Independent\" human review; \"every disagreement has the same direction\"",
        "Timing/blinding unverified; disagreements are not uniformly directional; agreement restated with an explicit Unclear treatment"],
       ["Dataset construction", "\"Self-validating\", \"authoritative\" labels; \"negligible\" label noise",
        "Hash verification checks reconstruction, not vulnerability truth; label noise is measured (24% on the sampled cards) and not assumed negligible"],
       ["Splits / leakage", "\"Lexically similar functions cannot straddle the split\"",
        "True only for exact (whitespace-normalised) duplicates; near-duplicate independence unverified; 4 train/test and 1 train/val CVE-ID overlaps found"],
       ["Trusted-repository corpus", "\"Bounds the false-positive rate by construction\"",
        "Corpus was reused for detector tuning (development set, not held-out); an illustrative i.i.d. one-sided 95% upper bound of approximately 8.2% is reported but explicitly not a generalisation guarantee"],
       ["Obfuscation experiment", "\"Semantics-preserving obfuscation\"",
        "Regex-based textual perturbation (including Python-specific constructs applied across languages); semantic equivalence unverified; renamed \"textual perturbation\""]],
      [30 * mm, 62 * mm, 78 * mm])

h2("6.5 Post-hoc validity controls")
para(
    "Further checks were run against saved data and current code, with no re-execution of "
    "historical model calls. The table below summarises them; the provenance and reproduction entry points are in Appendix A.")
tnum("Post-hoc validity controls: what was checked, the result, and its status.")
ai_ck = A.get("auxiliary_identity_checks", {})
mal_ck = ai_ck.get("malware_predictions.jsonl", {}).get("shared_ids", {})
clean_pairs = sum(1 for v in mal_ck.values() if v == 300) if mal_ck else 0
table(["Check", "Result", "Status"],
      [["Near-duplicate screen, test vs. train/val (token-shingle Jaccard &gt;= 0.85)",
        f"{vc.get('fuzzy_screen', {}).get('n_test_with_candidate', '?')} of "
        f"{vc.get('fuzzy_screen', {}).get('n_test_eligible', '?')} test functions flagged",
        "Completed; heuristic candidates, not confirmed duplicates"],
       ["Syntax validity of historical obfuscation transform (AST parse only)",
        "52/70 malicious and 20/21 benign Python samples became syntactically invalid",
        "Completed; severe defect, see 7.3"],
       ["Prospective literal-splitting perturbation fixtures (AST-equality checked)",
        f"{pv2.get('python_validated', '?')} Python fixtures validated, "
        f"{pv2.get('syntax_rejected', '?')} rejected, {pv2.get('unsupported_language', '?')} "
        "non-Python unsupported",
        "Evaluated in follow-up run (Section 10.1)"],
       ["Prediction-identity pairing, malware/secrets/deps (duplicate IDs, shared IDs across configs)",
        f"0 duplicates, {clean_pairs} of {len(mal_ck)} malware config-pairs fully shared (n=300 each)"
        if mal_ck else "see audit.json",
        "Completed; confirms pairing is clean, no significance test computed yet (Section 10)"],
       ["Vulnerability-metric sensitivity to excluding test/example/fixture paths and dev-seen CVEs",
        "F1/MCC/accuracy shift by no more than a few points across all four configurations (the sensitivity "
        "figures; see audit.json posthoc_exclusion_sensitivity)",
        "Completed; exploratory robustness check, not a prespecified analysis"]],
      [58 * mm, 66 * mm, 46 * mm])



# ==================================================== 7 ROBUSTNESS
h1("7. Robustness and Interpretability")
h2("7.1 Trusted-repository corpus")
para(
    "The deterministic clone-safety analyser was evaluated on a corpus of 35 widely used repositories "
    "(e.g. Flask, Django, curl). This corpus was reused repeatedly during detector development to fix "
    "specific over-eager heuristics (Section 9), so it functions as a <b>development/regression set</b>, "
    "not a held-out test of generalisation, and the result below should be read accordingly.")
figure("chart_fp.png", 145, "Clone-unsafe verdicts on the trusted-repository development/regression "
       "corpus: none were produced, on the set used to tune the detectors.")
if tc:
    para(
        f"Zero of {tc.get('n_repos', 35)} repositories produced a clone-unsafe verdict; "
        f"{tc.get('repos_with_any_supply_alarm', '?')} produced at least one lower-severity supply-chain "
        f"alarm (mean {tc.get('mean_supply_alarms', 0):.2f} alarms per repository) that did not escalate "
        "to a clone-unsafe verdict. Treating this set as if it were i.i.d. and held-out (which it is not) "
        f"gives an illustrative one-sided 95% upper bound on a future false-clone-unsafe rate of "
        f"approximately {tc.get('one_sided_95_upper_if_iid_zero_failures', 0.082):.1%}; this bound is reported for "
        "context only and is not a generalisation guarantee, since the i.i.d./held-out assumptions behind "
        "it do not hold for a repeatedly-reused tuning set.")
h2("7.2 Explanation grounding")
para(
    "LLMs, unlike signature tools, emit natural-language justifications. An automated rubric checks "
    "whether code identifiers cited in an explanation actually occur in the analysed function — an "
    "identifier-overlap heuristic, which measures textual grounding, not causal faithfulness (whether "
    "the cited identifiers are the actual reason for the verdict) or explanation correctness.")
if interp:
    tnum("Explanation-grounding rubric results (local-qwen-coder only; no equivalent run exists for "
         "gemini-flash in the underlying results).")
    irows = [[e["strategy"], str(e["n_findings"]), f"{e['grounded']:.3f}" if e["grounded"] is not None else "-",
              f"{e['hallucination_rate']:.1%}" if e["hallucination_rate"] is not None else "-"]
             for e in interp.get("per_strategy", [])]
    table(["Strategy", "n findings", "Grounded (mean)", "Explanations with a non-existent identifier"],
          irows, [40 * mm, 30 * mm, 40 * mm, 60 * mm])
    gw = interp.get("grounded_weighted_mean"); hr = interp.get("hallucination_rate_overall")
    para(
        f"Across both strategies, mean grounding is {gw:.2f} and {hr:.1%} of explanations reference at "
        "least one identifier not present in the analysed function. This is measured for one model only; "
        "no equivalence or superiority claim is made across vendors for explanation quality.")
h2("7.3 Historical textual adversarial perturbation")
para(
    "Malicious malware samples were perturbed with regex-based string encoding, API-name splitting and "
    "identifier renaming (some of these transforms are Python-specific and were applied across all "
    "languages in the benchmark regardless), and both detectors were re-evaluated. Because the "
    "transforms are textual substitutions rather than AST-aware, semantics-preserving rewrites, "
    "behavioural equivalence between the original and perturbed code was <b>not</b> verified; this is "
    "reported as a textual perturbation experiment, not a proof of evasion under preserved behaviour.")
figure("chart_evasion.png", 145, "Malware detection before and after textual perturbation.")
if ev:
    g = ev.get("guarddog_yara", {}); llm = ev.get("llm", {}); bc = llm.get("benign_obfuscation_control", {})
    para(
        f"The signature baseline's detection fell from {g.get('detection_original', 0):.0%} to "
        f"{g.get('detection_obfuscated', 0):.0%} after perturbation. The LLM's apparent detection on "
        f"malicious samples rose to {llm.get('detection_obfuscated', 0):.0%}, but a control on perturbed "
        f"<b>benign</b> code (n = {bc.get('n', 25)}) shows its false-positive rate rose from "
        f"{bc.get('false_positive_original', 0):.0%} to {bc.get('false_positive_obfuscated', 0):.0%} over "
        "the same transforms — the LLM appears to key on the presence of perturbation itself rather than "
        "reading through it. Only aggregate rates for this benign control were saved historically, not "
        "item-level outcomes, which limits independent re-verification of exactly which samples flipped.")
spa = vc.get("syntax_only_perturbation_audit", {})
if spa:
    mal_a = spa.get("malicious_80", {}); ben_a = spa.get("benign_25", {})
    para(
        "A subsequent AST-parse-only audit of the historical obfuscator, reproducing its saved "
        "level/seed procedure without executing anything, found a severe structural defect: of "
        f"{mal_a.get('original_parseable', '?')} originally parseable Python malicious samples, only "
        f"{mal_a.get('transformed_parseable', '?')} remained parseable after transformation "
        f"({mal_a.get('parseable_original_became_invalid', '?')} became syntax errors); of "
        f"{ben_a.get('original_parseable', '?')} parseable Python benign controls, only "
        f"{ben_a.get('transformed_parseable', '?')} remained parseable "
        f"({ben_a.get('parseable_original_became_invalid', '?')} became syntax errors). <b>Most "
        "historical \"obfuscated\" Python detections and false positives above were therefore measured "
        "against text that was not valid Python at all</b>, not against working perturbed code; source "
        "hashes were not saved historically, so this audits the current implementation reproducing the "
        "documented procedure, not a byte-identical replay. This further supports withdrawing any "
        "\"behaviour-preserving\" or \"semantics-preserving\" framing for this experiment, and means the "
        "detection/false-positive rates above should be read as measurements on this specific, largely "
        "syntactically-broken transform, not on adversarial code that remains valid.")
notebox(
    "<b>Historical malformed-perturbation finding.</b> Textual perturbation "
    "degrades both detector families, in opposite directions: the signature tool loses recall, the LLM "
    "loses precision on the paired benign control. Neither is shown to be robust under this specific, "
    "unverified-semantics perturbation; no claim is made about robustness under semantics-preserving "
    "obfuscation more generally, since that property was not tested.")

# ==================================================== 8 DISCUSSION
h1("8. Discussion")
para(
    "The malware, secrets and dependency comparisons are informative about where LLM behaviour differs "
    "from each specialist baseline in this specific setup, but none rests on a computed significance "
    "test, and the malware and dependency baselines both have scope caveats (a rule subset; an in-corpus "
    "oracle) that limit how far the comparison generalises. For vulnerability detection specifically, the "
    "corrected picture is that raw accuracy is not a usable headline number for this class-imbalanced "
    "task — it is dominated by a content-free baseline — while MCC indicates modest, probably-non-chance "
    "skill, and only the within-model chain-of-thought effect for Qwen2.5-Coder survives correction for "
    "multiple comparisons. The evidence-tier design is best understood as a deliberate policy choice "
    "to gate consequential verdicts behind deterministic evidence, not as a proof that the resulting "
    "false-positive rate is bounded, since the corpus used to observe zero false clone-unsafe verdicts "
    "was also the corpus used to tune the detectors that produce them.")

# ==================================================== 9 LIMITATIONS
h1("9. Limitations and Threats to Validity")
for t in [
    "<b>Scale and sample identity.</b> The vulnerability evaluation is medium-scale (600 raw items per "
    "configuration), of which 582 have unambiguous sample identity; the 18 excluded rows cannot be "
    "recovered and are not claimed to be representative or unrepresentative of the excluded cases.",
    "<b>Pretraining contamination is unknown.</b> Repository- and hash-disjoint splits do not establish "
    "that a tested LLM never saw a given CVE fix commit during pretraining; this cannot be ruled out with "
    "the evidence collected here.",
    "<b>Near-duplicate independence is not established.</b> Only exact (whitespace-normalised) duplicate "
    "text is excluded across splits; near-duplicate leakage (renamed variables, reordered statements, "
    "cross-repository boilerplate) is screened heuristically in Section 6.5, but the candidates remain unadjudicated.",
    "<b>Model coverage and provenance.</b> The malware, evasion and interpretability results are "
    "established for one local LLM; a second-vendor confirmation is pending. Exact cloud-model snapshot "
    "identifiers, the installed GuardDog rule-set revision, and the application code version at the time "
    "of each historical run were not all recorded, and the current codebase has since changed — these "
    "are frozen historical measurements, and re-running the pipeline today is an engineering "
    "reproducibility check, not a re-validation of these specific research numbers.",
    "<b>Cached responses are not independent replicates.</b> Deterministic content-hash caching makes the "
    "pipeline resumable and exactly repeatable, but repeated runs against the cache return the same "
    "saved output rather than new stochastic samples of model behaviour.",
    "<b>Historical selection rates remain withdrawn</b> (Section 6.3); new instrumented rates are "
    "reported separately in Section 10.1. Historical detection/"
    "localisation/CWE-match counts are reported, and even those are drawn from 56 cases over 48 "
    "repositories, so some repositories contribute more than one non-independent case.",
    "<b>Label noise is measured on a non-random sample.</b> Section 3.5's round-robin diversity sample "
    "(n = 50) describes that sample, excludes negatives and orphaned positives, and its rates should not "
    "be extrapolated to a precise corpus-wide percentage.",
    "<b>The trusted-repository corpus is a development set.</b> Section 7.1's zero-false-positive result "
    "was observed on repositories reused during detector tuning; it is not a held-out generalisation test, "
    "and the accompanying illustrative statistical bound assumes i.i.d. sampling that does not hold here.",
    "<b>Obfuscation is textual, not verified-semantic.</b> Section 7.3's perturbations are regex "
    "substitutions, some language-mismatched, with unverified behavioural equivalence; a syntax-validity "
    "audit found severe syntax failures in this edition (Section 7.3); behavioural equivalence remains unverified.",
    "<b>Interpretability is a grounding heuristic.</b> Section 7.2 measures identifier overlap, not "
    "whether the cited identifiers causally explain the model's verdict."]:
    story.append(Paragraph("• " + t, BODY))

# ==================================================== 10 REMEDIES
h1("10. Completed vs. Pending Remedies")
para("The table separates repairs supported by this audit from validation that still requires new evidence.")
tnum("Status of each issue identified by the methodological audit: corrected in this revision using "
     "existing data, versus requiring new instrumentation or experiments not yet run.")
table(["Issue", "Status", "Note"],
      [["Vulnerability metrics contaminated by 18 duplicate-identity rows", "Completed (this revision)",
        "582-row unambiguous sensitivity set computed post-hoc from existing prediction logs"],
       ["Vulnerability CIs ignored within-repository correlation", "Completed (this revision)",
        "Repository-cluster bootstrap (167 clusters) added alongside the original per-function CIs"],
       ["Pairwise comparisons reported without full multiple-comparison correction", "Completed (this revision)",
        "All 6 pairwise comparisons now shown with raw and Holm-adjusted p-values"],
       ["Repository-benchmark selection trace computed without triage", "Completed follow-up run",
        "Actual trace recorded for 56 verified cases: 17 selected, 14 detected. Four reconstruction skips. See Section 10.1; historical rates remain withdrawn."],
       ["Near-duplicate (fuzzy) leakage across splits unverified", "Completed — heuristic screen run",
        "12 of 5,741 eligible test functions have a candidate near-duplicate in train/val (token-shingle Jaccard &gt;= 0.85); candidates are unconfirmed, not manually adjudicated"],
       ["Pretraining-contamination exposure unknown", "Pending — likely unresolvable with current tooling",
        "No reliable method to test what a closed-weight or opaquely-trained model saw during pretraining"],
       ["Malware/secrets/dependency comparisons lack significance tests", "Pending — prerequisite confirmed clean",
        "Prediction-identity pairing was audited and is clean (0 duplicate IDs, full ID overlap across compared configurations); the paired significance test itself is not yet computed"],
       ["Obfuscation semantic-equivalence unverified", "Completed (syntax-only) — severe defect found",
        "AST-parse audit of the historical transform: 52/70 malicious and 20/21 benign Python samples became syntactically invalid; full behavioural equivalence remains unverified and is a separate, larger undertaking"],
       ["Prospective literal-splitting perturbation instrument", "Completed restricted evaluation",
        "339 pairs evaluated by Qwen and 51 compiled YARA rules, no failed pairs. 312 pairs have AST changes. Broad robustness and unseen threats remain untested (Section 10.1)."],
       ["Prospective connected-component (repo+CVE+hash+pair) split", "Partially completed",
        "Assignment manifest computed with zero overlap on all four keys across 1,471 components; not applied to any historical result, and 5,685 test/example/fixture-path records are flagged for review, not relabelled"],
       ["Human label-review pass timing/blinding unrecorded", "Pending — needs a new review protocol",
        "A future review pass would need to record order and blinding explicitly to support an independence claim"],
       ["Trusted-repository corpus is a development, not held-out, set", "Pending — needs new data",
        "Requires a fresh, never-tuned-against repository sample to support a genuine generalisation claim"]],
      [66 * mm, 44 * mm, 60 * mm])
para("Completed repairs and post-hoc checks are distinguished above from pending validation. "
     "New held-out data, documented human review and instrumented detector runs are required "
     "before the corresponding claims can be extended.")

# Follow-up measurements are deliberately separate from historical estimates.
h2("10.1 Verified follow-up experiments: 15 September 2026")
para("Two completed runs now address the measurement and malformed-perturbation defects. "
     "They use existing benchmark data, not new held-out repositories or threat families. "
     "The historical results in Sections 6 and 7 remain unchanged; their invalid claims are not reinstated.")
F = D['followup_runs']
R = F['repo']; counts = R['counts']; n = R['summary']['n_cases']
tnum("Corrected repository trace: 60 attempted cases, four reconstruction skips, 56 scored cases across 48 repositories. Descriptive rates.")
table(['Measure','Count','Rate'], [
    ['Target-file selection',f"{counts['selected']}/{n}",f"{counts['selected']/n:.1%}"],
    ['Target-file detection',f"{counts['detected']}/{n}",f"{counts['detected']/n:.1%}"],
    ['Detection conditional on selection',f"{counts['detected']}/{counts['selected']}",f"{counts['detected']/counts['selected']:.1%}"],
    ['Exact-body localisation',f"{counts['localised']}/{n}",f"{counts['localised']/n:.1%}"],
    ['Strict CWE match',f"{counts['cwe_strict']}/{n}",f"{counts['cwe_strict']/n:.1%}"]], [95*mm,35*mm,40*mm])
para("The run uses Qwen zero-shot and the existing 25-file budget. Actual selected paths are now saved "
     "and no detection-without-selection violation occurs. The 82.4% conditional result describes this "
     "selected subset; it is not a randomised test proving that better ranking would recover missed flaws. "
     "Exact-body localisation uses a stricter definition than the historical name-based measure. "
     "The mean 31.68 off-target alarms per case remain unadjudicated review burden, not known false positives. "
     "The run took 1,485.4 seconds; cache reuse and implementation changes prevent treating this as a controlled speed comparison.")
para("The paired Python experiment includes 178 malicious and 161 benign samples. All 339 pairs "
     "completed for each detector without failed predictions. Of these, 312 contain an AST change; "
     "27 are formatting-only controls. Source hashes, labels and literal-folded AST equality were checked "
     "before evaluation. No sample was executed. This restricted static property does not cover source introspection or all observable behaviour.")
tnum("Paired Python results on all 339 samples: original versus transformed. Recall denominator is 178 malicious samples; false-positive denominator is 161 benign samples.")
rows=[]
for detector in ['local-qwen-coder','yara']:
    for arm in ['original','transformed']:
        v=F['perturbation']['summary'][detector]['all_complete_pairs'][arm]
        rows.append([detector,arm,f"{v['tp']}/178 ({v['recall']:.1%})",f"{v['fp']}/161 ({v['false_positive_rate']:.1%})",f"{v['f1']:.3f}"])
table(['Detector','Input','Malicious recall','Benign false positives','F1'],rows,[40*mm,27*mm,39*mm,42*mm,22*mm])
para("Qwen changes only two verdicts: one additional malicious sample is detected and one benign false "
     "alarm disappears. YARA changes no verdicts. On the 312 AST-changed pairs, all 178 malicious items "
     "remain included; Qwen benign false positives change from 1/134 to 0/134, and YARA remains at 63/134. "
     "Thus this literal-splitting transformation provides little challenge to either detector. "
     "Qwen has fewer false alarms on these synthetic cases, while YARA detects slightly more malicious items. "
     "These descriptive differences are not a significance test or a general adversarial-robustness conclusion.")
para("The baseline is YARA 4.5.4 with 51 of 54 installed rule files compiled; three compilation failures "
     "are recorded in the manifest, so scope remains a rule subset rather than the full GuardDog scanner. "
     "Qwen2.5-Coder:7b uses temperature 0 and an 800-token output budget. Of 678 model responses, 255 "
     "were cache hits; they are not independent inference replicates. Template dependence, synthetic labels "
     "and the absence of an independently held-out threat-family test limit generalisation.")
para("Run provenance: repository run <code>repo_bench_v2/20260915-022618</code>; paired run "
     "<code>perturbation_v2/20260915-025616</code>, both under <code>data/results/</code>. "
     "Each contains predictions, a summary and a manifest. The report builder explicitly selects these runs "
     "and verifies completed status and key invariants; it does not automatically select the latest folder.")

# ==================================================== 11 CONCLUSION
h1("11. Conclusion")
para(
    "This revised edition narrows what the project's data actually supports. The malware, secrets and "
    "dependency comparisons remain informative but are now stated as descriptive, scope-limited "
    "observations rather than tested superiority claims. Vulnerability detection is better characterised "
    "by MCC and balanced accuracy than by raw accuracy or F1 alone, given that a trivial baseline beats "
    "every tested configuration on accuracy; of six pairwise comparisons, only the within-model "
    "chain-of-thought effect for Qwen2.5-Coder survives correction for multiple comparisons. The "
    "repository-level file-selection bottleneck claimed in the original edition is not a causal finding. "
    "The new trace measures 30.4% selection and 82.4% detection conditional on selection. The restricted "
    "paired perturbation has little effect on either detector, with lower observed false alarms for Qwen "
    "but slightly higher recall for YARA; no general robustness claim follows. The "
    "label-quality audit stands as a genuine, if non-random-sample, finding that CWE-category correctness "
    "is materially weaker than whether a function is vulnerable at all. Taken together, this is a smaller "
    "but more defensible set of claims than the original edition made; the pending items in Section 10 "
    "define what would be needed to extend it further.")

# ==================================================== REFERENCES
h1("References")
refs = [
    "MITRE Corporation. <i>Common Weakness Enumeration (CWE)</i>. https://cwe.mitre.org",
    "National Institute of Standards and Technology. <i>National Vulnerability Database (NVD)</i>. https://nvd.nist.gov",
    "NIST/SEMATECH. <i>Confidence Intervals for a Binomial Proportion</i>, e-Handbook of Statistical Methods, section 7.2.4.1. https://itl.nist.gov/div898/handbook/prc/section2/prc241.htm",
    "Open Source Vulnerabilities (OSV). <i>osv.dev</i>. https://osv.dev",
    "Datadog. <i>GuardDog: a CLI to identify malicious PyPI and npm packages</i>. https://github.com/DataDog/guarddog",
    "Datadog Security Labs. <i>GuardDog 3.0 release notes</i>. https://securitylabs.datadoghq.com/articles/guarddog-3-0-release/",
    "Gitleaks. <i>Detect and prevent secrets in code</i>. https://github.com/gitleaks/gitleaks",
    "Semgrep. <i>Lightweight static analysis for many languages</i>. https://semgrep.dev",
    "Tree-sitter. <i>An incremental parsing system for programming tools</i>. https://tree-sitter.github.io",
    "Ollama. <i>Run large language models locally</i>. https://ollama.com",
]
for i, r in enumerate(refs, 1):
    story.append(Paragraph(f"[{i}]&nbsp;&nbsp;{r}", REF))
sp(4)
story.append(Paragraph(
    "Note: the literature that motivated the study design (surveyed papers on LLM vulnerability "
    "detection and prompting strategy) is catalogued in the project's separate bibliography and should "
    "be cited inline in the final thesis version. References above marked NIST/GuardDog were consulted "
    "directly during this revision, not carried forward without inspection.", SMALL))

# ==================================================== PROVENANCE APPENDIX

h1("Appendix A. Provenance")
para(
    "This edition combines the historical post-hoc audit with two new user-executed follow-up runs "
    "reported separately in Section 10.1. Run manifests and input/output hashes are embedded in "
    "output/report_build/report_data.json. The historical reanalysis is recorded in "
    "<code>output/experiment-audit/audit.json</code>, which includes a SHA-256 hash of every "
    f"input file it read (recorded seed: {A.get('seed', 'n/a')}). Rebuilding this PDF from the same "
    "inputs:")
for cmd in ["python research/report/gather.py",
            "python research/report/charts.py",
            "python research/report/build_report_v2.py"]:
    story.append(Paragraph(f"<font face='Courier'>{cmd}</font>", CELL))
sp(6)
para(
    "The historical result files these scripts read (<code>data/results/*.json</code>, "
    "<code>data/processed/*.jsonl</code>) were produced by the historical data-collection "
    "scripts in <code>src/</code> (e.g. <code>evaluate.py</code>, <code>malware_evaluate.py</code>, "
    "<code>secrets_evaluate.py</code>, <code>deps_evaluate.py</code>, <code>repo_bench_eval.py</code>, "
    "<code>evasion_eval.py</code>); their exact historical invocation "
    "parameters, model snapshot identifiers and timestamps for every historical run were not all "
    "preserved (Section 9). The original, unrevised report PDF is preserved unchanged at its original "
    "location and is not modified by this document. Hardened successors to the historical evaluation "
    "scripts (content-backed record identity, duplicate/mismatch rejection, checkpointed repository-"
    "benchmark runs) exist in <code>src/</code> and were used for the separately labelled follow-up "
    "experiments. 57 offline engineering regression tests pass, which is software validation, "
    "not evidence about detection accuracy.")

# ---------------- build ----------------
def deco(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5); canvas.setFillColor(GREY)
    canvas.drawString(20 * mm, 12 * mm, "LLM-based Security Assessment of Open-Source Repositories — Revised")
    canvas.drawRightString(190 * mm, 12 * mm, f"{doc.page}")
    canvas.setStrokeColor(LINE); canvas.setLineWidth(0.4)
    canvas.line(20 * mm, 15 * mm, 190 * mm, 15 * mm)
    canvas.restoreState()


doc = BaseDocTemplate(str(OUT), pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                      topMargin=18 * mm, bottomMargin=18 * mm,
                      title="LLM Security Analysis — Scientific Report (Revised)",
                      author="Alireza Shahidiani")
frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f")
doc.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=deco)])
OUT.parent.mkdir(parents=True, exist_ok=True)
doc.build(story)
print("REPORT ->", OUT)
print("size:", OUT.stat().st_size)
