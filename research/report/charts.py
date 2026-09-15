"""Generate charts for the REVISED report as PNG files.

Portable: paths derived from this file's location. Run after gather.py:

    python research/report/charts.py

Two charts present in the original build are deliberately NOT regenerated
here (see REVISION_NOTES.md): the vulnerability cross-vendor F1-with-CI
chart (its source, the 600-row statistical_report.json, mixes 18 rows with
ambiguous sample identity - superseded by a table built from the 582-row
audited sensitivity set) and the repository-benchmark selection/detection
bottleneck chart (the "selected" and "detection_given_selected" series are
invalid - historical selected paths were recomputed without static triage).
Both are replaced by plain tables in build_report_v2.py instead of charts.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

ROOT = Path(__file__).resolve().parents[2]
SP = ROOT / "output" / "report_build"
D = json.loads((SP / "report_data.json").read_text(encoding="utf-8"))

TEAL = "#12414B"; TEAL_D = "#0B2E36"; AMBER = "#C7871F"; GOOD = "#2A8C79"
CORAL = "#C0392B"; GREY = "#5C6B70"; BLUE = "#3E7CB1"; LIGHT = "#EEF3F4"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11,
                     "axes.edgecolor": "#D8E2E4", "axes.linewidth": 0.8,
                     "figure.dpi": 150})


def save(fig, name):
    fig.tight_layout()
    fig.savefig(SP / name, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", name)


ds = D["dataset"]

# 1. label balance (donut)
if ds.get("total"):
    fig, ax = plt.subplots(figsize=(4.2, 3.2))
    vals = [ds["vulnerable"], ds["safe"]]
    ax.pie(vals, labels=[f"Vulnerable\n{ds['vulnerable']:,}", f"Safe\n{ds['safe']:,}"],
           colors=[CORAL, GOOD], autopct=lambda p: f"{p:.0f}%", startangle=90,
           wedgeprops=dict(width=0.42, edgecolor="white"), pctdistance=0.78,
           textprops={"fontsize": 10})
    ax.set_title(f"Class distribution (N = {ds['total']:,})", fontsize=11, weight="bold")
    save(fig, "chart_labels.png")

# 2. language distribution (horizontal bars, stacked vuln/safe)
if ds.get("languages"):
    fig, ax = plt.subplots(figsize=(6.2, 3.2))
    langs = sorted(ds["languages"], key=lambda k: -ds["languages"][k])
    names = {"c": "C", "cpp": "C++", "java": "Java", "python": "Python", "javascript": "JavaScript"}
    vuln = [ds["lang_label"].get(l, {}).get("1", 0) for l in langs]
    safe = [ds["lang_label"].get(l, {}).get("0", 0) for l in langs]
    y = range(len(langs))
    ax.barh(y, safe, color=GOOD, label="Safe")
    ax.barh(y, vuln, left=safe, color=CORAL, label="Vulnerable")
    ax.set_yticks(list(y)); ax.set_yticklabels([names.get(l, l) for l in langs])
    ax.invert_yaxis()
    for i, l in enumerate(langs):
        tot = ds["languages"][l]
        ax.text(tot + 150, i, f"{tot:,}", va="center", fontsize=9, color=GREY)
    ax.set_xlabel("number of code samples")
    ax.set_title("Sample distribution by programming language", fontsize=11, weight="bold")
    ax.legend(loc="lower right", frameon=False, fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    save(fig, "chart_languages.png")

# 3. top CWE weakness types
if ds.get("top_cwe"):
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    top = ds["top_cwe"][:10]
    nm = ds.get("cwe_names", {})
    full = [f"{c} · {nm.get(c, '')[:26]}" for c, _ in top]
    counts = [n for _, n in top]
    yy = range(len(top))
    ax.barh(yy, counts, color=TEAL)
    ax.set_yticks(list(yy)); ax.set_yticklabels(full, fontsize=8.5)
    ax.invert_yaxis()
    for i, n in enumerate(counts):
        ax.text(n + 3, i, str(n), va="center", fontsize=8.5, color=GREY)
    ax.set_xlabel("number of vulnerable samples")
    ax.set_title("Ten most frequent CWE categories", fontsize=11, weight="bold")
    ax.spines[["top", "right"]].set_visible(False)
    save(fig, "chart_cwe.png")

# 4. train/val/test split
if ds.get("splits"):
    fig, ax = plt.subplots(figsize=(6.2, 1.5))
    sp = ds["splits"]
    order = ["train", "val", "test"]
    colors = [TEAL_D, AMBER, BLUE]
    left = 0
    for s, c in zip(order, colors):
        ax.barh(0, sp[s], left=left, color=c, height=0.6)
        ax.text(left + sp[s] / 2, 0, f"{s}\n{sp[s]:,}", ha="center", va="center",
                color="white", fontsize=9, weight="bold")
        left += sp[s]
    ax.set_xlim(0, left); ax.axis("off")
    ax.set_title("Train / validation / test partition (repository-disjoint, "
                 "exact-hash-disjoint; near-duplicate independence not established)",
                 fontsize=10, weight="bold")
    save(fig, "chart_splits.png")

# 5. cross-category comparison (descriptive F1; interpretive caveats live in the
#    report text, not in this chart - e.g. malware LLM recall is BELOW baseline
#    recall despite higher F1, and the malware baseline is a YARA rule subset).
def best_per_model(entries):
    result = {}
    for entry in entries:
        if entry["model"] not in result or entry["f1"] > result[entry["model"]]["f1"]:
            result[entry["model"]] = entry
    return result

mal = best_per_model(D["results"].get("malware", []))
sec = best_per_model(D["results"].get("secrets", []))
dep = best_per_model(D["results"].get("deps", []))
if mal and sec and dep:
    fig, ax = plt.subplots(figsize=(6.6, 3.6))
    pillars = ["Malware", "Secrets", "Dependencies"]
    tool_f1 = [mal.get("guarddog_yara", {}).get("f1"), sec.get("gitleaks", {}).get("f1"),
               dep.get("osv_lookup", {}).get("f1")]
    ai_f1 = [mal.get("local-qwen-coder", {}).get("f1"),
             max((v["f1"] for k, v in sec.items() if k != "gitleaks"), default=None),
             max((v["f1"] for k, v in dep.items() if k != "osv_lookup"), default=None)]
    tool_names = ["GuardDog\n(rule subset)", "Gitleaks", "OSV database"]
    x = range(len(pillars))
    w = 0.38
    for i, v in enumerate(tool_f1):
        if v is not None:
            ax.bar(i - w / 2, v, w, color=GREY)
            ax.text(i - w / 2, v + 0.02, f"{v:.2f}", ha="center", fontsize=8.5, color=GREY)
    for i, v in enumerate(ai_f1):
        if v is not None:
            ax.bar(i + w / 2, v, w, color=GOOD)
            ax.text(i + w / 2, v + 0.02, f"{v:.2f}", ha="center", fontsize=8.5, color=GOOD, weight="bold")
    ax.set_xticks(list(x)); ax.set_xticklabels(pillars, fontsize=10, weight="bold")
    ax.set_ylim(0, 1.17); ax.set_ylabel("Observed F1")
    ax.set_title("LLM vs. specialist baseline: F1 by threat category (descriptive)", fontsize=11, weight="bold")
    ax.legend([Patch(color=GREY), Patch(color=GOOD)],
              ["Specialist tool / oracle", "AI model (best observed)"], frameon=False,
              loc="upper center", bbox_to_anchor=(.5,-.12), ncol=2, fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    ax.axhline(0, color="#D8E2E4", lw=0.8)
    save(fig, "chart_results.png")

# 6. evasion: signatures vs LLM under textual perturbation
if "evasion" in D:
    ev = D["evasion"]
    g = ev.get("guarddog_yara", {})
    llm = ev.get("llm", {})
    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    cats = ["Installed YARA rules", "Qwen zero-shot"]
    before = [g.get("detection_original", 0) * 100, llm.get("detection_original", 0) * 100]
    after = [g.get("detection_obfuscated", 0) * 100, llm.get("detection_obfuscated", 0) * 100]
    x = range(len(cats)); w = 0.36
    ax.bar([i - w / 2 for i in x], before, w, color=TEAL, label="original code")
    ax.bar([i + w / 2 for i in x], after, w, color=AMBER, label="after textual perturbation")
    for i in x:
        ax.text(i - w / 2, before[i] + 1.5, f"{before[i]:.0f}%", ha="center", fontsize=9)
        ax.text(i + w / 2, after[i] + 1.5, f"{after[i]:.0f}%", ha="center", fontsize=9)
    ax.set_xticks(list(x)); ax.set_xticklabels(cats, fontsize=9.5)
    ax.set_ylabel("% of malware detected"); ax.set_ylim(0, 115)
    ax.set_title("Detection rate before and after textual perturbation", fontsize=11, weight="bold")
    ax.legend(frameon=False, fontsize=9, loc="upper center", ncol=2)
    ax.spines[["top", "right"]].set_visible(False)
    save(fig, "chart_evasion.png")

# 7. trusted-repository corpus outcome (development/regression set, not held-out)
if "fp" in D:
    fp = D["fp"]
    fig, ax = plt.subplots(figsize=(6.0, 1.7))
    total = fp.get("n_repos", 35)
    false_bad = fp.get("false_dangerous_verdicts", 0)
    ax.barh(0, total, color=GOOD, height=0.5)
    if false_bad:
        ax.barh(0, false_bad, color=CORAL, height=0.5)
    ax.text(total / 2, 0, f"{false_bad} of {total} clone-unsafe verdicts\n"
            "Development set reused for tuning",
            ha="center", va="center", color="white", fontsize=9, weight="bold")
    ax.set_xlim(0, total); ax.axis("off")
    ax.set_title("Clone-unsafe verdicts on the trusted-repository corpus (n = 35)",
                 fontsize=11, weight="bold")
    save(fig, "chart_fp.png")

# 8. label review: verdict breakdown, human (primary) vs LLM (secondary review pass)
if "label_review" in D.get("audit", {}):
    lr = D["audit"]["label_review"]["counts"]
    fig, axes = plt.subplots(1, 2, figsize=(7.6, 3.0))
    cats = ["CORRECT", "WRONG_CWE", "NOT_VULNERABLE", "UNCLEAR"]
    nice = ["Correct", "Wrong CWE", "Not actually\nvulnerable", "Unclear"]
    cols = [GOOD, AMBER, CORAL, GREY]
    n_shared = D["audit"]["label_review"]["n_shared"]
    for ax, key, title in ((axes[0], "human", "Human review (primary)"),
                            (axes[1], "llm", "LLM review pass (secondary)")):
        counts = lr[key]
        vals = [counts.get(c, 0) for c in cats]
        ax.pie(vals, colors=cols, autopct=lambda p: f"{p:.0f}%" if p > 4 else "",
               startangle=90, wedgeprops=dict(width=0.42, edgecolor="white"),
               pctdistance=0.78, textprops={"fontsize": 8.5, "color": "white", "weight": "bold"})
        ax.set_title(f"{title}\n(n = {n_shared})", fontsize=9.5, weight="bold")
    fig.legend([Patch(color=c) for c in cols], nice, loc="lower center", ncol=4,
               frameon=False, fontsize=8.5, bbox_to_anchor=(0.5, -0.02))
    fig.suptitle("Label-review verdicts: 50 round-robin-sampled vulnerable-labelled "
                  "functions (not a corpus-wide random sample)", fontsize=10.5, weight="bold", y=1.02)
    save(fig, "chart_label_noise.png")

print("ALL CHARTS DONE")
