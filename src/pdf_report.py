"""Scan reports with explicit coverage, full finding lists and escaped source text."""
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape
import re
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

TEAL_D = colors.HexColor("#153C46")
TEAL = colors.HexColor("#246373")
AMBER = colors.HexColor("#8C5B12")
GREY = colors.HexColor("#52636B")
LIGHT = colors.HexColor("#EDF3F5")
WIDTH = 176 * mm
FONT, BOLD = "Helvetica", "Helvetica-Bold"
font_root = Path("C:/Windows/Fonts")
if (font_root / "segoeui.ttf").exists() and (font_root / "segoeuib.ttf").exists():
    pdfmetrics.registerFont(TTFont("ReportUI", str(font_root / "segoeui.ttf")))
    pdfmetrics.registerFont(TTFont("ReportUI-Bold", str(font_root / "segoeuib.ttf")))
    pdfmetrics.registerFontFamily("ReportUI", normal="ReportUI", bold="ReportUI-Bold")
    FONT, BOLD = "ReportUI", "ReportUI-Bold"
S_TITLE = ParagraphStyle("title", fontName=BOLD, fontSize=21, leading=26, textColor=TEAL_D, spaceAfter=9)
S_H2 = ParagraphStyle("heading", fontName=BOLD, fontSize=12, leading=16, textColor=TEAL_D,
                     spaceBefore=13, spaceAfter=7, keepWithNext=True)
S_BODY = ParagraphStyle("body", fontName=FONT, fontSize=9.5, leading=14, spaceAfter=7)
S_SMALL = ParagraphStyle("small", parent=S_BODY, fontSize=8, leading=11, textColor=GREY)
S_CELL = ParagraphStyle("cell", parent=S_BODY, fontSize=8.5, leading=12, spaceAfter=0)
S_CELLB = ParagraphStyle("cellbold", parent=S_CELL, fontName=BOLD)
S_LOCATION = ParagraphStyle("location", parent=S_BODY, fontName=BOLD, textColor=TEAL,
                            spaceBefore=9, spaceAfter=3, keepWithNext=True)
S_WHITE = ParagraphStyle("white", parent=S_BODY, textColor=colors.white, spaceAfter=0)


def _text(value):
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(value if value is not None else "")).replace("\u2011", "-")


def _p(value, style=S_BODY):
    return Paragraph(escape(_text(value)).replace("\n", "<br/>"), style)


def _body(story, text, style=S_BODY):
    text = _text(text)
    # Bound each paragraph, not the evidence: all chunks are included.
    for offset in range(0, len(text), 1600):
        story.append(_p(text[offset:offset + 1600], style))


def _doc(path, title):
    doc = BaseDocTemplate(str(path), pagesize=A4, leftMargin=17 * mm, rightMargin=17 * mm,
                          topMargin=17 * mm, bottomMargin=19 * mm, title=title)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0, id="body")
    def footer(canvas, d):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#D5E0E4"))
        canvas.line(doc.leftMargin, 15 * mm, doc.leftMargin + WIDTH, 15 * mm)
        canvas.setFont(FONT, 7)
        canvas.setFillColor(GREY)
        canvas.drawString(doc.leftMargin, 10 * mm, "Security review aid | Findings require verification | Not a safety certification")
        canvas.drawRightString(doc.leftMargin + WIDTH, 10 * mm, f"Page {d.page}")
        canvas.restoreState()
    doc.addPageTemplates(PageTemplate(id="report", frames=frame, onPage=footer))
    return doc


def _header(story, title, repo, extra=""):
    story.extend([_p(title, S_TITLE), _p(f"Repository: {repo}"),
        _p(f"Generated: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %z')}" +
           (f"\n{extra}" if extra else ""), S_SMALL), Spacer(1, 6)])


def _banner(story, title, detail, color=GREY):
    rows = [[_p(title, ParagraphStyle("banner", parent=S_WHITE, fontName=BOLD, fontSize=12, leading=17))],
            [_p(detail, S_WHITE)]]
    table = Table(rows, colWidths=[WIDTH])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), color),
        ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.extend([table, Spacer(1, 9)])


def _table(story, headers, rows, widths):
    header_style = ParagraphStyle("th", parent=S_CELLB, textColor=colors.white)
    cells = [[_p(c, header_style) for c in headers]] + [[_p(c, S_CELL) for c in row] for row in rows]
    table = Table(cells, colWidths=[w * mm for w in widths], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), TEAL_D),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), .35, colors.HexColor("#D5E0E4")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    story.extend([table, Spacer(1, 8)])


def _cards(story, pairs):
    gap = 3 * mm
    width = (WIDTH - 2 * gap) / 3
    for start in range(0, len(pairs), 3):
        row, styles = [], []
        for i in range(3):
            if i:
                row.append("")
            index = start + i
            row.append(_p(f"{pairs[index][1]}\n{pairs[index][0]}", S_WHITE) if index < len(pairs) else "")
            if index < len(pairs):
                styles.append(("BACKGROUND", (2 * i, 0), (2 * i, 0), TEAL))
        table = Table([row], colWidths=[width, gap, width, gap, width])
        table.setStyle(TableStyle(styles + [("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
        story.extend([table, Spacer(1, 6)])


def _coverage(story, coverage, analysed=0):
    story.append(_p("Scan coverage", S_H2))
    _body(story, f"Status: {coverage.get('status', 'unknown').upper()} | Files checked: {analysed} | "
        f"Eligible files: {coverage.get('eligible_files', 'unknown')} | Skipped by file limit: {coverage.get('omitted_by_limit', 'unknown')}")
    _body(story, f"Oversized: {coverage.get('oversized', 0)} | Unreadable: {coverage.get('unreadable', 0)} | "
        f"Functions checked: {coverage.get('functions_checked', 'not applicable')} | Functions skipped by limit: {coverage.get('functions_omitted', 0)}", S_SMALL)
    _body(story, coverage.get("scope_note", "Coverage details unavailable. Do not infer that the entire repository was checked."), S_SMALL)
    errors = coverage.get("errors", [])
    if errors:
        story.append(_p(f"Incomplete checks ({len(errors)})", S_H2))
        for error in errors:
            _body(story, f"{error.get('file', '-')} | {error.get('pillar', '-')} | {error.get('error', 'Check failed')}", S_SMALL)


PILLAR_NAME = {"supply_chain": "Supply-chain patterns", "malware": "Possible malicious code",
    "secret": "Possible exposed secrets", "vulnerability": "Code vulnerabilities", "dependency": "Dependencies"}


def _evidence(f):
    if f.get("pillar") == "supply_chain":
        return "Pattern match - intent unverified"
    return {"A": "Database / code match", "B": "Corroborated", "C": "Unverified model finding"}.get(f.get("tier"), "Unverified model finding")


def _findings(story, findings):
    story.append(_p(f"Findings ({len(findings)})", S_H2))
    if not findings:
        _body(story, "No findings were returned. Interpret this only within the scan coverage shown above.")
        return
    for i, f in enumerate(sorted(findings, key=lambda f: (f.get("pillar", ""),
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.get("severity"), 4))), 1):
        destination, story = story, []
        loc = str(f.get("file", "-")) + (f":{f['line']}" if f.get("line") else "")
        story.append(_p(f"{i}. {loc}", S_LOCATION))
        _body(story, " | ".join([PILLAR_NAME.get(f.get("pillar"), f.get("tool", "Finding")),
            str(f.get("severity", "UNRATED")), _evidence(f) if "pillar" in f else "Static rule match - verify context"]), S_SMALL)
        ids = [f.get("cwe_id") or f.get("cwe") or f.get("category"), f.get("cve_id"), f.get("rule")]
        _body(story, " | ".join(str(x) for x in ids if x), S_SMALL)
        detail = f.get("detail") or f.get("message") or "No explanation supplied."
        if f.get("pillar") == "secret" or f.get("tool") == "gitleaks":
            detail = "Possible hardcoded credential. Value redacted; inspect the listed location locally and rotate if live."
        _body(story, detail)
        if f.get("novelty"):
            _body(story, {"known": "Matches a CVE-linked function in the local corpus; validate applicability.",
                "known_location": "Historical CVE in this function; current vulnerability is unconfirmed.",
                "novel": "No match in the local corpus. This does not establish a new vulnerability.",
                "unconfirmed": "Advisory data did not confirm this finding."}.get(f["novelty"], "Unconfirmed"), S_SMALL)
        _body(story, "Next action: " + str(f.get("fix") or "Inspect the evidence and confirm applicability before changing or deploying the code."), S_SMALL)
        if sum(len(str(v)) for v in f.values()) < 2200:
            destination.append(KeepTogether(story))
        else:
            destination.extend(story)
        story = destination


def build_ai_report(path, repo, report, calibration=None, model="", strategy=""):
    doc, story = _doc(path, f"Security review - {repo}"), []
    _header(story, "AI-assisted security review", repo, f"Model: {model} | Vulnerability strategy: {strategy}")
    coverage = report.get("coverage") or {}
    level = report.get("risk_level", "unknown")
    incomplete = coverage.get("status") != "complete" or not report.get("n_analysed")
    if report.get("demo") or model == "stub":
        _banner(story, "DEMO - NOT A SECURITY ASSESSMENT", "Offline model responses are synthetic. Do not use these conclusions for a real repository.", AMBER)
    elif incomplete:
        _banner(story, "SCAN INCOMPLETE - SAFETY NOT ESTABLISHED", "Review the coverage and failed checks. Any findings below remain actionable leads.", AMBER)
    else:
        _banner(story, "CHECKS COMPLETED WITHIN THE STATED SCOPE", "Completion does not prove the repository is safe. Validate findings and review excluded code.", TEAL)
    if level == "clean" and incomplete:
        level = "unknown"
    _cards(story, [("Files with completed checks", report.get("n_analysed", 0)),
        ("Findings", len(report.get("findings", []))), ("Finding risk", level.upper())])
    _coverage(story, coverage, report.get("n_analysed", 0))
    story.append(_p("Installation and execution", S_H2))
    _body(story, report.get("clone_reason") or "Supply-chain checks are unavailable; safety is unknown.")
    supply = report.get("supply_scan") or {}
    _body(story, f"Supply-chain coverage: {supply.get('status', 'unknown')} | {supply.get('n_scanned', 0)} files inspected | "
        f"{supply.get('omitted_by_limit', 0)} skipped by limit. Pattern matches do not establish harmful intent.", S_SMALL)
    _findings(story, report.get("findings", []))
    if calibration and calibration.get("results"):
        story.append(_p("Method: strategy calibration", S_H2))
        _body(story, f"Selected using {calibration.get('n_samples', 0)} labelled validation samples. "
            "These benchmark scores are not accuracy estimates for this repository. A small sample may give an unstable ranking. "
            "This selection applies to vulnerability checks; the other categories use their own fixed prompts.", S_SMALL)
        rows = [[s["strategy"] + (" (selected)" if s["strategy"] == strategy else ""),
            f"{s['f1']:.3f}", f"{s['balanced_accuracy']:.3f}", f"{s['mcc']:+.3f}", f"{s['format_adherence']:.0%}"] for s in calibration["results"]]
        _table(story, ["Strategy", "F1", "Balanced accuracy", "MCC", "Valid format"], rows, [56, 23, 38, 25, 34])
    if report.get("coverage_note"):
        _body(story, report["coverage_note"], S_SMALL)
    doc.build(story)
    return str(path)


def build_static_report(path, repo, static):
    doc, story = _doc(path, f"Static review - {repo}"), []
    _header(story, "Static analysis review", repo)
    status = static.get("scan_status", "unknown")
    _banner(story, f"STATIC SCAN: {status.upper()}", "A zero count from a failed or unavailable tool is not a clean scan.", TEAL if status == "complete" else AMBER)
    _cards(story, [("Findings", len(static.get("findings", []))), ("Tools selected", len(static.get("tools_used", [])))])
    story.append(_p("Tools and coverage", S_H2))
    _body(story, "Source languages: " + (", ".join(f"{k} ({v})" for k, v in static.get("languages", {}).items()) or "None detected; source analysis coverage is unknown."))
    for tool in static.get("tools_used", []):
        entry = static.get("tool_status", {}).get(tool, {})
        _body(story, f"{tool}: {entry.get('status', 'unknown') if isinstance(entry, dict) else entry} | Findings: {static.get('per_tool', {}).get(tool, 0)}")
        if isinstance(entry, dict):
            _body(story, entry.get("error") or entry.get("message") or "", S_SMALL)
            inventory = entry.get("scanned_files")
            _body(story, f"Files reported as scanned: {len(inventory) if inventory is not None else 'unknown'}", S_SMALL)
    _body(story, "Tools have different rules, file exclusions and language support. Their findings are review leads, not proof of exploitability.", S_SMALL)
    _findings(story, static.get("findings", []))
    doc.build(story)
    return str(path)


def build_clone_report(path, repo, supply):
    doc, story = _doc(path, f"Supply-chain review - {repo}"), []
    _header(story, "Supply-chain review", repo, "Before installing or running downloaded code")
    findings = supply.get("findings", [])
    risky = any(f.get("severity") in ("CRITICAL", "HIGH") for f in findings)
    title = "REVIEW BEFORE INSTALLING OR RUNNING" if risky else "NO HIGH-RISK PATTERNS FOUND"
    if not risky and (supply.get("status") != "complete" or not supply.get("n_scanned")):
        title = "SCAN INCOMPLETE - SAFETY UNKNOWN"
    _banner(story, title, "These are heuristic pattern checks. Downloading, installing and running are different actions; this report does not certify any of them as safe.", AMBER if risky or supply.get("status") != "complete" else TEAL)
    _coverage(story, supply, supply.get("n_scanned", 0))
    _findings(story, [dict(f, pillar="supply_chain", category=f.get("kind")) for f in findings])
    doc.build(story)
    return str(path)


def build_comparison_report(path, repo, comparison):
    doc, story = _doc(path, f"Comparison - {repo}"), []
    _header(story, "AI and static findings", repo,
        f"Model: {comparison.get('model', '-')} | Strategy: {comparison.get('strategy', '-')}")
    if comparison.get("model") == "stub":
        _banner(story, "DEMO - NOT A SECURITY ASSESSMENT", "The AI responses in this comparison are synthetic.", AMBER)
    _banner(story, "FINDING OVERLAP - NOT AN ACCURACY SCORE", "Matching findings may still be false positives. Unmatched findings may reflect different coverage, rules or issue classifications.", TEAL)
    counts = comparison["counts"]
    _cards(story, [("AI findings", counts["ai_total"]), ("Static findings", counts["static_total"]),
        ("Matched pairs", counts["agreed"]), ("Unmatched AI", counts["ai_only"]), ("Unmatched static", counts["static_only"])])
    _body(story, "Pairs require compatible issue classification and nearby locations, with each static finding used at most once. "
        "Deterministic findings in the AI-assisted report are not independent model evidence.", S_SMALL)
    _body(story, f"Static scan status: {comparison.get('scan_status', comparison.get('static_scan_status', 'unknown'))}. "
        "Check the individual scan reports for failures and excluded files.", S_SMALL)
    for warning in comparison.get("warnings", []):
        _body(story, warning, S_SMALL)
    for title, key in [("Matched findings", "agreed_items"), ("Unmatched AI findings", "ai_only_items"), ("Unmatched static findings", "static_only_items")]:
        items = comparison.get(key, [])
        story.append(_p(f"{title} ({len(items)})", S_H2))
        if not items:
            _body(story, "None recorded.", S_SMALL)
        for item in items:
            story.append(_p(item.get("location", "-"), S_LOCATION))
            _body(story, f"AI: {item.get('ai', '-')} | Static: {item.get('static', '-')}", S_SMALL)
            _body(story, item.get("detail", ""))
            for key in ("coverage", "note", "coverage_note"):
                if item.get(key):
                    _body(story, item[key], S_SMALL)
    doc.build(story)
    return str(path)
