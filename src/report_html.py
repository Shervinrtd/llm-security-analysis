"""Turn a RepoReport into a comprehensive, self-contained HTML security report.

One file, no external assets, opens in any browser. Designed to be the
"comprehensive report" a user gets back after pointing the tool at a repository.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

PILLAR_META = {
    "malware":       ("Malicious Code", "#7A5CA8", "Deliberately harmful code hidden in the project"),
    "secret":        ("Exposed Secrets", "#C7871F", "Passwords or keys committed into the code"),
    "vulnerability": ("Code Vulnerabilities", "#D0533B", "Coding flaws an attacker could exploit"),
    "dependency":    ("Vulnerable Dependencies", "#2A8C79", "Third-party packages with known flaws"),
}
RISK_COLOR = {"critical": "#C0392B", "high": "#E67E22", "medium": "#D4A017",
              "low": "#4C9A6B", "clean": "#2A9D8F", "unknown": "#6B7280"}
RISK_VERDICT = {
    "critical": "Do NOT use this repository until the critical findings are resolved.",
    "high": "Review carefully before use — several serious issues were found.",
    "medium": "Some issues were found; review the flagged items before relying on this code.",
    "low": "Only minor issues were found.",
    "clean": "No security issues were detected across the four analysis categories.",
    "unknown": "Analysis incomplete.",
}


def _esc(x) -> str:
    return html.escape(str(x)) if x is not None else ""


def render(report: dict, source_url: str | None = None) -> str:
    findings = report.get("findings", [])
    by_pillar: dict[str, list] = {k: [] for k in PILLAR_META}
    for f in findings:
        by_pillar.setdefault(f["pillar"], []).append(f)

    level = report.get("risk_level", "unknown")
    rc = RISK_COLOR.get(level, "#6B7280")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    repo_name = source_url or report.get("repo", "repository")

    # ---- summary cards per pillar ----
    cards = []
    for pillar, (name, color, desc) in PILLAR_META.items():
        n = len(by_pillar.get(pillar, []))
        state = "found" if n else "clean"
        cards.append(f"""
        <div class="card">
          <div class="card-bar" style="background:{color}"></div>
          <div class="card-body">
            <div class="card-count" style="color:{color if n else '#2A9D8F'}">{n}</div>
            <div class="card-name">{name}</div>
            <div class="card-desc">{desc}</div>
            <div class="card-state {state}">{'issue(s) found' if n else 'none found'}</div>
          </div>
        </div>""")

    # ---- detailed findings ----
    sections = []
    order = ["malware", "secret", "vulnerability", "dependency"]
    for pillar in order:
        items = by_pillar.get(pillar, [])
        if not items:
            continue
        name, color, _ = PILLAR_META[pillar]
        rows = []
        for f in items:
            loc = f":{f['line']}" if f.get("line") else ""
            cat = f"<span class='tag' style='background:{color}22;color:{color}'>{_esc(f['category'])}</span>" if f.get("category") else ""
            sev = _esc(f.get("severity", ""))
            rows.append(f"""
            <tr>
              <td class="file">{_esc(f['file'])}{loc}</td>
              <td>{cat}</td>
              <td><span class="sev sev-{sev.lower()}">{sev}</span></td>
              <td class="detail">{_esc(f['detail'])}</td>
            </tr>""")
        sections.append(f"""
        <section class="findings">
          <h2 style="border-color:{color}"><span class="dot" style="background:{color}"></span>{name}
            <span class="count-badge" style="background:{color}">{len(items)}</span></h2>
          <table>
            <thead><tr><th>Location</th><th>Type</th><th>Severity</th><th>Details</th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
          </table>
        </section>""")

    if not sections:
        sections.append("<section class='findings'><p class='allclear'>"
                        "&#10003; No security issues detected across all four categories.</p></section>")

    by_pillar_counts = report.get("by_pillar", {})
    total = len(findings)

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Report — {_esc(repo_name)}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font-family:'Segoe UI',system-ui,Arial,sans-serif;
         background:#0d1b20; color:#1a2226; }}
  .wrap {{ max-width:1000px; margin:0 auto; padding:0 0 60px; }}
  header {{ background:linear-gradient(135deg,#0d1b20,#12414b);
            color:#fff; padding:34px 40px 30px; }}
  header .kicker {{ color:#F2A64B; font-size:13px; font-weight:700; letter-spacing:1px; }}
  header h1 {{ margin:6px 0 4px; font-size:26px; }}
  header .repo {{ color:#AEC7CD; font-size:15px; word-break:break-all; }}
  header .meta {{ color:#7C99A0; font-size:12px; margin-top:8px; }}
  .verdict {{ margin:0; padding:22px 40px; color:#fff; background:{rc}; }}
  .verdict .level {{ font-size:13px; letter-spacing:2px; text-transform:uppercase; opacity:.9; }}
  .verdict .big {{ font-size:30px; font-weight:800; margin:2px 0 6px; }}
  .verdict .say {{ font-size:15px; opacity:.95; }}
  .cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px;
            padding:26px 40px 6px; background:#fff; }}
  .card {{ background:#f4f7f8; border-radius:10px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.06); }}
  .card-bar {{ height:5px; }}
  .card-body {{ padding:14px 14px 16px; }}
  .card-count {{ font-size:34px; font-weight:800; line-height:1; }}
  .card-name {{ font-size:14px; font-weight:700; margin:6px 0 4px; color:#14343d; }}
  .card-desc {{ font-size:11.5px; color:#5c6b70; line-height:1.35; min-height:46px; }}
  .card-state {{ font-size:11px; font-weight:700; margin-top:6px; }}
  .card-state.found {{ color:#C0392B; }}
  .card-state.clean {{ color:#2A9D8F; }}
  .stats {{ padding:6px 40px 20px; background:#fff; color:#5c6b70; font-size:13px; }}
  main {{ background:#fff; padding:8px 40px 30px; }}
  section.findings {{ margin-top:26px; }}
  section.findings h2 {{ font-size:18px; color:#14343d; border-bottom:3px solid;
        padding-bottom:8px; display:flex; align-items:center; gap:10px; }}
  .dot {{ width:12px; height:12px; border-radius:50%; display:inline-block; }}
  .count-badge {{ color:#fff; font-size:12px; padding:2px 9px; border-radius:11px; margin-left:auto; }}
  table {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:13px; }}
  th {{ text-align:left; color:#5c6b70; font-size:11px; text-transform:uppercase;
        letter-spacing:.5px; padding:6px 10px; border-bottom:2px solid #e3eaec; }}
  td {{ padding:9px 10px; border-bottom:1px solid #eef2f3; vertical-align:top; }}
  td.file {{ font-family:Consolas,monospace; font-size:12px; color:#12414b; white-space:nowrap; }}
  td.detail {{ color:#333; }}
  .tag {{ font-family:Consolas,monospace; font-size:11px; padding:2px 7px; border-radius:5px; font-weight:600; }}
  .sev {{ font-size:11px; font-weight:700; padding:2px 8px; border-radius:11px; }}
  .sev-critical {{ background:#fbe3e0; color:#C0392B; }}
  .sev-high {{ background:#fdeede; color:#E67E22; }}
  .sev-medium {{ background:#fbf3d6; color:#B8860B; }}
  .sev-low {{ background:#e6f3ec; color:#4C9A6B; }}
  .allclear {{ font-size:18px; color:#2A9D8F; font-weight:700; padding:30px 0; text-align:center; }}
  footer {{ padding:18px 40px; color:#7C99A0; font-size:11.5px; background:#fff;
            border-top:1px solid #eef2f3; }}
  @media (max-width:720px) {{ .cards {{ grid-template-columns:repeat(2,1fr); }} }}
</style></head><body><div class="wrap">
<header>
  <div class="kicker">AI-POWERED SECURITY AUDIT</div>
  <h1>Repository Security Report</h1>
  <div class="repo">{_esc(repo_name)}</div>
  <div class="meta">Generated {now} &nbsp;·&nbsp; {report.get('n_analysed',0)} of {report.get('n_files',0)} files analysed &nbsp;·&nbsp; {report.get('elapsed_s',0)}s</div>
</header>
<div class="verdict">
  <div class="level">Overall risk</div>
  <div class="big">{level.upper()}</div>
  <div class="say">{RISK_VERDICT.get(level,'')}</div>
</div>
<div class="cards">{''.join(cards)}</div>
<div class="stats">Total findings: <b>{total}</b>
  {' · '.join(f"{PILLAR_META[k][0]}: {v}" for k,v in by_pillar_counts.items()) if by_pillar_counts else ''}</div>
<main>{''.join(sections)}</main>
<footer>
  Produced by the four-pillar LLM security analyser (vulnerabilities · malware · secrets · dependencies).
  Findings are AI-assisted and should be confirmed by a human reviewer before action.
</footer>
</div></body></html>"""


def write(report: dict, out_path, source_url: str | None = None) -> None:
    from pathlib import Path
    Path(out_path).write_text(render(report, source_url), encoding="utf-8")
