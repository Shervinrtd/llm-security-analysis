"""Export a stratified sample for manual label verification.

Commit-derived labels carry known noise: a fix commit may touch functions that
are not themselves the root cause, so a `pre` function inherits the CVE's CWE
without that necessarily being true of *that* function. Prior work (SecVulEval,
BigVul, CVEfixes) makes the same assumption; the defensible response is to
measure the error rate on a sample rather than assert the labels are clean.

This produces a self-contained HTML review sheet: the vulnerable function, its
patched counterpart, the diff between them, and the CVE context - plus radio
buttons for a verdict. Reviewer selections export back to CSV from the page.

    python src/sample_for_review.py --n 100 --seed 42
"""
from __future__ import annotations

import argparse
import html
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C


def stratified_sample(recs: list[dict], n: int, seed: int) -> list[dict]:
    """Sample vulnerable records, spread across language families and CWEs."""
    vuln = [r for r in recs if r.get("label") == 1 and r.get("pair_id")]
    if not vuln:
        return []
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for r in vuln:
        buckets[(r["language_family"], r.get("cwe_primary"))].append(r)

    rng = random.Random(seed)
    keys = sorted(buckets)
    rng.shuffle(keys)
    out: list[dict] = []
    # round-robin across buckets so no single language/CWE dominates the sheet
    while len(out) < n and any(buckets[k] for k in keys):
        for k in keys:
            if not buckets[k]:
                continue
            pick = rng.choice(buckets[k])
            buckets[k].remove(pick)
            out.append(pick)
            if len(out) >= n:
                break
    return out


def diff_lines(pre: str, post: str) -> str:
    import difflib
    d = difflib.unified_diff(pre.splitlines(), post.splitlines(),
                             fromfile="vulnerable", tofile="patched", lineterm="", n=3)
    return "\n".join(d)


def render(samples: list[dict], pairs: dict[str, dict]) -> str:
    css = """
    body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f6fa;color:#1a1a2e}
    header{background:#1f3b57;color:#fff;padding:16px 24px;position:sticky;top:0;z-index:10}
    header h1{margin:0;font-size:19px}
    header p{margin:4px 0 0;font-size:13px;opacity:.85}
    .card{background:#fff;margin:18px 24px;border-radius:8px;padding:18px 22px;
          box-shadow:0 1px 4px rgba(0,0,0,.08)}
    .meta{font-size:13px;color:#555;margin-bottom:10px;line-height:1.6}
    .meta b{color:#1f3b57}
    .cwe{display:inline-block;background:#e63946;color:#fff;padding:2px 9px;
         border-radius:11px;font-size:12px;font-weight:600}
    .lang{display:inline-block;background:#2e75b6;color:#fff;padding:2px 9px;
          border-radius:11px;font-size:12px}
    pre{background:#1e1e2e;color:#e6e6e6;padding:12px;border-radius:6px;
        overflow-x:auto;font-size:12px;line-height:1.45;max-height:400px}
    pre.diff{background:#f8f8f8;color:#222}
    .diff .add{color:#0a7d38}.diff .del{color:#c0392b}
    h3{margin:14px 0 6px;font-size:14px;color:#1f3b57}
    .verdict{margin-top:14px;padding:12px;background:#f0f3fa;border-radius:6px}
    .verdict label{margin-right:18px;font-size:13.5px;cursor:pointer}
    .cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}
    @media(max-width:1100px){.cols{grid-template-columns:1fr}}
    button{background:#1f3b57;color:#fff;border:0;padding:10px 20px;border-radius:6px;
           font-size:14px;cursor:pointer}
    """
    js = """
    function exportCsv(){
      let rows=[['sample_id','cve_id','cwe','language','verdict','notes']];
      document.querySelectorAll('.card[data-sid]').forEach(c=>{
        const sid=c.dataset.sid;
        const sel=c.querySelector('input[type=radio]:checked');
        const notes=c.querySelector('textarea').value.replace(/"/g,'""');
        rows.push([sid,c.dataset.cve,c.dataset.cwe,c.dataset.lang,
                   sel?sel.value:'UNREVIEWED','"'+notes+'"']);
      });
      const csv=rows.map(r=>r.join(',')).join('\\n');
      const a=document.createElement('a');
      a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
      a.download='label_review.csv'; a.click();
    }
    """
    parts = [f"<!doctype html><meta charset='utf-8'><title>Label review</title>"
             f"<style>{css}</style><script>{js}</script>",
             "<header><h1>Vulnerability label review</h1>"
             f"<p>{len(samples)} sampled vulnerable functions. For each: does this function "
             "actually contain the stated CWE? &nbsp;|&nbsp; "
             "<button onclick='exportCsv()'>Export CSV</button></p></header>"]

    for i, r in enumerate(samples, 1):
        pair = pairs.get(r["pair_id"], {})
        post = pair.get("post")
        dtxt = diff_lines(r["code"], post["code"]) if post else "(patched version unavailable)"
        dhtml = []
        for ln in dtxt.splitlines():
            cls = "add" if ln.startswith("+") else "del" if ln.startswith("-") else ""
            dhtml.append(f"<span class='{cls}'>{html.escape(ln)}</span>")

        parts.append(f"""
        <div class="card" data-sid="{r['sample_id']}" data-cve="{r['cve_id']}"
             data-cwe="{r.get('cwe_primary','')}" data-lang="{r['language']}">
          <div class="meta">
            <b>#{i}</b> &nbsp; <span class="cwe">{html.escape(str(r.get('cwe_primary')))}</span>
            <span class="lang">{r['language']}</span> &nbsp;
            <b>{html.escape(str(r.get('cwe_name') or ''))}</b><br>
            <b>CVE:</b> {r['cve_id']} ({r.get('cvss_severity') or '?'}) &nbsp;
            <b>repo:</b> {html.escape(r['repo'])} &nbsp;
            <b>function:</b> <code>{html.escape(r['func_name'])}</code> ({r['loc']} LOC)<br>
            <b>file:</b> {html.escape(r['file_path'])}<br>
            <b>CVE description:</b> {html.escape((r.get('cve_description') or '')[:400])}
          </div>
          <div class="cols">
            <div><h3>Vulnerable (label = 1)</h3><pre>{html.escape(r['code'][:6000])}</pre></div>
            <div><h3>Fix diff (vulnerable &rarr; patched)</h3>
                 <pre class="diff">{"<br>".join(dhtml[:200])}</pre></div>
          </div>
          <div class="verdict">
            <b>Is the stated CWE actually present in THIS function?</b><br>
            <label><input type="radio" name="v{i}" value="CORRECT"> Correct</label>
            <label><input type="radio" name="v{i}" value="WRONG_CWE"> Vulnerable, but wrong CWE</label>
            <label><input type="radio" name="v{i}" value="NOT_VULNERABLE"> Not actually vulnerable</label>
            <label><input type="radio" name="v{i}" value="UNCLEAR"> Unclear</label><br>
            <textarea rows="2" style="width:100%;margin-top:8px" placeholder="notes"></textarea>
          </div>
        </div>""")
    return "\n".join(parts)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(C.PROCESSED / "dataset.jsonl"))
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(C.PROCESSED / "label_review.html"))
    args = ap.parse_args()

    path = Path(args.data)
    if not path.exists():
        sys.exit(f"No dataset at {path}")
    recs = [json.loads(l) for l in path.open(encoding="utf-8") if l.strip()]

    pairs: dict[str, dict] = defaultdict(dict)
    for r in recs:
        if r.get("pair_id"):
            pairs[r["pair_id"]][r["version"]] = r

    samples = stratified_sample(recs, args.n, args.seed)
    if not samples:
        sys.exit("No vulnerable paired records to sample.")

    Path(args.out).write_text(render(samples, pairs), encoding="utf-8")
    langs = defaultdict(int)
    cwes = defaultdict(int)
    for s in samples:
        langs[s["language_family"]] += 1
        cwes[s.get("cwe_primary")] += 1
    print(f"sampled {len(samples)} vulnerable functions (seed {args.seed})")
    print(f"  languages : {dict(langs)}")
    print(f"  CWEs      : {len(cwes)} distinct")
    print(f"  -> {args.out}")
    print("\nOpen in a browser, review each, then click 'Export CSV'.")


if __name__ == "__main__":
    main()
