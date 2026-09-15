"""Build the standalone manuscript and PDF from the verified report data."""
import hashlib
import html
import json
import re
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, KeepTogether
from PIL import Image as PILImage
from reportlab.lib.pagesizes import A4

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).parent
DATA = ROOT/'output/report_build/report_data.json'
D = json.loads(DATA.read_text(encoding='utf-8'))
PROJECT_REPORT = '--project-report' in sys.argv
OUT = ROOT/('output/pdf' if PROJECT_REPORT else 'output/paper')
STEM = 'LLM Security Analysis - Project Report' if PROJECT_REPORT else 'LLM Security Assessment - Paper'
TEMPLATE = ROOT/'research/report/project_report.md' if PROJECT_REPORT else HERE/'manuscript.md'
OUT.mkdir(parents=True, exist_ok=True)


def mdtable(caption, headers, rows):
    return caption+'\n\n'+'\n'.join(['| '+' | '.join(headers)+' |',
        '| '+' | '.join(['---']*len(headers))+' |']+
        ['| '+' | '.join(map(str,row))+' |' for row in rows])


names = {'local-qwen-coder':'Qwen', 'gemini-flash':'Gemini'}
rows=[]
for k,e in D['audit']['vulnerability'].items():
    model,strategy=k.split('/')
    m=e['metrics'];ci=e['cluster_bootstrap']['f1']
    rows.append([names[model]+' / '+('zero-shot' if strategy=='zero_shot' else 'CoT'),
                 f"{m['accuracy']:.3f}",f"{m['balanced_accuracy']:.3f}",f"{m['f1']:.3f}",
                 f"{m['mcc']:.3f}",f"{ci['ci_low']:.3f}–{ci['ci_high']:.3f}"])
tables={'VULNERABILITY_TABLE':mdtable('Table 1. Vulnerability sensitivity set: 582 records per configuration, 167 repositories. F1 intervals use repository-cluster bootstrap resampling.',
    ['Model / prompt','Accuracy','Balanced acc.','F1','MCC','95% F1 interval'],rows)}
rows=[]
for category,baseline in [('malware','guarddog_yara'),('secrets','gitleaks'),('deps','osv_lookup')]:
    entries=D['results'][category]
    base=next(e for e in entries if e['model']==baseline)
    best=max([e for e in entries if e['model']!=baseline],key=lambda e:e['f1'])
    for e,label in [(base,'Baseline/oracle'),(best,'Best-observed LLM')]:
        tp,fp,fn=e['tp'],e['fp'],e['fn']
        rows.append([{'deps':'Dependencies','malware':'Malware','secrets':'Secrets'}[category], (names.get(e['model'],e['model'])+' / '+e['strategy']) if label=='Best-observed LLM' else e['model'],f"{tp/(tp+fp):.3f}",f"{tp/(tp+fn):.3f}",f"{2*tp/(2*tp+fp+fn):.3f}"])
tables['AUXILIARY_TABLE']=mdtable('Table 2. Historical auxiliary results. Best-observed selection is exploratory; categories have different evaluation units. Dependency scores here cover listed entries.',
    ['Category','Configuration','Precision','Recall','F1'],rows)
r=D['followup_runs']['repo'];c=r['counts'];n=r['summary']['n_cases']
rows=[[label,f'{num}/{den}',f'{num/den:.1%}'] for label,num,den in [
    ('Target-file selection',c['selected'],n),('Target-file alarm hit',c['detected'],n),
    ('Alarm hit given selection',c['detected'],c['selected']),('Exact-body localisation',c['localised'],n),
    ('Strict CWE agreement',c['cwe_strict'],n)]]
tables['REPOSITORY_TABLE']=mdtable('Table 3. Instrumented repository results: 60 attempted cases, 56 verified, 48 repositories. Rates are descriptive.', ['Measure','Count','Rate'],rows)
rows=[]
for detector in ['local-qwen-coder','yara']:
    for arm in ['original','transformed']:
        v=D['followup_runs']['perturbation']['summary'][detector]['all_complete_pairs'][arm]
        rows.append(['Qwen' if detector!='yara' else 'YARA subset',arm,
                     f"{v['tp']}/178 ({v['recall']:.1%})",f"{v['fp']}/161 ({v['false_positive_rate']:.1%})",f"{v['f1']:.3f}"])
tables['PERTURBATION_TABLE']=mdtable('Table 4. Paired Python experiment: 178 malicious and 161 benign items, no failed pairs for either detector.',
    ['Detector','Input','Malicious recall','Benign false alarms','F1'],rows)
rows=[]
sensitivity=[]
for key,e in D['audit']['vulnerability'].items():
    model,strategy=key.split('/')
    name=names[model]+' / '+('zero-shot' if strategy=='zero_shot' else 'CoT')
    c=e['counts'];rows.append([name,c['tp'],c['fp'],c['tn'],c['fn']])
    values=[]
    for rule in ['exclude_test_example_fixture_paths','exclude_development_cves']:
        a=e['posthoc_exclusion_sensitivity'][rule];m=a['metrics']
        values.append(f"{a['n']} / {m['f1']:.3f} / {m['mcc']:.3f} / {m['accuracy']:.3f}")
    sensitivity.append([name,*values])
tables['COUNTS_TABLE']=mdtable('', ['Configuration','TP','FP','TN','FN'], rows)
tables['SENSITIVITY_TABLE']=mdtable('', ['Configuration','Exclude test/example paths','Exclude development CVEs'], sensitivity)
text=TEMPLATE.read_text(encoding='utf-8')
if PROJECT_REPORT:
    sys.path.insert(0,str(ROOT/'src'))
    import perturbation_eval as PE
    control_dir=ROOT/'data/results/formatting_control/20260915-project-report'
    cm=json.loads((control_dir/'predictions.manifest.json').read_text())
    assert cm['status']=='complete' and cm['intervention']=='reserialisation_only'
    cr=PE.read_rows(control_dir/'predictions.jsonl')
    cs=json.loads((control_dir/'predictions.summary.json').read_text())
    assert PE.summarise(cr)==cs
    combined_dir=ROOT/D['followup_runs']['perturbation']['path']
    combined=PE.read_rows(combined_dir/'predictions.jsonl')
    prior=D['followup_runs']['perturbation']['manifest']
    assert cm['source_sha256']==prior['source_sha256']
    assert cm['fixtures_sha256']==prior['fixtures_sha256']
    assert cm['model']==prior['model'] and cm['rules']==prior['rules']
    source=ROOT/'data/processed/malware_benchmark.jsonl'
    fixtures=ROOT/'output/experiment-audit/perturbation-v2.jsonl'
    assert PE.digest(source)==cm['source_sha256'] and PE.digest(fixtures)==cm['fixtures_sha256']
    expected={a['sample_id']:hashlib.sha256(b['content'].encode()).hexdigest()
              for a,b,_ in PE.formatting_pairs(PE.pairs(PE.read_rows(source),PE.read_rows(fixtures)))}
    assert all(r['transformed_sha256']==expected[r['sample_id']] and not r['changed_ast'] for r in cr)
    assert PE.summarise(combined)==D['followup_runs']['perturbation']['summary']
    ci={(r['sample_id'],r['detector']):r for r in cr}
    pi={(r['sample_id'],r['detector']):r for r in combined}
    assert len(ci)==len(cr)==len(pi)==len(combined)==678
    assert ci.keys()==pi.keys()
    assert all(ci[k]['truth']==pi[k]['truth'] and ci[k]['source_sha256']==pi[k]['source_sha256'] for k in ci)
    rows=[];comparisons={}
    for detector in ['local-qwen-coder','yara']:
        keys=[k for k in ci if k[1]==detector]
        complete=[k for k in keys if all(type(r[a]['prediction']) is bool for r in (ci[k],pi[k]) for a in ('original','transformed'))]
        comparisons[detector]={'complete_three_arm_items':len(complete),
            'original_disagreements':sum(ci[k]['original']['prediction']!=pi[k]['original']['prediction'] for k in complete),
            'control_vs_split_flips':sum(ci[k]['transformed']['prediction']!=pi[k]['transformed']['prediction'] for k in complete)}
        for name,v in [('Original',PE.metrics([pi[k] for k in complete],'original')),
                       ('Reserialised only',PE.metrics([ci[k] for k in complete],'transformed')),
                       ('Reserialised + split',PE.metrics([pi[k] for k in complete],'transformed'))]:
            rows.append(['Qwen' if detector!='yara' else 'YARA subset',name,
                f"{v['tp']}/{v['tp']+v['fn']} ({v['recall']:.1%})",
                f"{v['fp']}/{v['fp']+v['tn']} ({v['false_positive_rate']:.1%})",f"{v['f1']:.3f}"])
    tables['CONTROL_RESULTS']=mdtable('Table 5. Three-arm comparison on matched identities and complete responses. The formatting control uses the same source, fixture eligibility, recorded model settings and rule files.',
                ['Detector','Input','Malicious recall','Benign false alarms','F1'],rows)
    tables['CONTROL_RESULTS']+='\n\nThe formatting-control run is data/results/formatting_control/20260915-project-report. '
    for detector,v in comparisons.items():
        tables['CONTROL_RESULTS']+=f"For {detector}, {v['complete_three_arm_items']} items have complete three-arm evidence; repeated original predictions disagree on {v['original_disagreements']} items, and the reserialised-only and split inputs differ on {v['control_vs_split_flips']} verdicts. "
    tables['CONTROL_RESULTS']+='This is a sequential, cache-enabled control on the same synthetic sample, not an independent replication or a test of unseen threat families. '
    control_hits=sum(r[a].get('cached',False) for r in cr for a in ('original','transformed'))
    tables['CONTROL_RESULTS']+=f"The control reused {control_hits} of 678 Qwen responses."
    (OUT/'project_report_control_evidence.json').write_text(json.dumps({'comparisons':comparisons,'manifest':cm,'summary':cs,
        'input_sha256':{str(p.relative_to(ROOT)):PE.digest(p) for p in control_dir.glob('*.json*')}},indent=2))
for key,value in tables.items():text=text.replace('{{'+key+'}}',value)
assert '{{' not in text
(OUT/(STEM+'.md')).write_text(text,encoding='utf-8')
ink=colors.HexColor('#142c36')
body=ParagraphStyle('body',fontName='Times-Roman',fontSize=10.5,leading=14.2,spaceAfter=7,alignment=TA_JUSTIFY)
title=ParagraphStyle('title',fontName='Helvetica-Bold',fontSize=19,leading=23,spaceAfter=14,textColor=ink)
h1=ParagraphStyle('h1',fontName='Helvetica-Bold',fontSize=12,leading=15,spaceBefore=12,spaceAfter=6,keepWithNext=True,textColor=ink)
h2=ParagraphStyle('h2',parent=h1,fontSize=10.5,leading=13)
cell=ParagraphStyle('cell',fontName='Times-Roman',fontSize=8.4,leading=11)
head=ParagraphStyle('head',parent=cell,fontName='Helvetica-Bold',textColor=colors.white)
cap=ParagraphStyle('cap',fontName='Helvetica',fontSize=8.5,leading=11,spaceAfter=6,keepWithNext=True)
ref=ParagraphStyle('ref',parent=body,fontSize=9,leading=12,alignment=0)


def markup(s):
    s=html.escape(s)
    s=re.sub(r'`([^`]+)`',lambda m:'<font face="Courier" size="8">'+m[1]+'</font>',s)
    s=re.sub(r'(https://[^\s]+)',lambda m:f'<link href="{m[1]}" color="#145a78">{m[1]}</link>',s)
    return s


story=[];lines=text.splitlines();i=0;references=False
while i<len(lines):
    line=lines[i].strip();i+=1
    if not line:continue
    if line.startswith('!['):
        match=re.fullmatch(r'!\[(.*?)\]\((.*?)\)',line)
        if not match:raise ValueError('Invalid report figure')
        caption,path=match.groups();path=ROOT/path
        with PILImage.open(path) as img:w,h=img.size
        width=min(470,280*w/h);height=width*h/w
        story.append(KeepTogether([Image(str(path),width=width,height=height),Paragraph(markup(caption),ref),Spacer(1,10)]))
        continue
    if line.startswith('|'):
        block=[line]
        while i<len(lines) and lines[i].strip().startswith('|'):
            block.append(lines[i].strip());i+=1
        raw=[[c.strip() for c in row.strip('|').split('|')] for j,row in enumerate(block) if j!=1]
        data=[[Paragraph(markup(v),head if j==0 else cell) for v in row] for j,row in enumerate(raw)]
        widths={3:[150,160,160],5:[100,110,90,110,60],6:[140,60,70,45,45,110]}[len(raw[0])]
        t=Table(data,colWidths=widths,repeatRows=1,hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),ink),('VALIGN',(0,0),(-1,-1),'TOP'),
            ('LINEBELOW',(0,1),(-1,-1),.3,colors.HexColor('#cbd4d7')),
            ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)]))
        story.extend([t,Spacer(1,9)]);continue
    if line.startswith('# '):style=title;line=line[2:]
    elif line.startswith('### '):style=h2;line=line[4:]
    elif line.startswith('## '):
        style=h1;line=line[3:];references=line=='References'
    elif re.match(r'^Table [0-9]+\.',line):style=cap
    else:
        style=ref if references else body
        while i<len(lines) and lines[i].strip() and not lines[i].startswith(('#','|')):
            line+=' '+lines[i].strip();i+=1
    story.append(Paragraph(markup(line),style))


def footer(canvas,doc):
    canvas.saveState();canvas.setFont('Helvetica',8);canvas.setFillColor(colors.HexColor('#607079'))
    canvas.drawString(62,28,'LLM-Assisted Security Assessment | '+('Project report' if PROJECT_REPORT else 'Research manuscript draft'))
    canvas.drawRightString(A4[0]-62,28,str(doc.page));canvas.restoreState()


pdf=OUT/(STEM+'.pdf')
SimpleDocTemplate(str(pdf),pagesize=A4,leftMargin=62,rightMargin=62,topMargin=48,bottomMargin=47,
                  title=text.splitlines()[0].lstrip('# '),author='Alireza Shahidiani').build(story,onFirstPage=footer,onLaterPages=footer)
(OUT/('project_report_manifest.json' if PROJECT_REPORT else 'paper_manifest.json')).write_text(json.dumps({'report_data_sha256':hashlib.sha256(DATA.read_bytes()).hexdigest(),
    'template_sha256':hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),
    'pdf_sha256':hashlib.sha256(pdf.read_bytes()).hexdigest(),'tables':5 if PROJECT_REPORT else 7},indent=2))
print(pdf)
