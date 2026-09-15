"""Generate referee-response evidence without model calls or fixture execution."""
import collections
import hashlib
import json
import random
import shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'output/paper'
def load(p):return [json.loads(l) for l in (ROOT/p).read_text(encoding='utf-8').splitlines() if l.strip()]
pred=load('data/results/predictions.jsonl')
test=load('data/processed/test.jsonl')
expected=collections.Counter(r['sample_id'] for r in random.Random(42).sample(test,600))
actual=collections.Counter(r['sample_id'] for r in pred if r['model']=='local-qwen-coder' and r['strategy']=='zero_shot')
mal=load('data/processed/malware_benchmark.jsonl')
mp=load('data/results/malware_predictions.jsonl')
prefix_match={r['sample_id'] for r in mp}=={r['sample_id'] for r in mal[:300]}
repo=load('data/results/repo_bench_v2/20260915-022618/predictions.jsonl')
bench={r['case_id']:r for r in load('data/processed/repo_benchmark.jsonl')}
evidence={'vulnerability_seed42_sample_multiset_matches':expected==actual,
          'malware_first300_identity_set_matches':prefix_match,
          'vulnerability_sample_language':dict(collections.Counter(r['language'] for r in pred if r['model']=='local-qwen-coder' and r['strategy']=='zero_shot')),
          'repository_scored_languages':dict(collections.Counter(r['language'] for r in repo)),
          'python_families':dict(collections.Counter(r.get('technique') or 'benign_unspecified' for r in mal if r['language']=='python'))}
cards=[]
for r in repo:
    if not r['detected']:continue
    b=bench[r['case_id']]
    cards.append({'case_id':r['case_id'],'repo':r['repo'],'fix_sha':b['fix_sha'],
        'cve_id':r['cve_id'],'cwe_primary':b['cwe_primary'],'targets':b['targets'],
        'recorded_exact_body_hit':r['localised'],'recorded_cwe_match':r['cwe_strict'],
        'finding_evidence':'not retained in this run output','human_verdict':None,
        'reviewer':None,'rationale':None,'status':'awaiting finding recovery and human adjudication'})
(OUT/'target_file_hit_review.json').write_text(json.dumps(cards,indent=2),encoding='utf-8')
(OUT/'revision_evidence.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
paired=load('data/results/perturbation_v2/20260915-025616/predictions.jsonl')
summary=json.loads((ROOT/'data/results/perturbation_v2/20260915-025616/predictions.summary.json').read_text())
evidence['cache_hits_by_arm']={a:sum(r[a].get('cached',False) for r in paired if r['detector']=='local-qwen-coder') for a in ('original','transformed')}
evidence['paired_by_family']={k:v['by_family'] for k,v in summary.items()}
evidence['examples_selection']='First five sample IDs in lexical order among detector disagreements on the original arm; benchmark-label errors, not adjudicated defects.'
by_id=collections.defaultdict(dict)
for r in paired:by_id[r['sample_id']][r['detector']]=r
examples=[]
for sid,rs in sorted(by_id.items()):
    a,b=rs['local-qwen-coder'],rs['yara']
    if a['original']['prediction']!=b['original']['prediction']:
        examples.append({'sample_id':sid,'family':a['family'],'label':a['truth'],
                         'qwen':a['original']['prediction'],'yara':b['original']['prediction']})
evidence['disagreement_examples']=examples[:5]
source_dir=OUT/'method_sources';source_dir.mkdir(exist_ok=True)
evidence['current_method_source_sha256']={}
for name in ['prompts.py','evaluate.py','malware_evaluate.py','perturbation_eval.py','perturbation_v2.py','repo_bench_build.py','repo_bench_eval.py','models.py']:
    src=ROOT/'src'/name;shutil.copyfile(src,source_dir/name)
    evidence['current_method_source_sha256'][name]=hashlib.sha256(src.read_bytes()).hexdigest()
shutil.copyfile(ROOT/'data/processed/label_space.json',source_dir/'label_space.json')
(OUT/'revision_evidence.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
print(json.dumps(evidence,indent=2))
