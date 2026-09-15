"""Paired, static-only evaluation of validated Python perturbation fixtures."""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import random
import time

from perturbation_v2 import FoldStrings

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_rows(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def unique(rows):
    result = {}
    for row in rows:
        key = row['sample_id']
        if key in result:
            raise ValueError(f'Duplicate sample identity: {key}')
        result[key] = row
    return result


def pairs(source, fixtures):
    originals = unique(source)
    unique(fixtures)
    result = []
    for fixture in fixtures:
        original = originals[fixture['sample_id']]
        if original.get('language') != 'python' or fixture.get('schema_version') != 2:
            raise ValueError('Unsupported fixture language/schema')
        if hashlib.sha256(original['content'].encode()).hexdigest() != fixture['source_sha256']:
            raise ValueError('Original source hash mismatch')
        if type(original['is_malicious']) not in (bool, int) or original['is_malicious'] not in (0, 1):
            raise ValueError('Invalid truth label')
        if original['is_malicious'] != fixture['is_malicious']:
            raise ValueError('Pair truth mismatch')
        a, b = ast.parse(original['content']), ast.parse(fixture['content'])
        canonical = lambda tree: ast.dump(FoldStrings().visit(copy.deepcopy(tree)), include_attributes=False)
        if canonical(a) != canonical(b):
            raise ValueError('Literal-folded AST mismatch')
        result.append((original, fixture, ast.dump(a) != ast.dump(b)))
    if not result:
        raise ValueError('No eligible pairs')
    return result


def strict_prediction(text):
    text = text.strip()
    if text.startswith('```') and text.endswith('```'):
        text = text.split('\n', 1)[1].rsplit('```', 1)[0].strip()
    try:
        obj = json.loads(text)
        value = obj.get('malicious')
        return value if type(value) is bool else None
    except (ValueError, AttributeError):
        return None


def formatting_pairs(validated):
    """Reserialise exactly the eligible inputs without altering their ASTs."""
    result = []
    for original, fixture, _ in validated:
        tree = ast.parse(original['content'])
        content = ast.unparse(tree)+'\n'
        if ast.dump(tree) != ast.dump(ast.parse(content)):
            raise ValueError('Formatting control changed AST')
        result.append((original, {**fixture, 'content': content}, False))
    return result


def metrics(rows, arm):
    tp = sum(r['truth'] and r[arm]['prediction'] for r in rows)
    fp = sum(not r['truth'] and r[arm]['prediction'] for r in rows)
    fn = sum(r['truth'] and not r[arm]['prediction'] for r in rows)
    tn = len(rows) - tp - fp - fn
    ratio = lambda n, d: n / d if d else None
    return dict(n=len(rows), tp=tp, fp=fp, tn=tn, fn=fn,
                recall=ratio(tp, tp+fn), false_positive_rate=ratio(fp, fp+tn),
                precision=ratio(tp, tp+fp), f1=ratio(2*tp, 2*tp+fp+fn))


def summarise(records):
    summary = {}
    for detector in sorted({r['detector'] for r in records}):
        attempted = [r for r in records if r['detector'] == detector]
        good = [r for r in attempted if all(type(r[a]['prediction']) is bool for a in ('original', 'transformed'))]
        def section(rows):
            return {'original': metrics(rows, 'original'), 'transformed': metrics(rows, 'transformed'),
                    'positive_to_negative': sum(r['original']['prediction'] and not r['transformed']['prediction'] for r in rows),
                    'negative_to_positive': sum(not r['original']['prediction'] and r['transformed']['prediction'] for r in rows)}
        summary[detector] = {'attempted_pairs': len(attempted), 'complete_pairs': len(good),
                             'failed_pairs': len(attempted)-len(good),
                             'changed_ast_pairs': sum(r['changed_ast'] for r in attempted),
                             'all_complete_pairs': section(good),
                             'changed_ast_only': section([r for r in good if r['changed_ast']]),
                             'by_family': {f: section([r for r in good if r['family'] == f]) for f in sorted({r['family'] for r in good})}}
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', type=Path, default=ROOT/'data/processed/malware_benchmark.jsonl')
    ap.add_argument('--fixtures', type=Path, default=ROOT/'output/experiment-audit/perturbation-v2.jsonl')
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--with-llm', action='store_true')
    ap.add_argument('--model', default='local-qwen-coder')
    ap.add_argument('--strategy', choices=['zero_shot', 'triage'], default='zero_shot')
    ap.add_argument('--limit', type=int, default=0, help='Smoke-test pair limit; 0 means all')
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--fresh', action='store_true', help='Disable LLM response cache')
    ap.add_argument('--formatting-control', action='store_true',
                    help='Use AST reserialisation without literal splitting on the same eligible pairs')
    args = ap.parse_args()
    if args.limit < 0:
        ap.error('--limit must be nonnegative')
    selected = pairs(read_rows(args.source), read_rows(args.fixtures))
    if args.formatting_control:
        selected = formatting_pairs(selected)
    random.Random(args.seed).shuffle(selected)
    if args.limit:
        selected = selected[:args.limit]
    paths = [args.out, args.out.with_suffix('.summary.json'), args.out.with_suffix('.manifest.json')]
    if any(p.exists() for p in paths):
        ap.error('Output already exists; choose a new run directory (automatic resume is not supported)')

    import malware_evaluate as MAL
    import yara
    rules, rule_manifest = [], []
    for path in sorted(MAL.RULES_DIR.glob('*.yar')):
        item = {'file': path.name, 'sha256': digest(path)}
        try:
            rules.append(yara.compile(filepath=str(path)))
            item['status'] = 'compiled'
        except Exception as exc:
            item['status'] = 'compile_failed'
            item['error_type'] = type(exc).__name__
        rule_manifest.append(item)
    if not rules:
        ap.error('No YARA rules compiled; refusing an empty baseline')
    provider = None
    if args.with_llm:
        import models
        provider = models.get(args.model)
        if not provider.is_available():
            ap.error('Requested model is unavailable')
    manifest = {'status': 'started', 'schema_version': 1, 'seed': args.seed,
                'source_sha256': digest(args.source), 'fixtures_sha256': digest(args.fixtures),
                'source_code_sha256': {p.name: digest(p) for p in Path(__file__).parent.glob('*.py')},
                'n_pairs': len(selected), 'yara_version': yara.__version__, 'rules': rule_manifest,
                'intervention': 'reserialisation_only' if args.formatting_control else 'reserialisation_plus_literal_splitting',
                'strategy': args.strategy, 'cache_policy': 'disabled' if args.fresh else 'reuse recorded; not independent replicates',
                'model': None if provider is None else {k: getattr(provider, k) for k in ('name', 'model', 'temperature', 'max_tokens')},
                'started_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
                'scope': 'Python AST reserialisation control' if args.formatting_control else 'Restricted Python literal perturbations; descriptive paired results, no population significance claim'}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    paths[2].write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    def detect(detector, content, filename):
        try:
            if detector == 'yara':
                # Evaluate all rules: a match must not hide failure in another rule.
                matches = [rule.match(data=content, timeout=30) for rule in rules]
                return {'prediction': any(matches), 'status': 'ok'}
            system, user = MAL.STRATEGIES[args.strategy]({'content': content, 'filename': filename})
            reply = provider.generate(system, user, use_cache=not args.fresh)
            pred = strict_prediction(reply.text) if reply.ok else None
            return {'prediction': pred, 'status': 'ok' if pred is not None else 'invalid_or_failed_reply',
                    'cached': reply.cached, 'latency_s': reply.latency_s, 'response': reply.text}
        except Exception as exc:
            return {'prediction': None, 'status': 'error', 'error_type': type(exc).__name__}
    records = []
    rng = random.Random(args.seed)
    with args.out.open('x', encoding='utf-8') as fh:
        for i, (original, fixture, changed) in enumerate(selected, 1):
            for detector in (['yara', args.model] if provider else ['yara']):
                row = {'sample_id': original['sample_id'], 'truth': bool(original['is_malicious']),
                       'family': str(original.get('technique') or 'benign_unspecified'),
                       'source_sha256': fixture['source_sha256'],
                       'transformed_sha256': hashlib.sha256(fixture['content'].encode()).hexdigest(),
                       'changed_ast': changed, 'detector': detector}
                order = ['original', 'transformed']
                rng.shuffle(order)
                row['evaluation_order'] = order
                for arm in order:
                    source = original if arm == 'original' else fixture
                    row[arm] = detect(detector, source['content'], original.get('filename', 'sample.py'))
                records.append(row)
                fh.write(json.dumps(row)+'\n'); fh.flush(); os.fsync(fh.fileno())
            print(f'{i}/{len(selected)} pairs checkpointed', flush=True)
    result = summarise(records)
    paths[1].write_text(json.dumps(result, indent=2), encoding='utf-8')
    manifest['status'] = 'complete'
    manifest['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    paths[2].write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(f'Summary: {paths[1]}')
    print(json.dumps({k: {f: v[f] for f in ('attempted_pairs', 'complete_pairs', 'failed_pairs')} for k,v in result.items()}, indent=2))


if __name__ == '__main__':
    main()
