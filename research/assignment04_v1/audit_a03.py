"""Recompute descriptive complexity control from archived VALIDATION predictions.
No fit or inference. Fixed paths; old consumed test aggregates read for disclosure only.
"""
import argparse
import csv
import gzip
import hashlib
import json
from pathlib import Path
import numpy as np


def score(rows, weights=None):
    counts = dict.fromkeys(('tn','fp','fn','tp'), 0.)
    for i,row in enumerate(rows): counts[row['outcome']] += 1 if weights is None else weights[i]
    tn,fp,fn,tp = [counts[k] for k in ('tn','fp','fn','tp')]
    return dict(counts, f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
                fpr=fp/(tn+fp) if tn+fp else None, recall=tp/(tp+fn) if tp+fn else None)


def balanced_complexity(rows):
    # Equal class prevalence, uniform train-defined tag-count quartiles within class.
    counts = {(label,b):sum(r['label']==label and r['complexity_bin']==b for r in rows)
              for label in (0,1) for b in range(4)}
    if not all(counts.values()): return None
    return score(rows, [1/(8*counts[(r['label'],r['complexity_bin'])]) for r in rows])


def run(root):
    used = {}
    def read(path, gz=False):
        data = (root/path).read_bytes(); used[path]=hashlib.sha256(data).hexdigest()
        return gzip.decompress(data).decode() if gz else data.decode()
    predictions = [json.loads(x) for x in read('results/assignment03/development_v1/primary_validation_predictions.jsonl.gz', True).splitlines()]
    if any(r['partition']!='validation' for r in predictions): raise ValueError('validation_only')
    ledger = [json.loads(x) for x in read('results/assignment03/review_v1/error_ledger.jsonl.gz', True).splitlines()]
    index = {(r['condition'],r['sample_id']):r for r in predictions}
    if len(index)!=len(predictions) or len(ledger)!=len(index) or len({(r['condition'],r['sample_id']) for r in ledger}) != len(ledger): raise ValueError('nonunique_or_incomplete_pairs')
    for r in ledger:
        p=index[(r['condition'],r['sample_id'])]
        outcome = ('tp' if p['predicted'] else 'fn') if p['label'] else ('fp' if p['predicted'] else 'tn')
        if r['outcome']!=outcome or any(r[k]!=p[k] for k in ('label','final_group','score')):
            raise ValueError('prediction_ledger_mismatch')
    conditions = sorted(set(r['condition'] for r in ledger))
    by = {c: sorted([r for r in ledger if r['condition']==c],key=lambda r:r['sample_id']) for c in conditions}
    if any([r['sample_id'] for r in rows] != [r['sample_id'] for r in by[conditions[0]]] for rows in by.values()):
        raise ValueError('unpaired_comparison')
    comparison = {c:{'unadjusted':score(rows), 'standardized':balanced_complexity(rows),
        'strata':[dict(bin=b, n=sum(r['complexity_bin']==b for r in rows),
                       **score([r for r in rows if r['complexity_bin']==b])) for b in range(4)]}
        for c,rows in by.items()}
    # Paired whole-group resampling, re-standardizing each draw. Missing-stratum draws are counted.
    rng=np.random.default_rng(4940401)
    groups=sorted(set(r['final_group'] for r in by[conditions[0]]))
    group_rows={c:{g:[r for r in rows if r['final_group']==g] for g in groups} for c,rows in by.items()}
    deltas={family:[] for family in ('random_forest','gradient_boosting')}
    for _ in range(1000):
        draw=rng.choice(groups,len(groups),replace=True)
        metrics={c:balanced_complexity([r for g in draw for r in group_rows[c][g]]) for c in conditions}
        for family in deltas:
            a,b=metrics[family+'/url_only/baseline'],metrics[family+'/url_dom/baseline']
            if a is not None and b is not None: deltas[family].append(b['f1']-a['f1'])
    intervals={f:{'valid_draws':len(v),'invalid_draws':1000-len(v),
                  'f1_delta_percentile95':np.quantile(v,[.025,.975]).tolist() if v else None} for f,v in deltas.items()}
    metrics=list(csv.DictReader(read('results/assignment03/development_v1/metrics.csv').splitlines()))
    gaps=[]
    for c in conditions:
        pair={r['partition']:float(r['f1']) for r in metrics if r['condition']==c and r['seed']=='4941401'}
        gaps.append(dict(condition=c,train_f1=pair['train'],validation_f1=pair['validation'],gap=pair['train']-pair['validation']))
    old=json.loads(read('results/assignment03/final_test_v1/test_summary.json'))
    access=json.loads(read('results/assignment03/final_test_v1/test_access_started.json'))
    return {'method':'Post-exposure descriptive validation reanalysis; equal class x complexity-bin mass. No causal interpretation.',
        'complexity_cuts_from_training':[106,475,1083], 'comparison':comparison,
        'paired_group_bootstrap':intervals,'bootstrap_seed':4940401,'train_validation_gaps':gaps,
        'old_consumed_test':{'access_started_at':access['created_at'],'finished_at':old['finished_at'],
            'run_id':old['run_id'],'metrics':old['metrics'],'aggregate_archive_read_only':True},
        'limitations':['No joint HTML-byte-size control: row-level HTML bytes absent in retained development evidence.',
            'Coarse tag-count bins leave residual complexity/source/time confounding.',
            '464-row exclusion sensitivity requires development features/models; not executed.',
            'Bootstrap is descriptive and has no multiplicity correction.'],
        'inputs_sha256':used,'model_fits':0,'new_test_access':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=Path('.'));p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    result=run(a.root)
    with a.output.open('x') as f: json.dump(result,f,indent=2,allow_nan=False);f.write('\n')
