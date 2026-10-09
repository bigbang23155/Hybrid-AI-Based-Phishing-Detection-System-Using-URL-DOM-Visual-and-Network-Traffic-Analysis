"""Recalculate all six test metrics independently from sanitized predictions.

No model load, fit, feature access or second inference. Bootstrap F1 checks use
explicitly resampled rows and sklearn, independently of weighted implementation.
"""
import argparse
from collections import Counter,defaultdict
import gzip
import json
from pathlib import Path
import numpy as np
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,roc_auc_score,average_precision_score,brier_score_loss,confusion_matrix
from phishing_url.final_test import validate_execution
from phishing_url.modality_contract import read_locked_manifest


def read_rows(path):
    if not path.exists():path=path.with_suffix(path.suffix+'.gz')
    raw=path.read_bytes()
    if path.suffix=='.gz':raw=gzip.decompress(raw)
    return [json.loads(r) for r in raw.splitlines()]


def independent_metrics(y,score,slice_mode=False):
    y=np.asarray(y);score=np.asarray(score);pred=score>=.5
    tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel().tolist()
    both=len(set(y.tolist()))==2
    return dict(accuracy=accuracy_score(y,pred),precision=precision_score(y,pred,zero_division=0),
        recall=recall_score(y,pred,zero_division=0) if tp+fn or not slice_mode else None,
        f1=f1_score(y,pred,zero_division=0),fpr=fp/(fp+tn) if fp+tn else None if slice_mode else 0,
        tn=tn,fp=fp,fn=fn,tp=tp,brier_score=brier_score_loss(y,score),
        roc_auc=roc_auc_score(y,score) if both else None,average_precision=average_precision_score(y,score) if both else None)


def match(expected,actual):
    for name,v in expected.items():
        a=actual[name]
        if v is None:
            if a is not None:raise ValueError('undefined metric misreported: '+name)
        elif a is None or not np.isclose(a,v,rtol=0,atol=1e-12):raise ValueError('metric mismatch: '+name)


def verify_result(root,public):
    lock,cfg=validate_execution(root)
    manifest=read_locked_manifest(root/'results/assignment03/holdout_v1/partition_manifest.jsonl.gz',lock)
    test={r['sample_id']:r for r in manifest if r['partition']=='test'};ids=sorted(test)
    predictions=read_rows(public/'test_predictions.jsonl');by=defaultdict(dict)
    for r in predictions:
        if r['condition'] in by and r['sample_id'] in by[r['condition']]:raise ValueError('duplicate prediction')
        ref=test[r['sample_id']]
        if r['partition']!='test' or r['seed']!=lock['seed'] or r['label']!=ref['label'] or r['final_group']!=ref['final_group'] or r['predicted']!=int(r['score']>=lock['threshold']):raise ValueError('prediction identity mismatch')
        if not 0<=r['score']<=1:raise ValueError('invalid score')
        by[r['condition']][r['sample_id']]=r
    if set(by)!={c['condition'] for c in lock['evaluation_cells']}:raise ValueError('missing/extra cells')
    if any(set(rows)!=set(test) for rows in by.values()):raise ValueError('test membership mismatch')
    y=np.asarray([test[s]['label'] for s in ids]);scores={c:np.asarray([rows[s]['score'] for s in ids]) for c,rows in by.items()}
    reports=json.loads((public/'metrics.json').read_text())
    if len(reports)!=6 or {r['condition'] for r in reports}!=set(by):raise ValueError('metrics cells mismatch')
    for r in reports:
        if r['n']!=len(ids):raise ValueError('metric denominator mismatch')
        match(independent_metrics(y,scores[r['condition']]),r)
    ledger=read_rows(public/'error_ledger.jsonl');li=defaultdict(dict)
    for r in ledger:
        c,s=r['condition'],r['sample_id']
        if s in li[c]:raise ValueError('duplicate error ledger')
        ref=by[c][s]
        for k in ('label','score','predicted','partition','final_group'):
            if r[k]!=ref[k]:raise ValueError('ledger differs from prediction')
        outcome=('tp' if ref['predicted'] else 'fn') if ref['label'] else ('fp' if ref['predicted'] else 'tn')
        if r['outcome']!=outcome:raise ValueError('wrong error class')
        li[c][s]=r
    if set(li)!=set(by) or any(set(v)!=set(test) for v in li.values()):raise ValueError('incomplete ledger')
    slices=json.loads((public/'slices.json').read_text());checked=0
    for r in slices:
        def value(row):
            if r['facet']=='password_x_complexity':return f"{row['password_present']}:{row['complexity_bin']}"
            return str(row[r['facet']])
        members=[v for v in li[r['condition']].values() if value(v)==r['value']]
        if len(members)!=r['n'] or len({v['final_group'] for v in members})!=r['groups']:raise ValueError('slice count mismatch')
        match(independent_metrics([v['label'] for v in members],[v['score'] for v in members],True),r);checked+=1
    paired=json.loads((public/'paired_error_cohorts.json').read_text())
    changes=read_rows(public/'paired_changes.jsonl');expected_changes=set()
    for r in paired:
        h=scores[r['model']+'/url_dom/baseline']>=.5;b=scores[r['model']+'/'+r['comparator']+'/baseline']>=.5
        hc=h==y;bc=b==y;masks=dict(fixes=hc&~bc,breaks=~hc&bc,both_wrong=~hc&~bc,both_correct=hc&bc);mask=masks[r['kind']]
        if int(mask.sum())!=r['n'] or int(np.sum(mask&(y==0)))!=r['benign'] or int(np.sum(mask&(y==1)))!=r['phishing']:raise ValueError('paired counts mismatch')
        if r['kind'] in ('fixes','breaks'):
            expected_changes.update((r['model'],r['comparator'],r['kind'],ids[i]) for i in np.flatnonzero(mask))
    actual_changes={(r['model'],r['comparator'],r['kind'],r['sample_id']) for r in changes}
    if len(changes)!=len(actual_changes) or actual_changes!=expected_changes:raise ValueError('paired change ledger mismatch')
    groups=sorted({test[s]['final_group'] for s in ids});members=[np.asarray([i for i,s in enumerate(ids) if test[s]['final_group']==g]) for g in groups]
    boot=json.loads((public/'bootstrap_intervals.json').read_text());values=defaultdict(list);diff=defaultdict(list)
    rng=np.random.default_rng(lock['uncertainty']['seed'])
    for _ in range(lock['uncertainty']['resamples']):
        ix=np.concatenate([members[i] for i in rng.integers(len(groups),size=len(groups))])
        f={c:f1_score(y[ix],s[ix]>=.5,zero_division=0) for c,s in scores.items()}
        for c,v in f.items():values[c].append(v)
        for model in ('random_forest','gradient_boosting'):
            for other in ('url_only','dom_only'):diff[model+'/url_dom-minus-'+other].append(f[model+'/url_dom/baseline']-f[model+'/'+other+'/baseline'])
    for field,data in [('cells',values),('paired_differences',diff)]:
        for c,v in data.items():
            low,high=np.quantile(v,[.025,.975]);match(dict(low=low,high=high,valid_replicates=len(v)),boot[field][c]['f1'])
    statuses=read_rows(public/'test_features/extraction_status.jsonl')
    if len(statuses)!=len(ids) or {r['sample_id'] for r in statuses}!=set(ids) or any(r['extraction_status']!='ok' or r['partition']!='test' for r in statuses):raise ValueError('extraction coverage mismatch')
    summary=json.loads((public/'test_summary.json').read_text())
    if summary['test_predictions']!=6*len(ids) or summary['test_rows']!=len(ids) or summary['test_groups']!=len(groups) or summary['test_fits']!=0:raise ValueError('summary count mismatch')
    if list(public.rglob('*.joblib')):raise ValueError('private models in public artifact')
    return dict(verification_passed=True,freeze_sha256=cfg['freeze_sha256'],test_rows=len(ids),test_groups=len(groups),
        cells=6,predictions=len(predictions),slices_independently_recalculated=checked,paired_change_records=len(changes),
        bootstrap_replicates_independently_checked=lock['uncertainty']['resamples'],bootstrap_checks='all six F1 intervals and four paired F1 intervals, explicit group resampling with sklearn',
        metrics_checked=lock['metrics'],no_second_inference=True,
        limits=['Slice metadata depend on frozen extraction; independent source-label adjudication not performed.',
                'AUC/AP/Brier bootstrap intervals use frozen previously tested metric code; only point metrics and F1 intervals are independently recomputed here.'])

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=Path('.'));p.add_argument('--public',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    r=verify_result(a.root,a.public);a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
