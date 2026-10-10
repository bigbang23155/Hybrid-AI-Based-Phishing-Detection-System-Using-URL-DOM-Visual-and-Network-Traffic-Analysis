"""Exploratory nested grouped CV for reviewed NEW development rows, never holdout.

No data acquisition, automatic relabeling, augmentation or external evaluation.
The caller supplies aligned 41-feature records and the actual review packets.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import time
import warnings
import platform
import sklearn
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import f1_score, confusion_matrix, roc_auc_score, average_precision_score
from .intake import HERE, read_rows, write_rows, write_json, digest, adjudicate
from .models import MODELS, make_model
from phishing_url.modality_contract import feature_names


def group_folds(y, groups, count, seed):
    if len(set(groups)) < count:
        raise ValueError('insufficient independent groups')
    folds = list(StratifiedGroupKFold(n_splits=count, shuffle=True, random_state=seed).split(np.zeros((len(y),1)),y,groups))
    for train, val in folds:
        if set(groups[train]) & set(groups[val]) or len(set(y[train])) != 2 or len(set(y[val])) != 2:
            raise ValueError('invalid fold: group overlap or missing class; do not search for a nicer seed')
    return folds


def validate_overlap_receipt(rows, history_path, receipt_path):
    receipt=json.loads(receipt_path.read_text())
    if receipt.get('status') != 'completed' or receipt.get('historical_registry_sha256') != digest(history_path):
        raise ValueError('missing or stale overlap receipt')
    checks={'pilot','sample_id','normalized_url','registered_domain','exact_html','structural_template','campaign'}
    if not checks <= set(receipt.get('completed_checks',[])):
        raise ValueError('incomplete overlap checks')
    bindings={r['sample_id']:r for r in receipt.get('candidates',[])}
    if len(bindings)!=len(receipt.get('candidates',[])) or set(bindings)!={r['sample_id'] for r in rows}:
        raise ValueError('overlap receipt membership mismatch')
    for row in rows:
        b=bindings[row['sample_id']]
        if (b.get('eligible_for_new_development') is not True or b.get('html_sha256')!=row['html_sha256']
                or row.get('overlap_audit_receipt_sha256')!=digest(receipt_path)):
            raise ValueError('overlap receipt content binding mismatch')
    # Recorded evidence is not itself an independent certification of the audit.
    if not receipt.get('evidence_sha256') or not receipt.get('reviewer_id'):
        raise ValueError('overlap audit evidence/reviewer missing')


def validate_cohort(rows, packets, history):
    if not rows or len({r['sample_id'] for r in rows}) != len(rows):
        raise ValueError('empty or duplicate cohort')
    if len({r['sample_id'] for r in packets}) != len(packets):
        raise ValueError('duplicate review packets')
    reviews = {r['sample_id']:r for r in packets}
    if set(reviews) != {r['sample_id'] for r in rows}:
        raise ValueError('review/cohort membership mismatch')
    keys = ('sample_id','html_sha256','registered_domain_sha256','final_group',
            'normalized_url_sha256','structural_sha256','campaign_id')
    denied = {key:{r[key] for r in history if r.get(key)} for key in keys}
    source_positions = {(r.get('source_revision', 'eabec4b7a66324b79cc8a0ad856d1731dc26fe1a'),
                         r['source_file'],r['source_row']) for r in history
                        if r.get('source_file') is not None and r.get('source_row') is not None}
    owners = {key:{} for key in ('registered_domain_sha256','html_sha256','normalized_url_sha256','structural_sha256','campaign_id')}
    names = list(feature_names('url_dom'))
    for row in rows:
        if row['scope'] != 'new_development':
            raise ValueError('only new_development allowed; historical/test/external rows rejected')
        if any(row.get(key) in denied[key] for key in keys):
            raise ValueError('historically exposed sample/domain/content/group')
        if (row.get('source_revision'),row.get('source_file'),row.get('source_row')) in source_positions:
            raise ValueError('historically exposed source row')
        if row.get('overlap_audit_status') != 'complete_with_pilot_url_template_campaign':
            raise ValueError('full overlap audit needed; basic denylist alone is insufficient')
        if not row.get('overlap_audit_receipt_sha256') or not row.get('source_family') or not row.get('captured_at'):
            raise ValueError('missing provenance')
        for key in owners:
            value = row.get(key)
            if key != 'campaign_id' and not value:raise ValueError('missing leakage key: '+key)
            if value:
                group = owners[key].setdefault(value, row['final_group'])
                if group != row['final_group']:raise ValueError('leakage component incorrectly split')
        packet = reviews[row['sample_id']]
        if packet['html_sha256'] != row['html_sha256'] or packet['captured_at'] != row['captured_at']:
            raise ValueError('review not bound to input snapshot/time')
        decision = adjudicate(packet)
        if decision['status'] != 'accepted_recorded_review' or decision['label'] != row['label']:
            raise ValueError('unreviewed, uncertain or inconsistent label')
        if set(row['features']) != set(names) or not np.isfinite([row['features'][n] for n in names]).all():
            raise ValueError('feature schema/order/finite value mismatch')
    if set(r['label'] for r in rows) != {0,1}:raise ValueError('both classes required')
    return names


def measures(y, score):
    prediction = score >= .5
    tn,fp,fn,tp = confusion_matrix(y,prediction,labels=[0,1]).ravel()
    return dict(f1=float(f1_score(y,prediction)),fpr=float(fp/(fp+tn)),recall=float(tp/(tp+fn)),
                fp=int(fp),fn=int(fn),roc_auc=float(roc_auc_score(y,score)),average_precision=float(average_precision_score(y,score)))


def choose_variant(metrics):
    # Predeclared near-tie rule, applied only to inner validation predictions.
    best = max(r['f1'] for r in metrics)
    eligible = [i for i,r in enumerate(metrics) if r['f1'] >= best-.005]
    return min(eligible,key=lambda i:(metrics[i]['fpr'],i))


def fitted(name, variant, seed, x, y, groups):
    calibration = group_folds(y,groups,3,seed) if name == 'rbf_svm' else None
    estimator = make_model(name,variant,seed,calibration)
    # Treat convergence warnings as recorded failed fits, not silent success.
    with warnings.catch_warnings():
        warnings.simplefilter('error')
        estimator.fit(x,y)
    return estimator


def compare(rows, names, output, protocol, provenance=None):
    y = np.array([r['label'] for r in rows]);groups=np.array([r['final_group'] for r in rows])
    full=np.array([[r['features'][n] for n in names] for r in rows])
    # Preflight ALL nested folds, including SVM calibration, before any fit.
    outer = group_folds(y,groups,protocol['experiments']['outer_group_folds'],protocol['seed'])
    for train,_ in outer:
        inner=group_folds(y[train],groups[train],protocol['experiments']['inner_group_folds'],protocol['seed'])
        for small,_ in inner:
            for seed in protocol['model_seeds']:group_folds(y[train][small],groups[train][small],3,seed)
        for seed in protocol['model_seeds']:group_folds(y[train],groups[train],3,seed)
    output.mkdir(parents=True,exist_ok=False)
    write_json(output/'provenance.json',dict(input_sha256=provenance or {},
               code_sha256={p.name:digest(p) for p in sorted(HERE.glob('*.py'))},
               protocol=protocol,python=platform.python_version(),numpy=np.__version__,sklearn=sklearn.__version__))
    write_rows(output/'folds.jsonl',[dict(outer_fold=i,train_ids=[rows[j]['sample_id'] for j in tr],validation_ids=[rows[j]['sample_id'] for j in va]) for i,(tr,va) in enumerate(outer)])
    predictions=[];results=[]
    write_json(output/'status.json',dict(status='running',scope='exploratory_new_development',no_external_evaluation=True))
    try:
        for seed in protocol['model_seeds']:
            for modality in protocol['experiments']['modalities']:
                columns=[names.index(n) for n in feature_names(modality)];x=full[:,columns]
                for name in MODELS:
                    for fold,(train,val) in enumerate(outer):
                        inner=group_folds(y[train],groups[train],protocol['experiments']['inner_group_folds'],protocol['seed'])
                        inner_metrics=[]
                        for variant in (0,1):
                            oof=np.full(len(train),np.nan)
                            for fit,check in inner:
                                estimator=fitted(name,variant,seed,x[train][fit],y[train][fit],groups[train][fit])
                                oof[check]=estimator.predict_proba(x[train][check])[:,1]
                            inner_metrics.append(measures(y[train],oof))
                        selected=choose_variant(inner_metrics)
                        start=time.perf_counter();estimator=fitted(name,selected,seed,x[train],y[train],groups[train]);fit_seconds=time.perf_counter()-start
                        start=time.perf_counter();score=estimator.predict_proba(x[val])[:,1];prediction_seconds=time.perf_counter()-start
                        condition=dict(seed=seed,model=name,modality=modality,outer_fold=fold)
                        results.append(dict(**condition,variant=selected,inner_metrics=inner_metrics,fit_seconds=fit_seconds,prediction_seconds=prediction_seconds,**measures(y[val],score)))
                        predictions.extend(dict(**condition,sample_id=rows[j]['sample_id'],final_group=str(groups[j]),label=int(y[j]),score=float(s)) for j,s in zip(val,score))
                        write_rows(output/'metrics.jsonl',results);write_rows(output/'predictions.jsonl',predictions)
        write_json(output/'status.json',dict(status='completed_exploratory_cv',outer_fit_cells=len(results),adversarial_or_external_claim=False,
                                            limitation='Not an independent final estimate after selecting an algorithm family; no promotion without subgroup/paired-interval review.'))
    except Exception as exc:
        write_json(output/'status.json',dict(status='failed_preserved_partial',error=type(exc).__name__+':'+str(exc)))
        raise


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('input','reviews','history','overlap-audit','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();rows=read_rows(a.input);packets=read_rows(a.reviews);history=read_rows(a.history)
    validate_overlap_receipt(rows,a.history,a.overlap_audit)
    names=validate_cohort(rows,packets,history)
    protocol=json.loads((HERE/'protocol.json').read_text())
    compare(rows,names,a.output,protocol,{str(f):digest(f) for f in (a.input,a.reviews,a.history,a.overlap_audit,HERE/'protocol.json')})


if __name__=='__main__':main()
