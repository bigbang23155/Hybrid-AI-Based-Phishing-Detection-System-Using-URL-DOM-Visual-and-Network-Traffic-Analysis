"""Independent checks of public development evidence; does not load models/HTML."""
import argparse
from collections import defaultdict
import csv
import gzip
import hashlib
import json
from pathlib import Path

import numpy as np
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             roc_auc_score, average_precision_score, brier_score_loss, confusion_matrix)


def verify(public, repository):
    protocol=json.loads((repository/'config/assignment03_modeling_protocol_v1.json').read_text())
    raw=gzip.decompress((repository/'results/assignment03/holdout_v1/partition_manifest.jsonl.gz').read_bytes())
    assert hashlib.sha256(raw).hexdigest()==protocol['partition_manifest_sha256']
    manifest=[json.loads(x) for x in raw.splitlines()]
    expected={r['sample_id']:r for r in manifest if r['partition']=='validation'}
    sealed={r['sample_id'] for r in manifest if r['partition']=='test'}
    rows=[json.loads(x) for x in (public/'models/validation_predictions.jsonl').read_text().splitlines()]
    conditions=defaultdict(dict)
    for r in rows:
        sid=r['sample_id']; key=(r['condition'],r['seed'])
        assert sid in expected and sid not in sealed and r['partition']=='validation'
        assert sid not in conditions[key]
        assert r['label']==expected[sid]['label'] and r['final_group']==expected[sid]['final_group']
        assert r['predicted']==int(r['score']>=protocol['threshold'])
        conditions[key][sid]=r
    metrics={(r['condition'],int(r['seed']),r['partition']):r for r in csv.DictReader((public/'models/metrics.csv').open())}
    assert len(conditions)==70 and len(metrics)==140
    assert all(set(v)==set(expected) for v in conditions.values())
    ids=sorted(expected); y=np.array([expected[s]['label'] for s in ids])
    primary={}
    max_diff=0.0
    for (condition,seed), data in conditions.items():
        s=np.array([data[i]['score'] for i in ids]); pred=s>=protocol['threshold']
        tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
        actual=dict(accuracy=accuracy_score(y,pred),precision=precision_score(y,pred,zero_division=0),
                    recall=recall_score(y,pred),f1=f1_score(y,pred),fpr=fp/(fp+tn),
                    roc_auc=roc_auc_score(y,s),average_precision=average_precision_score(y,s),
                    brier_score=brier_score_loss(y,s),tn=tn,fp=fp,fn=fn,tp=tp)
        for name,value in actual.items():
            diff=abs(value-float(metrics[condition,seed,'validation'][name]));max_diff=max(max_diff,diff)
            assert diff<1e-12,(condition,seed,name,diff)
        if seed==protocol['primary_model_seed'] and condition.endswith('/baseline'):
            primary[condition]=pred
    # Independent bootstrap recomputation of headline F1 and its paired contrasts.
    names=sorted({r['final_group'] for r in expected.values()})
    members=[np.array([i for i,s in enumerate(ids) if expected[s]['final_group']==g]) for g in names]
    rng=np.random.default_rng(protocol['uncertainty']['seed'])
    boot=defaultdict(list);delta=defaultdict(list)
    for _ in range(protocol['uncertainty']['resamples']):
        picked=rng.choice(len(names),size=len(names),replace=True)
        idx=np.concatenate([members[g] for g in picked])
        score={key: f1_score(y[idx],pred[idx],zero_division=0) for key,pred in primary.items()}
        for key,value in score.items():boot[key].append(value)
        for model in protocol['models']:
            for other in ('url_only','dom_only'):
                delta[f'{model}/url_dom-minus-{other}'].append(score[f'{model}/url_dom/baseline']-score[f'{model}/{other}/baseline'])
    saved=json.loads((public/'models/bootstrap_intervals.json').read_text())
    for data,section in ((boot,'cells'),(delta,'paired_differences')):
        for key,values in data.items():
            low,high=np.quantile(values,[.025,.975]); target=saved[section][key]['f1']
            assert abs(low-target['low'])<1e-12 and abs(high-target['high'])<1e-12
    integrity=json.loads((public/'features/feature_integrity.json').read_text())
    assert integrity['successes']==4203 and integrity['failures']==0 and integrity['test_feature_rows']==0
    statuses=[json.loads(x) for x in (public/'features/extraction_status.jsonl').read_text().splitlines()]
    dev={r['sample_id'] for r in manifest if r['partition'] in ('train','validation')}
    assert len(statuses)==len(dev)==4203 and {r['sample_id'] for r in statuses}==dev
    assert all(r['extraction_status']=='ok' for r in statuses)
    assert not list(public.rglob('*.joblib'))
    return dict(verification_passed=True,validation_conditions=70,validation_predictions=len(rows),
                validation_rows_per_condition=len(expected),independent_sklearn_metric_recompute=True,
                maximum_metric_difference=float(max_diff),independent_resampled_row_f1_intervals=True,
                paired_f1_intervals_verified=True,development_status_records=4203,
                sealed_test_prediction_overlap=0,train_metrics_recomputed=False,
                limitation='Train metrics are execution evidence; only validation scores are independently recomputed here.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--public',type=Path,required=True)
    p.add_argument('--repository',type=Path,default=Path('.'))
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();result=verify(a.public,a.repository)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,indent=2))
