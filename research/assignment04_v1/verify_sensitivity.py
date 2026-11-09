"""Independent aggregate verification from sanitized validation predictions only."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import numpy as np


def verify(root, directory):
    summary=json.loads((directory/'summary.json').read_text())
    with gzip.open(directory/'validation_predictions.jsonl.gz','rt') as f:rows=[json.loads(x) for x in f]
    with gzip.open(root/'results/assignment03/holdout_v1/partition_manifest.jsonl.gz','rt') as f:manifest=[json.loads(x) for x in f]
    expected={r['sample_id']:r for r in manifest if r['partition']=='validation'}
    assert len(rows)==742 and len({r['sample_id'] for r in rows})==742
    assert set(expected)=={r['sample_id'] for r in rows}
    for r in rows:
        assert all(r[k]==expected[r['sample_id']][k] for k in ('partition','final_group','label'))
        assert r['joint_bin']==int(r['html_bytes']>=summary['joint_control']['cuts']['html_bytes'])*2+int(r['tag_count']>=summary['joint_control']['cuts']['tag_count'])
    y=np.array([r['label'] for r in rows]);bins=np.array([r['joint_bin'] for r in rows]);cells=y*4+bins
    support=summary['joint_control']['supported_bins']
    def weights(m):
        counts=np.bincount(cells,weights=m,minlength=8)
        if any(counts[c*4+b]==0 for c in (0,1) for b in support):return None
        out=np.zeros(len(rows))
        for c in (0,1):
            for b in support:
                ix=cells==c*4+b;out[ix]=m[ix]/counts[c*4+b]/(2*len(support))
        return out
    def metric(s,w):
        pred=np.asarray(s)>=.5
        tp=w[(y==1)&pred].sum();fn=w[(y==1)&~pred].sum()
        fp=w[(y==0)&pred].sum();tn=w[(y==0)&~pred].sum()
        return {'f1':2*tp/(2*tp+fp+fn),'fpr':fp/(fp+tn),'recall':tp/(tp+fn),
                'accuracy':(tp+tn)/w.sum(),'precision':tp/(tp+fp) if tp+fp else 0,
                'tp':tp,'tn':tn,'fp':fp,'fn':fn}
    keys=set(rows[0]['scores']);assert len(keys)==12 and all(set(r['scores'])==keys for r in rows)
    scores={k:np.array([r['scores'][k] for r in rows]) for k in keys}
    w=weights(np.ones(len(rows)));assert w is not None
    for cell in summary['metrics']:
        for field,weight in [('validation',np.ones(len(rows))),('joint_standardized_validation',w)]:
            actual=metric(scores[cell['condition']],weight)
            for key,val in actual.items():assert abs(val-cell[field][key])<1e-12,(cell['condition'],key)
    groups,inv=np.unique([r['final_group'] for r in rows],return_inverse=True)
    rng=np.random.default_rng(summary['plan']['bootstrap']['seed'])
    contrasts=summary['paired_standardized_f1_contrasts'];dist=[[] for c in contrasts];invalid=0
    for _ in range(2000):
        m=np.bincount(rng.integers(0,len(groups),len(groups)),minlength=len(groups))[inv]
        bw=weights(m)
        if bw is None:invalid+=1;continue
        f1={k:metric(s,bw)['f1'] for k,s in scores.items()}
        for i,c in enumerate(contrasts):dist[i].append(f1[c['a']]-f1[c['b']])
    assert invalid==summary['joint_control']['bootstrap_invalid_draws']
    for c,d in zip(contrasts,dist):
        assert c['valid_draws']==len(d)
        np.testing.assert_allclose(c['percentile95'],np.quantile(d,[.025,.975]),atol=1e-12,rtol=0)
        np.testing.assert_allclose(c['delta'],metric(scores[c['a']],w)['f1']-metric(scores[c['b']],w)['f1'],atol=1e-12,rtol=0)
    return {'status':'independently_verified','validation_rows':742,'model_conditions':12,
            'metrics_checked_per_condition':18,'paired_intervals_checked':len(contrasts),'bootstrap_draws':2000,
            'new_test_read':False,'files_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [directory/'summary.json',directory/'validation_predictions.jsonl.gz']}}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=Path('.'));p.add_argument('--directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=verify(a.root,a.directory)
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
