"""Independent audit of the development review's sanitized evidence."""
import argparse
from collections import Counter,defaultdict
import gzip,hashlib,json
from pathlib import Path
import numpy as np
from sklearn.metrics import confusion_matrix,f1_score,roc_auc_score,brier_score_loss


def verify(public,root):
    cfg=json.loads((root/'config/assignment03_development_review_v1.json').read_text())
    raw=gzip.decompress((root/cfg['reference_predictions_path']).read_bytes())
    assert hashlib.sha256(raw).hexdigest()==cfg['reference_predictions_raw_sha256']
    ref={(r['condition'],r['sample_id']):r for r in map(json.loads,raw.splitlines())}
    manifest=list(map(json.loads,gzip.decompress((root/'results/assignment03/holdout_v1/partition_manifest.jsonl.gz').read_bytes()).splitlines()))
    val={r['sample_id']:r for r in manifest if r['partition']=='validation'}
    dev={r['sample_id'] for r in manifest if r['partition'] in ('train','validation')}
    rows=list(map(json.loads,(public/'error_ledger.jsonl').read_text().splitlines()))
    assert len(rows)==len(ref)==4452
    lookup={};by=defaultdict(list)
    for r in rows:
        key=(r['condition'],r['sample_id']);assert key not in lookup
        a=ref[key];m=val[r['sample_id']]
        assert r['label']==a['label']==m['label'] and r['final_group']==m['final_group']
        assert r['source_shard']==m['source_file']
        assert abs(r['score']-a['score'])<=cfg['model_replay_max_absolute_score_error']
        assert r['outcome']==('tp' if r['score']>=.5 else 'fn') if r['label']==1 else r['outcome']==('fp' if r['score']>=.5 else 'tn')
        lookup[key]=r;by[r['condition']].append(r)
    assert len(by)==6 and all({r['sample_id'] for r in rr}==set(val) for rr in by.values())
    slices=json.loads((public/'slices.json').read_text());checked=0
    for s in slices:
        rr=by[s['condition']]
        if s['facet']=='password_x_complexity': selected=[r for r in rr if f"{r['password_present']}:{r['complexity_bin']}"==s['value']]
        elif s['facet']=='language':continue
        else:selected=[r for r in rr if str(r[s['facet']])==s['value']]
        y=[r['label'] for r in selected];pred=[r['score']>=.5 for r in selected]
        tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
        assert [tn,fp,fn,tp]==[s[k] for k in ('tn','fp','fn','tp')] and len(selected)==s['n']
        assert abs(f1_score(y,pred,zero_division=0)-s['f1'])<1e-12
        assert s['positive_n']==tp+fn and s['negative_n']==tn+fp
        assert s['fpr'] is None if tn+fp==0 else abs(s['fpr']-fp/(tn+fp))<1e-12
        assert s['recall'] is None if tp+fn==0 else abs(s['recall']-tp/(tp+fn))<1e-12
        checked+=1
    old=json.loads((root/'results/assignment03/development_v1/development_review.json').read_text())
    prior={(r['condition'],r['facet'],r['value']):r for r in old['validation_strata_with_denominators']}
    for s in slices:
        if s['facet'] in ('language','month','password_present'):
            a=prior[s['condition'],s['facet'],s['value']]
            assert all(s[k]==a[k] for k in ('n','tn','fp','fn','tp'))
    changes=list(map(json.loads,(public/'paired_changes.jsonl').read_text().splitlines()))
    for r in changes:
        sid=r['sample_id'];h=lookup[f"{r['model']}/url_dom/baseline",sid];b=lookup[f"{r['model']}/{r['comparator']}/baseline",sid]
        assert h['label']==b['label']==r['label']
        assert r['kind']==('fixes' if h['outcome'] in ('tp','tn') else 'breaks')
        assert (h['outcome'] in ('tp','tn')) != (b['outcome'] in ('tp','tn'))
    cohorts=json.loads((public/'paired_error_cohorts.json').read_text())
    for c in cohorts:
        rr=by[f"{c['model']}/url_dom/baseline"]
        selected=[]
        for r in rr:
            a=lookup[f"{c['model']}/{c['comparator']}/baseline",r['sample_id']]
            hc=r['outcome'] in ('tp','tn');bc=a['outcome'] in ('tp','tn')
            kind=('both_correct' if hc else 'breaks') if bc else ('fixes' if hc else 'both_wrong')
            if kind==c['kind']:selected.append(r)
        assert c['n']==len(selected) and c['benign']==sum(r['label']==0 for r in selected) and c['phishing']==sum(r['label']==1 for r in selected)
    repeats=list(map(json.loads,(public/'permutation_repeats.jsonl').read_text().splitlines()))
    assert len(repeats)==960
    ps=json.loads((public/'permutation_summary.json').read_text())
    for s in ps:
        rr=[r for r in repeats if all(r[k]==s[k] for k in ('condition','mode','block'))]
        assert sorted(r['repeat'] for r in rr)==list(range(30))
        for metric in ('f1_drop','auc_drop','brier_increase'):
            a=np.array([r[metric] for r in rr]);t=s[metric]
            for actual,key in [(a.mean(),'mean'),(a.std(ddof=1),'std_sample'),(np.quantile(a,.025),'shuffle_p025'),(np.quantile(a,.975),'shuffle_p975')]:assert abs(actual-t[key])<1e-12
    adjusted=json.loads((public/'password_complexity_standardization.json').read_text())
    for condition, rr in by.items():
        for label,name in ((0,'fpr'),(1,'fnr')):
            common=[]
            for bin_id in sorted({r['complexity_bin'] for r in rr}):
                cells=[[r for r in rr if r['label']==label and r['complexity_bin']==bin_id and r['password_present']==p] for p in (False,True)]
                if min(map(len,cells))>=cfg['standardization_min_class_support_per_cell']:common.append(cells)
            saved_adjustment=adjusted[condition][name]
            if not common:assert not saved_adjustment['available'];continue
            total=sum(len(c[0])+len(c[1]) for c in common)
            rates=[sum((len(c[0])+len(c[1]))/total*sum(r['outcome'] in ('fp','fn') for r in c[p])/len(c[p]) for c in common) for p in (0,1)]
            assert saved_adjustment['supported_class_rows']==total
            assert abs(saved_adjustment['absent']-rates[0])<1e-12 and abs(saved_adjustment['present']-rates[1])<1e-12
    # Independently re-evaluate primary password gap intervals by resampling row indexes.
    rr=sorted(by['random_forest/url_dom/baseline'],key=lambda r:r['sample_id'])
    members=[[i for i,r in enumerate(rr) if r['final_group']==g] for g in sorted({r['final_group'] for r in rr})]
    y=np.array([r['label'] for r in rr]);pred=np.array([r['score']>=.5 for r in rr]);pw=np.array([r['password_present'] for r in rr])
    rng=np.random.default_rng(cfg['diagnostic_bootstrap_seed']);values=defaultdict(list)
    for _ in range(cfg['diagnostic_bootstrap_repeats']):
        ix=np.concatenate([members[g] for g in rng.choice(len(members),size=len(members),replace=True)])
        sets=[]
        for p in (False,True):
            idx=ix[pw[ix]==p];tn,fp,fn,tp=confusion_matrix(y[idx],pred[idx],labels=[0,1]).ravel()
            sets.append(dict(f1=f1_score(y[idx],pred[idx],zero_division=0),recall=tp/(tp+fn) if tp+fn else None,fpr=fp/(fp+tn) if fp+tn else None))
        for k in sets[0]:
            if sets[0][k] is not None and sets[1][k] is not None:values[k].append(sets[1][k]-sets[0][k])
    saved=json.loads((public/'password_gap_intervals.json').read_text())['random_forest/url_dom/baseline']
    for k,v in values.items():
        assert abs(np.quantile(v,.025)-saved[k]['low'])<1e-12 and abs(np.quantile(v,.975)-saved[k]['high'])<1e-12
    statuses=list(map(json.loads,(public/'features/extraction_status.jsonl').read_text().splitlines()))
    assert len(statuses)==4203 and {r['sample_id'] for r in statuses}==dev and all(r['extraction_status']=='ok' for r in statuses)
    assert not list(public.rglob('*.joblib'))
    return dict(verification_passed=True,reference_probabilities_checked=4452,independent_slice_checks=checked,prior_language_month_password_counts_equal=True,paired_change_rows_verified=len(changes),permutation_repeats_aggregated=960,primary_password_gap_intervals_independently_verified=True,complexity_standardized_rates_independently_verified=True,development_statuses=4203,test_feature_rows=0,limitations=['Permutation predictions require private model/features; verified via runner tests and aggregates, not recomputed from public evidence.','Detailed feature profiles and bin assignments depend on the hash-matched extraction; source labels were not manually adjudicated.'])

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--public',type=Path,required=True);p.add_argument('--root',type=Path,default=Path('.'));p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=verify(a.public,a.root);a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
