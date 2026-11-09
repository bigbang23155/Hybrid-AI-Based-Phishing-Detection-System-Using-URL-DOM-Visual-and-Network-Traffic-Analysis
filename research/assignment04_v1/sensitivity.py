"""Development-only reconstruction and fixed, post-exposure sensitivity analysis."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import platform
import numpy as np
import sklearn
from phishing_url.formal_html import frozen_candidates, selected_html
from phishing_url.modality_contract import (verify_contract, read_locked_manifest,
    assemble_development, make_unfitted_model)
from phishing_url.paired_development import extract_development, weighted_metrics

PLAN = {'version':'a04-development-sensitivity-v1','partitions':['train','validation'],
 'primary_seed':4941401,'threshold':0.5,'fits':12,
 'conditions':['all_training','exclude_exposed_components'],
 'joint_bins':'training medians of HTML UTF-8 bytes and tag count; >= median is upper bin',
 'standardization':'equal mass for each class x supported joint bin; fixed common-support bins',
 'bootstrap':{'draws':2000,'seed':4940411,'unit':'whole validation group'},
 'claims':'post-exposure descriptive sensitivity; not independent confirmation',
 'new_test_evaluation':False,'hyperparameter_tuning':False}


def joint_bins(train_bytes, train_tags, val_bytes, val_tags):
    cuts=[float(np.median(train_bytes)),float(np.median(train_tags))]
    bins=(np.asarray(val_bytes)>=cuts[0]).astype(int)*2+(np.asarray(val_tags)>=cuts[1]).astype(int)
    return cuts,bins


def standardized_weights(y,bins,multiplicity=None,support=None):
    y=np.asarray(y);bins=np.asarray(bins)
    m=np.ones(len(y)) if multiplicity is None else np.asarray(multiplicity,dtype=float)
    if support is None: support=[b for b in range(4) if all(np.any((y==c)&(bins==b)) for c in (0,1))]
    if not support:return None
    w=np.zeros(len(y))
    for b in support:
        for c in (0,1):
            idx=(y==c)&(bins==b);total=m[idx].sum()
            if total==0:return None
            w[idx]=m[idx]/(2*len(support)*total)
    return w


def run(root,source_root,output):
    if output.exists():raise FileExistsError('fresh output directory required')
    verify_contract(root)
    lock=json.loads((root/'config/assignment03_final_evaluation_v1.json').read_text())
    for path,digest in lock['file_sha256'].items():
        if hashlib.sha256((root/path).read_bytes()).hexdigest()!=digest:raise ValueError('frozen file changed')
    protocol=json.loads((root/'config/assignment03_modeling_protocol_v1.json').read_text())
    manifest=read_locked_manifest(root/'results/assignment03/holdout_v1/partition_manifest.jsonl.gz',protocol)
    chosen,frame,_,inventory,_=frozen_candidates(source_root,root/'config/assignment03_paired_source_frame_v1.json',
        root/'config/assignment03_paired_release_policy_v1.json',root/'config/assignment03_formal_candidate_freeze_v1.json')
    allowed={r['sample_id'] for r in manifest if r['partition'] in PLAN['partitions']}
    selected=[r for r in chosen if r['sample_id'] in allowed]
    if len(selected)!=4203:raise ValueError('unexpected development count')
    output.mkdir(parents=True); public=output/'public';public.mkdir()
    (public/'plan.json').write_text(json.dumps(PLAN,indent=2)+'\n')
    u,d,context,integrity=extract_development(manifest,selected,selected_html(source_root,frame,selected),output/'private_features')
    index={r['sample_id']:r for r in manifest}
    matrices={};ids={};labels={}
    for p in PLAN['partitions']:
        for modality in ('url_only','dom_only','url_dom'):
            sid,x=assemble_development(manifest,[r for r in u if r['partition']==p],[r for r in d if r['partition']==p],partition=p,modality=modality)
            ids[p]=sid;matrices[p,modality]=np.asarray(x,dtype=float)
        labels[p]=np.array([index[s]['label'] for s in ids[p]])
    exposed_groups={r['final_group'] for r in manifest if r['component_pilot_exposed']}
    keep=np.array([index[s]['final_group'] not in exposed_groups for s in ids['train']])
    if len(exposed_groups)!=96 or int((~keep).sum())!=464 or any(index[s]['final_group'] in exposed_groups for s in ids['validation']):
        raise ValueError('exposure grouping mismatch')
    dom={r['sample_id']:r['features'] for r in d}
    cuts,bins=joint_bins([context[s]['html_bytes'] for s in ids['train']],[dom[s]['tag_count'] for s in ids['train']],
                        [context[s]['html_bytes'] for s in ids['validation']],[dom[s]['tag_count'] for s in ids['validation']])
    y=labels['validation'];support=[b for b in range(4) if all(np.any((bins==b)&(y==c)) for c in (0,1))]
    weights=standardized_weights(y,bins,support=support)
    if weights is None:raise ValueError('no common support')
    archived={}
    with gzip.open(root/'results/assignment03/development_v1/primary_validation_predictions.jsonl.gz','rt') as f:
        for line in f:
            r=json.loads(line)
            if r['partition']!='validation':raise ValueError('nonvalidation archive')
            archived[r['condition'],r['sample_id']]=r['score']
    scores={};metrics=[];replay={};fits=0
    for mode in PLAN['conditions']:
        mask=np.ones(len(keep),dtype=bool) if mode=='all_training' else keep
        for family in ('random_forest','gradient_boosting'):
            for modality in ('url_only','dom_only','url_dom'):
                key=f'{mode}/{family}/{modality}'
                model=make_unfitted_model(protocol,family,PLAN['primary_seed'])
                model.fit(matrices['train',modality][mask],labels['train'][mask]);fits+=1
                score=model.predict_proba(matrices['validation',modality])[:,1]
                if mode=='all_training':
                    ref=np.array([archived[f'{family}/{modality}/baseline',s] for s in ids['validation']])
                    delta=float(np.max(np.abs(ref-score)));replay[key]=delta
                    if delta>1e-12:raise ValueError('baseline replay mismatch: '+key)
                scores[key]=score
                metrics.append({'condition':key,'training_rows':int(mask.sum()),'validation_rows':len(y),
                    'train':weighted_metrics(labels['train'][mask],model.predict_proba(matrices['train',modality][mask])[:,1]),
                    'validation':weighted_metrics(y,score),'joint_standardized_validation':weighted_metrics(y,score,weights)})
                print(key+' completed',flush=True)
    groups=np.array([index[s]['final_group'] for s in ids['validation']]);unique,inv=np.unique(groups,return_inverse=True)
    contrasts=[]
    for mode in PLAN['conditions']:
        for family in ('random_forest','gradient_boosting'):
            contrasts.append((f'{mode}/{family}/url_dom',f'{mode}/{family}/url_only'))
    for family in ('random_forest','gradient_boosting'):
        for modality in ('url_only','dom_only','url_dom'):
            contrasts.append((f'exclude_exposed_components/{family}/{modality}',f'all_training/{family}/{modality}'))
    distributions={(a,b):[] for a,b in contrasts};rng=np.random.default_rng(PLAN['bootstrap']['seed']);skipped=0
    for _ in range(PLAN['bootstrap']['draws']):
        counts=np.bincount(rng.integers(0,len(unique),len(unique)),minlength=len(unique))[inv]
        w=standardized_weights(y,bins,counts,support)
        if w is None:skipped+=1;continue
        f1={k:weighted_metrics(y,v,w)['f1'] for k,v in scores.items()}
        for a,b in contrasts:distributions[a,b].append(f1[a]-f1[b])
    summary={'plan':PLAN,'finished_at':datetime.now(timezone.utc).isoformat(),'fits':fits,
        'integrity':integrity,'training_rows':len(keep),'retained_training_rows':int(keep.sum()),
        'removed_rows':int((~keep).sum()),'removed_groups':len(exposed_groups),
        'retained_training_labels':dict(Counter(str(x) for x in labels['train'][keep])),
        'validation_rows':len(y),'validation_groups':len(unique),'baseline_max_probability_difference':replay,
        'joint_control':{'cuts':dict(html_bytes=cuts[0],tag_count=cuts[1]),'supported_bins':support,
            'counts':[{'bin':b,'benign':int(((bins==b)&(y==0)).sum()),'phishing':int(((bins==b)&(y==1)).sum())} for b in range(4)],
            'excluded_validation_rows_from_standardization':int(sum(b not in support for b in bins)),
            'bootstrap_invalid_draws':skipped},'metrics':metrics,
        'paired_standardized_f1_contrasts':[{'a':a,'b':b,'delta':weighted_metrics(y,scores[a],weights)['f1']-weighted_metrics(y,scores[b],weights)['f1'],
            'percentile95':np.quantile(v,[.025,.975]).tolist() if v else None,'valid_draws':len(v)} for (a,b),v in distributions.items()],
        'environment':{'python':platform.python_version(),'numpy':np.__version__,'sklearn':sklearn.__version__},
        'sources':inventory,'implementation_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'input_sha256':{p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in ['config/assignment03_modeling_protocol_v1.json','results/assignment03/holdout_v1/partition_manifest.jsonl.gz','results/assignment03/development_v1/primary_validation_predictions.jsonl.gz']},'new_test_features':0,'new_test_predictions':0,'human_labels_adopted':0,
        'limitations':['Coarse joint bins do not remove within-bin/source/time confounding.',
            'Removing exposed components changes training size and composition; effect is not attributable to exposure alone.',
            'Single prespecified model seed; descriptive bootstrap without multiplicity correction.',
            'Original publisher labels retained; no new A04 labels or multimodal cohort certified.',
            'Parquet pages decode neighboring historical test rows; only development HTML scalars are selected, converted and featurized.']}
    (public/'summary.json').write_text(json.dumps(summary,indent=2,allow_nan=False)+'\n')
    # Only de-identified development predictions and covariates for independent verification.
    with gzip.open(public/'validation_predictions.jsonl.gz','wt') as f:
        for i,s in enumerate(ids['validation']):
            f.write(json.dumps({'sample_id':s,'final_group':index[s]['final_group'],'partition':'validation','label':int(y[i]),
                'html_bytes':context[s]['html_bytes'],'tag_count':dom[s]['tag_count'],'joint_bin':int(bins[i]),
                'scores':{k:float(v[i]) for k,v in scores.items()}},sort_keys=True)+'\n')
    return summary

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=Path('.'));p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run(a.root,a.source_root,a.output)
