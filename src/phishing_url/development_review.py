"""Reproduce frozen development models and diagnose errors; no test feature path."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import platform
import joblib
import numpy as np
import sklearn
from .formal_candidates import file_sha, sha
from .formal_html import frozen_candidates, selected_html, numeric
from .modality_contract import verify_contract, read_protocol, read_locked_manifest, assemble_development, feature_names, make_unfitted_model
from .paired_development import extract_development, jsonl, write_json, weighted_metrics


def metrics(y, scores, weights=None):
    r = weighted_metrics(y, scores, weights)
    r.update(positive_n=r['tp']+r['fn'], negative_n=r['tn']+r['fp'])
    if not r['negative_n']: r['fpr'] = None
    if not r['positive_n']: r['recall'] = None
    return r


def bin_values(train, validation, quantiles):
    cuts = np.unique(np.quantile(train, quantiles))
    return cuts, np.searchsorted(cuts, train, side='right'), np.searchsorted(cuts, validation, side='right')


def permutation_indices(strata, rng):
    strata = np.asarray(strata)
    ix = np.arange(len(strata))
    for name in np.unique(strata):
        rows = np.flatnonzero(strata == name)
        ix[rows] = rng.permutation(rows)
    return ix


def permutation_review(estimator, x, y, names, blocks, strata, config):
    baseline = weighted_metrics(y, estimator.predict_proba(x)[:,1])
    rows = []
    for mode in config['permutation_modes']:
        grouping = ['all']*len(y) if mode == 'unconditional' else strata
        eligible = sum(n for n in Counter(grouping).values() if n > 1)
        # Same draws for each model/block, making comparison less noisy.
        for block, columns in blocks.items():
            indexes = [names.index(c) for c in columns]
            rng = np.random.default_rng(config['permutation_seed'])
            for repeat in range(config['permutation_repeats']):
                order = permutation_indices(grouping, rng)
                perturbed = x.copy()
                perturbed[:, indexes] = x[order][:, indexes]
                m = weighted_metrics(y, estimator.predict_proba(perturbed)[:,1])
                rows.append(dict(mode=mode, block=block, repeat=repeat,
                    eligible_rows=eligible, index_changed_rows=int(np.sum(order != np.arange(len(y)))),
                    f1_drop=baseline['f1']-m['f1'], auc_drop=baseline['roc_auc']-m['roc_auc'],
                    brier_increase=m['brier_score']-baseline['brier_score']))
    return rows


def password_uncertainty(y, score, password, groups, cfg):
    unique, gi = np.unique(groups, return_inverse=True)
    rng = np.random.default_rng(cfg['diagnostic_bootstrap_seed'])
    values = defaultdict(list)
    for _ in range(cfg['diagnostic_bootstrap_repeats']):
        w = np.bincount(rng.integers(len(unique),size=len(unique)),minlength=len(unique))[gi]
        results=[]
        for value in (False,True):
            mask=password==value
            if not w[mask].sum(): results.append(None)
            else: results.append(metrics(y[mask],score[mask],w[mask]))
        if any(r is None for r in results): continue
        for name in ('f1','recall','fpr'):
            a,b=results[0][name],results[1][name]
            if a is not None and b is not None:values[name].append(b-a)
    return {k:dict(low=float(np.quantile(v,.025)),high=float(np.quantile(v,.975)),valid_replicates=len(v)) for k,v in values.items()}


def standardize_password(y, score, password, bins, minimum):
    """Descriptive common-bin standardization; class-specific denominators."""
    pred=score>=.5
    output={}
    for label, name in ((0,'fpr'),(1,'fnr')):
        eligible=[]
        for b in sorted(set(bins)):
            counts=[int(np.sum((bins==b)&(password==p)&(y==label))) for p in (False,True)]
            if min(counts)>=minimum:eligible.append((b,counts))
        total=sum(sum(c) for b,c in eligible)
        if not total:
            output[name]=dict(available=False,reason='no common bins with sufficient class support');continue
        rates=[]
        for p in (False,True):
            value=0
            for b,c in eligible:
                mask=(bins==b)&(password==p)&(y==label)
                value+=sum(c)/total*float(np.mean(pred[mask]!=y[mask]))
            rates.append(value)
        output[name]=dict(available=True,absent=rates[0],present=rates[1],present_minus_absent=rates[1]-rates[0],
                         supported_class_rows=total,total_class_rows=int(np.sum(y==label)),
                         bins=[dict(bin=int(b),absent=c[0],present=c[1],weight=sum(c)/total) for b,c in eligible])
    return output


def analyze(manifest, urows, drows, context, candidates, protocol, cfg, references, public):
    index={r['sample_id']:r for r in manifest}; source={r['sample_id']:r for r in candidates}
    ud={r['sample_id']:r['features'] for r in urows}; dd={r['sample_id']:r['features'] for r in drows}
    matrices={}; ids={}; labels={}
    for part in ('train','validation'):
        for modality in ('url_only','dom_only','url_dom'):
            sid,x=assemble_development(manifest,[r for r in urows if r['partition']==part],
                                      [r for r in drows if r['partition']==part],partition=part,modality=modality)
            ids[part]=sid;labels[part]=np.array([index[s]['label'] for s in sid]);matrices[part,modality]=np.asarray(x)
    val=ids['validation']; y=labels['validation']; groups=np.array([index[s]['final_group'] for s in val])
    password=np.array([dd[s]['password_input_count']>0 for s in val])
    proxy=cfg['complexity_bin_feature']
    cuts,train_bins,bins=bin_values([dd[s][proxy] for s in ids['train']],[dd[s][proxy] for s in val],cfg['complexity_train_quantiles'])
    facets={
        'password_present':np.array([str(v) for v in password]),
        'complexity_bin':np.array([str(int(b)) for b in bins]),
        'password_x_complexity':np.array([f'{p}:{b}' for p,b in zip(password,bins)]),
        'language':np.array([context[s]['language'] for s in val]),
        'language_group':np.array(['en' if context[s]['language']=='en' else 'other_or_missing' for s in val]),
        'month':np.array([context[s]['month'] for s in val]),
        'source_shard':np.array([source[s]['source_file'] for s in val]),
    }
    strata=[f'{p}|{l}|{s}' for p,l,s in zip(facets['password_present'],facets['language_group'],facets['source_shard'])]
    ref=defaultdict(dict)
    for r in references: ref[r['condition']][r['sample_id']]=r
    scores={}; profiles=[]; slice_rows=[]; uncertainty={}; standardization={}; replay=[]; permutations=[]; ledger=[]
    for model in protocol['models']:
        for modality in ('url_only','dom_only','url_dom'):
            condition=f'{model}/{modality}/baseline';names=list(feature_names(modality))
            if set(ref[condition])!=set(val):raise ValueError('reference cohort mismatch')
            estimator=make_unfitted_model(protocol,model,cfg['primary_seed'])
            estimator.fit(matrices['train',modality],labels['train'])
            score=estimator.predict_proba(matrices['validation',modality])[:,1]
            expected=np.array([ref[condition][s]['score'] for s in val])
            for s in val:
                if ref[condition][s]['label']!=index[s]['label'] or ref[condition][s]['partition']!='validation':raise ValueError('reference label/partition mismatch')
            difference=float(np.max(np.abs(score-expected)))
            if difference>cfg['model_replay_max_absolute_score_error']:raise ValueError('original score replay failed')
            scores[condition]=score
            model_dir=public.parent/'private_models';model_dir.mkdir(exist_ok=True)
            model_path=model_dir/(model+'-'+modality+'.joblib');joblib.dump(estimator,model_path)
            model_digest=file_sha(model_path)
            replay.append(dict(condition=condition,maximum_score_difference=difference,train_n=len(ids['train']),validation_n=len(val),parameters=estimator.get_params(),feature_names=names,model_sha256=model_digest,original_model_bytes_equal=model_digest==cfg.get('reference_model_sha256',{}).get(condition)))
            pred=score>=.5
            error_type=np.where(y==1,np.where(pred,'tp','fn'),np.where(pred,'fp','tn'))
            for i,s in enumerate(val):
                ledger.append(dict(condition=condition,sample_id=s,final_group=index[s]['final_group'],label=int(y[i]),
                    score=float(score[i]),outcome=str(error_type[i]),password_present=bool(password[i]),complexity_bin=int(bins[i]),
                    language_group=str(facets['language_group'][i]),month=str(facets['month'][i]),source_shard=str(facets['source_shard'][i])))
            for facet,values in {**facets,'outcome':error_type}.items():
                for value in sorted(set(values)):
                    mask=values==value
                    slice_rows.append(dict(condition=condition,facet=facet,value=str(value),n=int(mask.sum()),groups=len(set(groups[mask])),**metrics(y[mask],score[mask])))
            for outcome in ('fp','fn','tp','tn'):
                members=[s for s,o in zip(val,error_type) if o==outcome]
                profiles.append(dict(condition=condition,outcome=outcome,n=len(members),features={name:numeric([dd[s][name] for s in members]) for name in dd[val[0]]}))
            uncertainty[condition]=password_uncertainty(y,score,password,groups,cfg)
            standardization[condition]=standardize_password(y,score,password,bins,cfg['standardization_min_class_support_per_cell'])
            blocks={}
            if modality!='dom_only':blocks['all_url']=[n for n in names if n.startswith('url__')]
            if modality!='url_only':
                blocks['all_dom']=[n for n in names if n.startswith('dom__')]
                for block,key in (('complexity','complexity_features'),('credential','credential_features')):
                    blocks[block]=['dom__'+n for n in cfg[key]]
            for row in permutation_review(estimator,matrices['validation',modality],y,names,blocks,strata,cfg):
                permutations.append(dict(condition=condition,**row))
            print(json.dumps(dict(replayed=condition,score_difference=difference)),flush=True)
    paired=[];changed=[];cases=[]
    for model in protocol['models']:
        hybrid=scores[f'{model}/url_dom/baseline']
        for other in ('url_only','dom_only'):
            base=scores[f'{model}/{other}/baseline']
            hc=(hybrid>=.5)==y;bc=(base>=.5)==y
            for kind,mask in [('fixes',hc&~bc),('breaks',~hc&bc),('both_wrong',~hc&~bc),('both_correct',hc&bc)]:
                paired.append(dict(model=model,comparator=other,kind=kind,n=int(mask.sum()),benign=int(np.sum(mask&(y==0))),phishing=int(np.sum(mask&(y==1))),password_present=int(np.sum(mask&password)),median_tag_count=float(np.median([dd[s]['tag_count'] for s,m in zip(val,mask) if m])) if mask.any() else None))
                if kind in ('fixes','breaks'):
                    for i in np.flatnonzero(mask):changed.append(dict(model=model,comparator=other,kind=kind,sample_id=val[i],label=int(y[i]),base_score=float(base[i]),hybrid_score=float(hybrid[i]),complexity_bin=int(bins[i]),password_present=bool(password[i])))
        for outcome in ('fp','fn'):
            selected=[(s,float(sc)) for s,yy,sc in zip(val,y,hybrid) if (yy==0 and sc>=.5 if outcome=='fp' else yy==1 and sc<.5)]
            selected.sort(key=lambda t:((-t[1] if outcome=='fp' else t[1]),t[0]))
            cases.extend(dict(model=model,outcome=outcome,sample_id=s,score=sc,features=dd[s],note='feature evidence only; not label adjudication') for s,sc in selected[:cfg['confidence_case_count_per_error']])
    # Public cases expose aggregates and IDs only; private exact feature case vectors are omitted.
    case_summary=[{k:v for k,v in r.items() if k!='features'} for r in cases]
    grouped=defaultdict(list)
    for r in permutations:grouped[r['condition'],r['mode'],r['block']].append(r)
    perm_summary=[dict(condition=c,mode=m,block=b,repeats=len(rr),eligible_rows=rr[0]['eligible_rows'],
        **{key:dict(mean=float(np.mean([r[key] for r in rr])),std_sample=float(np.std([r[key] for r in rr],ddof=1)),
                   shuffle_p025=float(np.quantile([r[key] for r in rr],.025)),shuffle_p975=float(np.quantile([r[key] for r in rr],.975))) for key in ('f1_drop','auc_drop','brier_increase')}) for (c,m,b),rr in sorted(grouped.items())]
    distributions=[]
    for part,these_ids,these_bins in [('train',ids['train'],train_bins),('validation',val,bins)]:
        for b in sorted(set(these_bins)):
            members=[s for s,bin_id in zip(these_ids,these_bins) if bin_id==b]
            distributions.append(dict(partition=part,bin=int(b),n=len(members),benign=sum(index[s]['label']==0 for s in members),phishing=sum(index[s]['label']==1 for s in members),password_present=sum(dd[s]['password_input_count']>0 for s in members)))
    outputs={'replay.json':replay,'slices.json':slice_rows,'error_feature_profiles.json':profiles,'password_gap_intervals.json':uncertainty,'password_complexity_standardization.json':standardization,'paired_error_cohorts.json':paired,'permutation_summary.json':perm_summary,'complexity_distributions.json':dict(cuts=cuts.tolist(),boundaries='searchsorted right: x < cut0, cut0 <= x < cut1, etc.; ties may make bins unequal',rows=distributions),'confidence_cases.json':case_summary}
    for name,data in outputs.items():write_json(public/name,data)
    jsonl(public/'error_ledger.jsonl',ledger);jsonl(public/'paired_changes.jsonl',changed);jsonl(public/'permutation_repeats.jsonl',permutations)
    return dict(replayed_fits=len(replay),maximum_score_difference=max(r['maximum_score_difference'] for r in replay),validation_rows=len(val),validation_groups=len(set(groups)),permutation_predictions=len(permutations),diagnostic_only=True,test_feature_rows=0,test_predictions=0,labels_adjudicated=False)


def run(root,source_root,output):
    if output.exists():raise FileExistsError('new review directory required')
    verify_contract(root)
    cfg=read_protocol(root/'config/assignment03_development_review_v1.json');protocol=read_protocol(root/'config/assignment03_modeling_protocol_v1.json')
    if cfg['test_evaluation_authorized'] or not cfg['development_only']:raise ValueError('development only')
    raw=gzip.decompress((root/cfg['reference_predictions_path']).read_bytes())
    if sha(raw)!=cfg['reference_predictions_raw_sha256']:raise ValueError('reference digest mismatch')
    references=[json.loads(s) for s in raw.splitlines()]
    if len(references)!=cfg['reference_predictions_rows']:raise ValueError('reference row count mismatch')
    manifest=read_locked_manifest(root/'results/assignment03/holdout_v1/partition_manifest.jsonl.gz',protocol)
    chosen,frame,_,inventory,_=frozen_candidates(source_root,root/'config/assignment03_paired_source_frame_v1.json',root/'config/assignment03_paired_release_policy_v1.json',root/'config/assignment03_formal_candidate_freeze_v1.json')
    allowed={r['sample_id'] for r in manifest if r['partition'] in ('train','validation')}
    selected=[r for r in chosen if r['sample_id'] in allowed]
    output.mkdir(parents=True);public=output/'public';public.mkdir()
    u,d,context,integrity=extract_development(manifest,selected,selected_html(source_root,frame,selected),public/'features')
    private=output/'private';private.mkdir()
    for name,rows in [('url_rows.jsonl',u),('dom_rows.jsonl',d)]:
        path=private/name;jsonl(path,sorted(rows,key=lambda r:r['sample_id']))
        if file_sha(path)!=cfg['reference_feature_hashes'][name]:raise ValueError('original feature matrix digest mismatch')
    summary=analyze(manifest,u,d,context,selected,protocol,cfg,references,public)
    summary.update(status='review_complete_test_sealed',feature_hashes_match_original=True,feature_integrity=integrity,
        review_config_sha256=file_sha(root/'config/assignment03_development_review_v1.json'),implementation_sha256=file_sha(Path(__file__)),
        environment=dict(python=platform.python_version(),sklearn=sklearn.__version__,numpy=np.__version__),source_inventory=inventory)
    write_json(public/'review_summary.json',summary)
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path('.'));p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(run(a.root,a.source_root,a.output),indent=2))
