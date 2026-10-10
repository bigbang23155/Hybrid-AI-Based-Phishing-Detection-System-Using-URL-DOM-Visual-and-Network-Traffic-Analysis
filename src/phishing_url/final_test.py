"""One authorized six-cell test evaluation; immutable v1 definitions are reused.

prepare reconstructs development only. evaluate requires a persistent GitHub
claim, verified model bytes and an exclusive local access marker. No refit,
threshold search, permutations or model selection is performed on test.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import json
import os
from pathlib import Path
import platform
import time
import joblib
import numpy as np
import sklearn
from .final_evaluation_contract import verify, verify_file_hashes
from .formal_candidates import file_sha, sha
from .formal_html import frozen_candidates, selected_html
from .dom_features import DOMFeatureExtractor, extract_dom_features
from .feature_registry import FeatureExtractor, REGISTERED_FEATURE_NAMES, FEATURE_SETS
from .modality_contract import (read_protocol, read_locked_manifest, assemble_development,
                                feature_names, make_unfitted_model)
from .paired_development import extract_development, jsonl, write_json, weighted_metrics, bootstrap_intervals
from .development_review import metrics, password_uncertainty, standardize_password

FREEZE = 'be19ad2c728704d75afd2eb605e023b9edfb8544d7700735e6fe071e906763e0'
AUTH_PATH = 'config/assignment03_final_test_execution_v1.json'


def utc():
    return datetime.now(timezone.utc).isoformat()


def exclusive_json(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True, allow_nan=False)
        f.write('\n'); f.flush(); os.fsync(f.fileno())


def validate_execution(root):
    original = verify(root)
    cfg = read_protocol(root / AUTH_PATH)
    if original['freeze_sha256'] != FREEZE or cfg['freeze_sha256'] != FREEZE:
        raise ValueError('wrong frozen version')
    if cfg['test_evaluation_authorized'] is not True or cfg['evaluation_count'] != 1:
        raise ValueError('one complete evaluation must be authorized')
    if cfg['fit_partitions'] != ['train'] or cfg['threshold_tuning'] or cfg['test_driven_selection']:
        raise ValueError('unauthorized tuning or refit')
    verify_file_hashes(root, cfg['executor_file_sha256'])
    return read_protocol(root/'config/assignment03_final_evaluation_v1.json'), cfg


def runtime_check(lock):
    versions = dict(python=platform.python_version(), numpy=np.__version__, sklearn=sklearn.__version__)
    if versions != lock['runtime']['versions']:
        raise ValueError('frozen runtime version mismatch: '+str(versions))
    if platform.machine() != 'x86_64' or platform.system() != 'Linux':
        raise ValueError('Linux amd64 runtime required')
    return versions


def inputs(root, source_root, lock):
    manifest = read_locked_manifest(root/'results/assignment03/holdout_v1/partition_manifest.jsonl.gz',lock)
    chosen, frame, _, inventory, _ = frozen_candidates(source_root,
        root/'config/assignment03_paired_source_frame_v1.json',
        root/'config/assignment03_paired_release_policy_v1.json',
        root/'config/assignment03_formal_candidate_freeze_v1.json')
    return manifest, chosen, frame, inventory


def model_path(output, cell):
    return output/'private_models'/('-'.join(cell['condition'].split('/'))+'.joblib')


def prepare(root, source_root, output):
    lock, cfg = validate_execution(root)
    versions = runtime_check(lock)
    output.mkdir(parents=True, exist_ok=False)
    public = output/'public'; public.mkdir()
    private = output/'private'; private.mkdir()
    (output/'private_models').mkdir()
    manifest, chosen, frame, inventory = inputs(root, source_root, lock)
    allowed = {r['sample_id'] for r in manifest if r['partition'] in ('train','validation')}
    selected = [r for r in chosen if r['sample_id'] in allowed]
    u,d,_,integrity = extract_development(manifest,selected,selected_html(source_root,frame,selected),public/'development_features')
    review = read_protocol(root/'config/assignment03_development_review_v1.json')
    for name, rows in [('url_rows.jsonl',u),('dom_rows.jsonl',d)]:
        p=private/name;jsonl(p,sorted(rows,key=lambda r:r['sample_id']))
        if file_sha(p)!=review['reference_feature_hashes'][name]:
            raise ValueError('development feature hash changed')
    refs=defaultdict(dict)
    for line in gzip.decompress((root/review['reference_predictions_path']).read_bytes()).splitlines():
        r=json.loads(line);refs[r['condition']][r['sample_id']]=r
    protocol=read_protocol(root/'config/assignment03_modeling_protocol_v1.json')
    index={r['sample_id']:r for r in manifest};evidence=[]
    for cell in lock['evaluation_cells']:
        model,mode,_=cell['condition'].split('/')
        mat={};ids={}
        for part in ('train','validation'):
            ids[part],values=assemble_development(manifest,[r for r in u if r['partition']==part],
                [r for r in d if r['partition']==part],partition=part,modality=mode)
            mat[part]=np.asarray(values,dtype=np.float64)
        est=make_unfitted_model(protocol,model,lock['seed'])
        est.fit(mat['train'],np.asarray([index[s]['label'] for s in ids['train']],dtype=int))
        path=model_path(output,cell);joblib.dump(est,path)
        if file_sha(path)!=cell['fitted_model_sha256'] or est.get_params()!=cell['parameters']:
            raise ValueError('model replay identity mismatch: '+cell['condition'])
        if set(refs[cell['condition']])!=set(ids['validation']):raise ValueError('validation reference membership mismatch')
        expected=np.asarray([refs[cell['condition']][s]['score'] for s in ids['validation']])
        difference=float(np.max(np.abs(est.predict_proba(mat['validation'])[:,1]-expected)))
        if difference>1e-12:raise ValueError('validation replay mismatch')
        evidence.append(dict(condition=cell['condition'],model_sha256=file_sha(path),
            train_n=len(ids['train']),validation_n=len(ids['validation']),maximum_score_difference=difference))
        print(json.dumps(dict(reproduced=cell['condition'],test_access=False)),flush=True)
    cuts=np.unique(np.quantile([r['features']['tag_count'] for r in d if r['partition']=='train'],review['complexity_train_quantiles'])).tolist()
    ready=dict(status='six_models_verified_before_test',created_at=utc(),freeze_sha256=FREEZE,
        authorization_sha256=file_sha(root/AUTH_PATH),execution_commit=os.environ['EXECUTION_COMMIT'],
        run_id=os.environ['EVALUATION_RUN_ID'],runtime=versions,models=evidence,source_inventory=inventory,
        development_integrity=integrity,complexity_cuts=cuts,test_features_read=0,test_predictions=0)
    exclusive_json(public/'ready.json',ready)
    return ready


def assemble_test(manifest,urows,drows,mode):
    """Strict test-only join. Never changes the frozen development assembler."""
    expected={r['sample_id']:r for r in manifest if r['partition']=='test'}
    def index(rows):
        result={r['sample_id']:r for r in rows}
        if len(result)!=len(rows) or set(result)!=set(expected):raise ValueError('test paired cohort mismatch')
        return result
    u,d=index(urows),index(drows)
    ue,de=FeatureExtractor(FEATURE_SETS['baseline']),DOMFeatureExtractor()
    names=feature_names(mode); ids=sorted(expected); vectors=[]
    if not ids:raise ValueError('empty test')
    for sid in ids:
        ref=expected[sid]
        if not ref['eligible']:raise ValueError('ineligible test row')
        for row in (u[sid],d[sid]):
            if row['extraction_status']!='ok':raise ValueError('failed test extraction')
            for key in ('partition','label','final_group','html_sha256'):
                if row[key]!=ref[key]:raise ValueError('test pairing metadata mismatch: '+key)
        uv,dv=ue.transform_mapping(u[sid]['features']),de.transform_mapping(d[sid]['features'])
        if not np.isfinite(uv+dv).all():raise ValueError('nonfinite test feature')
        values=uv if mode=='url_only' else dv if mode=='dom_only' else uv+dv
        if len(values)!=len(names):raise ValueError('feature dimension mismatch')
        vectors.append(values)
    return ids,np.asarray(vectors,dtype=np.float64)


def extract_test(manifest, chosen, html_items, output):
    output.mkdir(parents=True,exist_ok=False)
    expected={r['sample_id']:r for r in manifest if r['partition']=='test'}
    sources={r['sample_id']:r for r in chosen}
    if len(sources)!=len(chosen) or set(sources)!=set(expected):raise ValueError('test source membership mismatch')
    ue,de=FeatureExtractor(REGISTERED_FEATURE_NAMES),DOMFeatureExtractor()
    u,d,context,statuses,seen=[],[],{},[],set()
    # Flush every status so failures retain how far test access progressed.
    with (output/'extraction_status.jsonl').open('x') as status_file:
        def record(row):
            statuses.append(row);status_file.write(json.dumps(row,sort_keys=True)+'\n');status_file.flush()
        for sid,html in html_items:
            if sid not in expected or sid in seen:
                record(dict(sample_id=sid,partition='test',extraction_status='unexpected_or_duplicate'))
                raise ValueError('unexpected/duplicate test payload')
            seen.add(sid);ref,source=expected[sid],sources[sid]
            row=dict(sample_id=sid,partition='test',extraction_status='ok')
            try:
                if not ref['eligible'] or source['label']!=ref['label']:raise ValueError('eligibility/label mismatch')
                if source['source_file']!=ref['source_file'] or source['source_row']!=ref['source_row'] or sha(source['registered_domain'].encode())!=ref['registered_domain_sha256']:
                    raise ValueError('test source identity mismatch')
                if not isinstance(html,str) or sha(html.encode())!=ref['html_sha256']:raise ValueError('HTML hash mismatch')
                start=time.perf_counter();uv=dict(zip(REGISTERED_FEATURE_NAMES,ue.transform_one(source['url_clean']),strict=True));row['url_seconds']=time.perf_counter()-start
                start=time.perf_counter();dv=extract_dom_features(html,source['url_clean']);de.transform_mapping(dv);row['dom_seconds']=time.perf_counter()-start
                meta={k:ref[k] for k in ('sample_id','partition','label','final_group','html_sha256')}
                u.append(dict(**meta,extraction_status='ok',features=uv));d.append(dict(**meta,extraction_status='ok',features=dv))
                context[sid]=dict(month=(source.get('capture_date') or 'missing')[:7],
                    language_group='en' if source.get('lang')=='en' else 'other_or_missing',source_shard=source['source_file'])
            except (ValueError,TypeError,KeyError,UnicodeError) as exc:
                row.update(extraction_status='failed',reason=type(exc).__name__+':'+str(exc))
            record(row)
        for sid in sorted(set(expected)-seen):record(dict(sample_id=sid,partition='test',extraction_status='missing_payload'))
        os.fsync(status_file.fileno())
    summary=dict(expected_rows=len(expected),successes=len(u),failures=sum(r['extraction_status']!='ok' for r in statuses),
        no_backfill=True,feature_dimensions={m:len(feature_names(m)) for m in ('url_only','dom_only','url_dom')})
    write_json(output/'feature_integrity.json',summary)
    if summary['failures']:raise ValueError('test extraction failed; no dropping or replacement')
    for mode in ('url_only','dom_only','url_dom'):assemble_test(manifest,u,d,mode)
    return u,d,context,summary


def verify_claim(claim, ready, cfg, commit, run_id):
    if claim.get('ref')!=cfg['persistent_claim_ref'] or claim.get('object',{}).get('sha')!=commit:
        raise ValueError('persistent one-time claim mismatch')
    if ready['execution_commit']!=commit or str(ready['run_id'])!=str(run_id):raise ValueError('preparation belongs to another execution')
    if str(claim.get('run_id'))!=str(run_id) or str(claim.get('run_attempt'))!='1':raise ValueError('claim run identity mismatch')
    if claim.get('ready_sha256')!=sha(json_bytes_for_ready(ready)):raise ValueError('claim preparation hash mismatch')


def json_bytes_for_ready(ready):
    # exclusive_json uses this exact serialization.
    return (json.dumps(ready,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()


def summarize_test(manifest, ids, scores, drows, context, cuts, lock, review_cfg, public):
    index={r['sample_id']:r for r in manifest};dom={r['sample_id']:r['features'] for r in drows}
    y=np.asarray([index[s]['label'] for s in ids]);groups=np.asarray([index[s]['final_group'] for s in ids])
    password=np.asarray([dom[s]['password_input_count']>0 for s in ids]);bins=np.searchsorted(cuts,[dom[s]['tag_count'] for s in ids],side='right')
    facets=dict(password_present=np.asarray([str(v) for v in password]),complexity_bin=np.asarray([str(b) for b in bins]),
        password_x_complexity=np.asarray([f'{p}:{b}' for p,b in zip(password,bins)]),
        language_group=np.asarray([context[s]['language_group'] for s in ids]),
        month=np.asarray([context[s]['month'] for s in ids]),source_shard=np.asarray([context[s]['source_shard'] for s in ids]))
    rows=[];slices=[];ledger=[];paired=[];changes=[];gap={};standard={};group_errors=[]
    for condition,score in scores.items():
        rows.append(dict(condition=condition,partition='test',n=len(ids),**weighted_metrics(y,score,threshold=lock['threshold'])))
        pred=score>=lock['threshold'];outcome=np.where(y==1,np.where(pred,'tp','fn'),np.where(pred,'fp','tn'))
        for i,s in enumerate(ids):ledger.append(dict(condition=condition,sample_id=s,partition='test',final_group=str(groups[i]),
            label=int(y[i]),score=float(score[i]),predicted=int(pred[i]),outcome=str(outcome[i]),password_present=bool(password[i]),
            complexity_bin=int(bins[i]),**context[s]))
        for facet,values in facets.items():
            for value in sorted(set(values)):
                mask=values==value;slices.append(dict(condition=condition,facet=facet,value=str(value),n=int(mask.sum()),
                    groups=len(set(groups[mask])),**metrics(y[mask],score[mask])))
        for group in sorted(set(groups)):
            mask=groups==group
            group_errors.append(dict(condition=condition,final_group=str(group),n=int(mask.sum()),
                fp=int(np.sum(mask&(outcome=='fp'))),fn=int(np.sum(mask&(outcome=='fn')))))
        gap[condition]=password_uncertainty(y,score,password,groups,review_cfg)
        standard[condition]=standardize_password(y,score,password,bins,review_cfg['standardization_min_class_support_per_cell'])
    for model in ('random_forest','gradient_boosting'):
        hybrid=scores[f'{model}/url_dom/baseline'];hc=(hybrid>=.5)==y
        for other in ('url_only','dom_only'):
            base=scores[f'{model}/{other}/baseline'];bc=(base>=.5)==y
            for kind,mask in [('fixes',hc&~bc),('breaks',~hc&bc),('both_wrong',~hc&~bc),('both_correct',hc&bc)]:
                paired.append(dict(model=model,comparator=other,kind=kind,n=int(mask.sum()),
                    benign=int(np.sum(mask&(y==0))),phishing=int(np.sum(mask&(y==1))),password_present=int(np.sum(mask&password))))
                if kind in ('fixes','breaks'):
                    for i in np.flatnonzero(mask):changes.append(dict(model=model,comparator=other,kind=kind,sample_id=ids[i],
                        label=int(y[i]),base_score=float(base[i]),hybrid_score=float(hybrid[i]),complexity_bin=int(bins[i]),password_present=bool(password[i])))
    outputs={'metrics.json':rows,'slices.json':slices,'paired_error_cohorts.json':paired,
        'password_gap_intervals.json':gap,'password_complexity_standardization.json':standard,
        'group_errors.json':group_errors,'bootstrap_intervals.json':bootstrap_intervals(y,scores,groups,lock['uncertainty'])}
    for name,value in outputs.items():write_json(public/name,value)
    jsonl(public/'error_ledger.jsonl',ledger);jsonl(public/'paired_changes.jsonl',changes)
    return rows


def evaluate(root,source_root,output,claim_path):
    lock,cfg=validate_execution(root);runtime_check(lock)
    public=output/'public';ready=read_protocol(public/'ready.json');claim=read_protocol(claim_path)
    commit=os.environ['EXECUTION_COMMIT'];run_id=os.environ['EVALUATION_RUN_ID']
    verify_claim(claim,ready,cfg,commit,run_id)
    if ready['authorization_sha256']!=file_sha(root/AUTH_PATH) or ready['freeze_sha256']!=FREEZE:raise ValueError('preparation contract changed')
    estimators={}
    for cell in lock['evaluation_cells']:
        path=model_path(output,cell)
        if file_sha(path)!=cell['fitted_model_sha256']:raise ValueError('prepared model changed')
        estimators[cell['condition']]=joblib.load(path)
    manifest,chosen,frame,_=inputs(root,source_root,lock)
    allowed={r['sample_id'] for r in manifest if r['partition']=='test'}
    selected=[r for r in chosen if r['sample_id'] in allowed]
    # All checks precede this exclusive durable marker and all test HTML access.
    exclusive_json(public/'test_access_started.json',dict(created_at=utc(),execution_commit=commit,run_id=run_id,
        freeze_sha256=FREEZE,claim_ref=claim['ref'],test_rows=len(allowed),no_automatic_retry=True))
    completed=[];predictions=0
    try:
        u,d,context,integrity=extract_test(manifest,selected,selected_html(source_root,frame,selected),public/'test_features')
        hashes={}
        for name,rows in [('test_url_rows.jsonl',u),('test_dom_rows.jsonl',d)]:
            path=output/'private'/name;jsonl(path,sorted(rows,key=lambda r:r['sample_id']));hashes[name]=file_sha(path)
        write_json(public/'test_feature_hashes.json',hashes)
        index={r['sample_id']:r for r in manifest};scores={};timings=[]
        with (public/'test_predictions.jsonl').open('x') as stream:
            common_ids=None
            for cell in lock['evaluation_cells']:
                condition=cell['condition'];_,mode,_=condition.split('/')
                ids,x=assemble_test(manifest,u,d,mode)
                if common_ids is not None and ids!=common_ids:raise ValueError('test modality alignment changed')
                common_ids=ids
                est=estimators[condition]
                if est.get_params()!=cell['parameters'] or list(est.classes_)!=[0,1]:raise ValueError('estimator contract mismatch')
                start=time.perf_counter();score=est.predict_proba(x)[:,1];elapsed=time.perf_counter()-start
                if len(score)!=len(ids) or not np.isfinite(score).all() or (score<0).any() or (score>1).any():raise ValueError('invalid prediction')
                scores[condition]=score
                for sid,value in zip(ids,score,strict=True):
                    r=dict(condition=condition,seed=lock['seed'],sample_id=sid,label=index[sid]['label'],partition='test',
                        final_group=index[sid]['final_group'],score=float(value),predicted=int(value>=lock['threshold']))
                    stream.write(json.dumps(r,sort_keys=True)+'\n');predictions+=1
                stream.flush();os.fsync(stream.fileno());completed.append(condition)
                timings.append(dict(condition=condition,batch_size=len(ids),single_prediction_call_seconds=elapsed))
                write_json(public/'progress.json',dict(status='predictions_in_progress',completed_cells=completed,test_predictions=predictions))
        write_json(public/'prediction_timing.json',timings)
        review=read_protocol(root/'config/assignment03_development_review_v1.json')
        metrics_rows=summarize_test(manifest,common_ids,scores,d,context,ready['complexity_cuts'],lock,review,public)
        summary=dict(status='complete_six_cell_test_evaluation',finished_at=utc(),execution_commit=commit,run_id=run_id,
            freeze_sha256=FREEZE,authorization_sha256=file_sha(root/AUTH_PATH),test_evaluated=True,
            test_rows=len(common_ids),test_groups=len({index[s]['final_group'] for s in common_ids}),
            labels=dict(Counter(str(index[s]['label']) for s in common_ids)),test_predictions=predictions,
            completed_cells=completed,training_rows=lock['counts']['train'],feature_integrity=integrity,
            complexity_cuts_from_training=ready['complexity_cuts'],metrics=metrics_rows,
            threshold=lock['threshold'],seed=lock['seed'],test_fits=0,test_driven_tuning=False,
            diagnostics='descriptive fixed development facets; not external, temporal, adversarial or zero-day validation',
            partial_prior_outcome_exposure=False)
        write_json(public/'test_summary.json',summary)
        return summary
    except Exception as exc:
        write_json(public/'failure.json',dict(status='failed_after_test_access_started',time=utc(),error_type=type(exc).__name__,
            reason=str(exc),completed_cells=completed,test_predictions=predictions,test_holdout_consumed=True,no_automatic_retry=True))
        raise


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=['prepare','evaluate'])
    p.add_argument('--root',type=Path,default=Path('.'));p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--claim',type=Path)
    a=p.parse_args()
    if a.phase=='evaluate' and a.claim is None:p.error('evaluate requires --claim')
    result=prepare(a.root,a.source_root,a.output) if a.phase=='prepare' else evaluate(a.root,a.source_root,a.output,a.claim)
    print(json.dumps(result,indent=2))
