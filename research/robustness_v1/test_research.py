import copy
import json
from pathlib import Path
import numpy as np
import pytest
from .intake import adjudicate, historical_audit, precision_plan, wilson, read_rows
from .compare import group_folds, choose_variant, validate_cohort, validate_overlap_receipt
from .models import MODELS, make_model
from phishing_url.modality_contract import feature_names

ROOT=Path(__file__).resolve().parents[2]


def packet(label=0):
    t='2026-10-10T00:00:00Z'
    evidence=[dict(id=str(i),origin_family='independent-'+str(i),reference='synthetic:test',rationale='synthetic unit test evidence',
                   verdict=label,html_sha256='a'*64,evidence_type='snapshot_content_review',observed_at=t,valid_from=t,valid_to=t) for i in range(2)]
    reviews=[dict(reviewer_id='synthetic-reviewer-'+str(i),reviewer_type='human',rationale='fixture only, not a real review',
                  label=label,html_sha256='a'*64,reviewed_at=t,evidence_ids=['0','1'],blind_to_model_and_other_review=True) for i in range(2)]
    return dict(sample_id='synthetic-a',source_label=label,html_sha256='a'*64,captured_at=t,evidence=evidence,reviews=reviews)


def test_review_agreement_and_relabel_history():
    p=packet();p['source_label']=1
    r=adjudicate(p)
    assert r['status']=='accepted_recorded_review' and r['changed'] and not r['independently_verified_by_software']


@pytest.mark.parametrize('change',["same_source","absent_blocklist","stale_evidence","model_prediction"])
def test_insufficient_support_is_quarantined(change):
    p=packet()
    if change=='same_source':p['evidence'][1]['origin_family']=p['evidence'][0]['origin_family']
    if change=='absent_blocklist':p['evidence'][1]['evidence_type']='absence_from_blocklist'
    if change=='stale_evidence':p['evidence'][1]['valid_to']='2026-10-09T00:00:00Z';p['evidence'][1]['valid_from']='2026-10-08T00:00:00Z'
    if change=='model_prediction':p['evidence'][1]['evidence_type']='model_prediction'
    assert adjudicate(p)['status']=='quarantine'


@pytest.mark.parametrize('change',['same_reviewer','snapshot','not_blind','automated','early_review','bad_evidence_reference'])
def test_invalid_review_is_rejected(change):
    p=packet()
    if change=='same_reviewer':p['reviews'][1]['reviewer_id']=p['reviews'][0]['reviewer_id']
    if change=='snapshot':p['reviews'][1]['html_sha256']='b'*64
    if change=='not_blind':p['reviews'][1]['blind_to_model_and_other_review']=False
    if change=='automated':p['reviews'][1]['reviewer_type']='llm'
    if change=='early_review':p['reviews'][1]['reviewed_at']='2026-10-09T00:00:00Z'
    if change=='bad_evidence_reference':p['reviews'][1]['evidence_ids']=['not-found']
    with pytest.raises(ValueError):adjudicate(p)


def test_disagreement_requires_separate_third_review():
    p=packet();p['reviews'][1]['label']=1
    assert adjudicate(p)['status']=='quarantine'
    third={**p['reviews'][0],'reviewer_id':'synthetic-third','role':'adjudicator'}
    p['reviews'].append(third)
    assert adjudicate(p)['status']=='accepted_recorded_review'
    p['reviews'][-1]['label']='uncertain'
    assert adjudicate(p)['status']=='quarantine'


def test_conflicting_evidence_not_majority_vote():
    p=packet();p['evidence'].append({**p['evidence'][0],'id':'conflict','verdict':1})
    assert adjudicate(p)['status']=='quarantine'
    p['reviews'].append({**p['reviews'][0],'reviewer_id':'synthetic-third','role':'adjudicator','resolved_conflict_ids':['conflict']})
    assert adjudicate(p)['status']=='accepted_recorded_review'


def test_planning_is_not_synthetic_sample_inflation():
    r=precision_plan()
    assert r['independent_binomial_worst_case_n_for_95pct_plus_minus_5pp']==385
    assert r['zero_error_n_for_one_sided_95pct_upper_fpr_1pct']==299
    assert r['zero_error_n_for_one_sided_95pct_upper_fpr_0_1pct']==2995
    assert wilson(0,10)[0]==0


def test_actual_historical_intake_and_freeze(tmp_path):
    out=tmp_path/'audit';summary=historical_audit(ROOT,out)
    assert summary['frozen_files_verified']==75
    assert summary['historical_partitions']=={'train':3461,'validation':742,'test':742,'excluded':55}
    assert summary['test_predictions_read']==summary['model_fits']==summary['reviewed_labels']==0
    queue=read_rows(out/'review_queue_blinded.jsonl')
    assert all(not ({'score','source_label','reasons','label'} & r.keys()) for r in queue)
    assert summary['review_reason_counts']['fusion_introduced_error']==18
    with pytest.raises(FileExistsError):historical_audit(ROOT,out)


def test_group_folds_have_no_leakage_and_same_samples():
    y=np.tile([0,1],30);groups=np.repeat(np.arange(30),2)
    folds=group_folds(y,groups,5,4941801)
    assert sorted(i for _,v in folds for i in v)==list(range(60))
    assert all(not set(groups[t])&set(groups[v]) for t,v in folds)
    with pytest.raises(ValueError):group_folds(np.zeros(60),groups,5,4941801)


@pytest.mark.parametrize('name',MODELS)
def test_synthetic_model_probability_smoke(name):
    rng=np.random.default_rng(4941801);x=rng.normal(size=(60,5));y=np.tile([0,1],30);groups=np.repeat(np.arange(30),2)
    folds=group_folds(y,groups,3,4941801)
    for variant in (0,1):
        estimator=make_model(name,variant,4941802,folds if name=='rbf_svm' else None)
        estimator.fit(x,y)
        probability=estimator.predict_proba(x[:4])
        assert probability.shape==(4,2) and np.isfinite(probability).all()
        assert np.allclose(probability.sum(axis=1),1)


def test_svm_cannot_use_hidden_rowwise_calibration():
    with pytest.raises(ValueError):make_model('rbf_svm',0,4941802)


def test_near_tie_uses_inner_fpr():
    assert choose_variant([dict(f1=.9,fpr=.1),dict(f1=.897,fpr=.05)])==1
    assert choose_variant([dict(f1=.9,fpr=.1),dict(f1=.89,fpr=.05)])==0


def cohort():
    packets=[packet(i) for i in (0,1)];packets[1]['sample_id']='synthetic-b'
    packets[1]['html_sha256']='b'*64
    for ev in packets[1]['evidence']+packets[1]['reviews']:ev['html_sha256']='b'*64
    rows=[dict(sample_id=p['sample_id'],html_sha256=p['html_sha256'],label=p['source_label'],captured_at=p['captured_at'],
               scope='new_development',source_family='synthetic',registered_domain_sha256=str(i)*64,final_group=str(i),
               normalized_url_sha256=str(i+2)*64,structural_sha256=str(i+4)*64,
               overlap_audit_status='complete_with_pilot_url_template_campaign',overlap_audit_receipt_sha256='d'*64,
               features={n:0.0 for n in feature_names('url_dom')}) for i,p in enumerate(packets)]
    return rows,packets


def test_real_runner_rejects_exposed_and_unreviewed_rows():
    rows,packets=cohort();assert validate_cohort(rows,packets,[])==list(feature_names('url_dom'))
    history=[dict(sample_id=rows[0]['sample_id'],source_file='x',source_row=0)]
    with pytest.raises(ValueError):validate_cohort(rows,packets,history)
    packets[0]['reviews']=[]
    with pytest.raises(ValueError):validate_cohort(rows,packets,[])


@pytest.mark.parametrize('key',['scope','html_sha256','registered_domain_sha256','normalized_url_sha256','structural_sha256','features','overlap_audit_status'])
def test_leakage_schema_and_scope_rejected(key):
    rows,packets=cohort()
    if key=='scope':rows[0][key]='test'
    elif key=='features':rows[0][key]['unregistered_extra']=1
    elif key=='overlap_audit_status':rows[0][key]='pending'
    else:rows[1][key]=rows[0][key]
    with pytest.raises(ValueError):validate_cohort(rows,packets,[])


def test_overlap_receipt_required_and_bound(tmp_path):
    from .intake import digest,write_json
    rows,_=cohort();history=tmp_path/'history.jsonl';history.write_text('')
    receipt=tmp_path/'overlap.json'
    data=dict(status='completed',historical_registry_sha256=digest(history),completed_checks=['pilot','sample_id','normalized_url','registered_domain','exact_html','structural_template','campaign'],
              candidates=[dict(sample_id=r['sample_id'],html_sha256=r['html_sha256'],eligible_for_new_development=True) for r in rows],evidence_sha256={'synthetic':'e'*64},reviewer_id='synthetic-reviewer')
    write_json(receipt,data)
    for row in rows:row['overlap_audit_receipt_sha256']=digest(receipt)
    validate_overlap_receipt(rows,history,receipt)
    rows[0]['overlap_audit_receipt_sha256']='stale'
    with pytest.raises(ValueError):validate_overlap_receipt(rows,history,receipt)


def test_passive_packet_check_is_not_label_review():
    import hashlib
    from .prepare_packets import inspect_packet
    html='<html><body><form><input type="password"></form></body></html>'
    q=dict(sample_id='synthetic',review_id='synthetic',html_sha256=hashlib.sha256(html.encode()).hexdigest())
    source=dict(url_clean='https://example.test/',capture_date='2026-10-10',lang='en')
    r=inspect_packet(q,source,html,2097152)
    assert r['status']=='technical_checks_passed' and r['counters']['password_input_count']==1
    assert r['label_status']=='not_independently_adjudicated'
    with pytest.raises(ValueError):inspect_packet(q,source,html+'changed',2097152)


def test_nested_runner_end_to_end_synthetic_only(tmp_path,monkeypatch):
    from . import compare as module
    from .intake import HERE
    protocol=json.loads((HERE/'protocol.json').read_text())
    protocol['model_seeds']=[4941802]
    protocol['experiments'].update(outer_group_folds=3,inner_group_folds=2,modalities=['url_only'])
    monkeypatch.setattr(module,'MODELS',('logistic_regression',))
    names=list(feature_names('url_dom'));rng=np.random.default_rng(4941801)
    rows=[dict(sample_id='synthetic-'+str(i),label=i%2,final_group='synthetic-group-'+str(i//2),
               features=dict(zip(names,rng.normal(size=len(names))))) for i in range(120)]
    out=tmp_path/'synthetic-run';module.compare(rows,names,out,protocol)
    predictions=read_rows(out/'predictions.jsonl')
    assert len(predictions)==len(rows) and len({r['sample_id'] for r in predictions})==len(rows)
    assert json.loads((out/'status.json').read_text())['outer_fit_cells']==3
