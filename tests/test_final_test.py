import copy
import json
from pathlib import Path
import numpy as np
import pytest
from phishing_url.final_test import (assemble_test,extract_test,exclusive_json,verify_claim,
    summarize_test,json_bytes_for_ready,validate_execution)
from phishing_url.formal_candidates import sha
from phishing_url.modality_contract import read_protocol, assemble_development
from test_paired_development import fixture_rows
ROOT=Path(__file__).resolve().parents[1]


def synthetic_test():
    m,c,p=fixture_rows();m=[r for r in m if r['sample_id']!='sealed']
    for r in m:r['partition']='test'
    return m,c,p


def test_test_extraction_and_all_modality_alignment(tmp_path):
    m,c,p=synthetic_test();u,d,ctx,r=extract_test(m,c,p,tmp_path/'features')
    assert r['successes']==24 and r['failures']==0
    for mode,n in [('url_only',18),('dom_only',23),('url_dom',41)]:
        ids,x=assemble_test(m,u[::-1],d[::-1],mode)
        assert ids==sorted(r['sample_id'] for r in m) and x.shape==(24,n)
        # Exactly the baseline feature order used by the frozen training assembler.
        mm,uu,dd=copy.deepcopy((m,u,d))
        for row in mm+uu+dd:row['partition']='validation'
        dev_ids,dev_x=assemble_development(mm,uu,dd,partition='validation',modality=mode)
        assert ids==dev_ids and np.array_equal(x,np.asarray(dev_x))
    broken=copy.deepcopy(d);broken[0]['final_group']='wrong'
    with pytest.raises(ValueError,match='pairing metadata'):assemble_test(m,u,broken,'url_only')
    with pytest.raises(ValueError,match='cohort mismatch'):assemble_test(m,u[:-1],d,'url_dom')
    with pytest.raises(ValueError,match='cohort mismatch'):assemble_test(m,u+u[:1],d,'url_dom')


def test_test_extraction_preserves_failure_without_backfill(tmp_path):
    m,c,p=synthetic_test();p[0]=(p[0][0],'<p>changed</p>')
    with pytest.raises(ValueError,match='no dropping'):extract_test(m,c,p,tmp_path/'bad')
    rows=[json.loads(s) for s in (tmp_path/'bad/extraction_status.jsonl').read_text().splitlines()]
    assert len(rows)==24 and sum(r['extraction_status']=='failed' for r in rows)==1
    assert json.loads((tmp_path/'bad/feature_integrity.json').read_text())['no_backfill']


def test_unexpected_partition_never_reaches_extractor(tmp_path,monkeypatch):
    m,c,p=synthetic_test()
    def forbidden(*args):raise AssertionError('must reject before extraction')
    monkeypatch.setattr('phishing_url.final_test.extract_dom_features',forbidden)
    with pytest.raises(ValueError,match='unexpected/duplicate'):
        extract_test(m,c,[('train-row','ignored')],tmp_path/'unexpected')
    assert 'unexpected_or_duplicate' in (tmp_path/'unexpected/extraction_status.jsonl').read_text()


def test_exclusive_marker_cannot_be_reused(tmp_path):
    p=tmp_path/'marker.json';exclusive_json(p,{'a':1})
    with pytest.raises(FileExistsError):exclusive_json(p,{'a':2})
    assert json.loads(p.read_text())=={'a':1}


def test_persistent_claim_bound_to_preparation_commit_and_run():
    ready=dict(execution_commit='commit',run_id='5')
    cfg=dict(persistent_claim_ref='refs/tags/test')
    claim=dict(ref=cfg['persistent_claim_ref'],object={'sha':'commit'},run_id='5',run_attempt='1',ready_sha256=sha(json_bytes_for_ready(ready)))
    verify_claim(claim,ready,cfg,'commit','5')
    for change in [{'run_attempt':'2'},{'run_id':'6'},{'object':{'sha':'different'}},{'ready_sha256':'bad'}]:
        with pytest.raises(ValueError):verify_claim({**claim,**change},ready,cfg,'commit','5')


def test_synthetic_six_cell_outputs_and_independent_metrics(tmp_path):
    import importlib.util
    spec=importlib.util.spec_from_file_location('independent',ROOT/'scripts/verify_final_test.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    m,c,p=synthetic_test();u,d,context,_=extract_test(m,c,p,tmp_path/'features')
    ids=sorted(r['sample_id'] for r in m);y=np.array([r['label'] for r in m])
    lock=read_protocol(ROOT/'config/assignment03_final_evaluation_v1.json');lock['uncertainty']['resamples']=10
    cfg=read_protocol(ROOT/'config/assignment03_development_review_v1.json');cfg['diagnostic_bootstrap_repeats']=10
    scores={cell['condition']:np.where(y==1,.8,.2) for cell in lock['evaluation_cells']}
    # Deterministic bad URL-only predictions and threshold-boundary hybrid errors.
    scores['random_forest/url_only/baseline'][0]=.8
    scores['random_forest/url_dom/baseline'][2]=.5
    scores['random_forest/url_dom/baseline'][3]=.4
    public=tmp_path/'public';public.mkdir()
    rows=summarize_test(m,ids,scores,d,context,[3,5,9],lock,cfg,public)
    assert len(rows)==6
    for r in rows:module.match(module.independent_metrics(y,scores[r['condition']]),r)
    paired=json.loads((public/'paired_error_cohorts.json').read_text())
    r=[r for r in paired if r['model']=='random_forest' and r['comparator']=='url_only']
    assert next(x for x in r if x['kind']=='fixes')['n']==1
    assert next(x for x in r if x['kind']=='breaks')['n']==2
    slices=json.loads((public/'slices.json').read_text())
    assert any(r['fpr'] is None for r in slices)


def test_authorized_extension_leaves_original_freeze_unchanged():
    lock,cfg=validate_execution(ROOT)
    assert not lock['test_execution_authorized'] and cfg['test_evaluation_authorized']
    assert cfg['evaluation_count']==1 and len(lock['evaluation_cells'])==6
