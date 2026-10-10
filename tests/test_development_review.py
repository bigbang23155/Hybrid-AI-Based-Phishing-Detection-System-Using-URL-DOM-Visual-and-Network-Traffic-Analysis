import json
from pathlib import Path
import numpy as np
import pytest
from phishing_url.development_review import bin_values, permutation_indices, permutation_review, standardize_password, metrics, analyze
from phishing_url.paired_development import extract_development
from phishing_url.modality_contract import assemble_development, make_unfitted_model, read_protocol
from test_paired_development import fixture_rows
ROOT=Path(__file__).resolve().parents[1]


def test_bins_are_training_only_and_ties_explicit():
    cuts,tr,va=bin_values([0,0,2,4],[1000,-1,0,2],[.25,.5,.75])
    assert cuts.tolist()==[0,1,2.5]
    assert va.tolist()==[3,0,1,2]


def test_permutation_preserves_each_stratum_and_is_reproducible():
    strata=np.array(['a']*10+['b']*5+['singleton'])
    a=permutation_indices(strata,np.random.default_rng(7))
    assert np.array_equal(strata,strata[a])
    assert sorted(a.tolist())==list(range(16)) and a[-1]==15
    assert np.array_equal(a,permutation_indices(strata,np.random.default_rng(7)))


def test_no_class_means_undefined_rates():
    assert metrics([1,1],[.6,.8])['fpr'] is None
    assert metrics([0,0],[.1,.8])['recall'] is None


def test_standardization_excludes_unsupported_cells_with_coverage():
    y=np.array([0]*12);password=np.array([False]*6+[True]*6);bins=np.array([0]*5+[1]+[0]*5+[1])
    score=np.array([.1]*6+[.9]*6)
    r=standardize_password(y,score,password,bins,5)
    assert r['fpr']['supported_class_rows']==10 and r['fpr']['total_class_rows']==12
    assert r['fpr']['present_minus_absent']==1
    assert not r['fnr']['available']


def test_irrelevant_permutation_has_zero_effect():
    class Model:
        def predict_proba(self,x):return np.column_stack((1-x[:,0],x[:,0]))
    x=np.array([[.1,1],[.8,2],[.2,3],[.9,4]])
    cfg={'permutation_modes':['unconditional'],'permutation_seed':11,'permutation_repeats':3}
    rows=permutation_review(Model(),x,np.array([0,1,0,1]),['signal','noise'],{'noise':['noise']},['all']*4,cfg)
    assert all(r['f1_drop']==r['auc_drop']==r['brier_increase']==0 for r in rows)


def test_small_review_replays_same_models_and_exact_cohorts(tmp_path):
    m,c,p=fixture_rows();u,d,context,_=extract_development(m,c,p,tmp_path/'features')
    cfg=read_protocol(ROOT/'config/assignment03_development_review_v1.json')
    cfg.update(permutation_repeats=2,diagnostic_bootstrap_repeats=10,standardization_min_class_support_per_cell=1)
    protocol=read_protocol(ROOT/'config/assignment03_modeling_protocol_v1.json')
    for params in protocol['models'].values():params['n_estimators']=2
    refs=[];index={r['sample_id']:r for r in m}
    for model in protocol['models']:
        for modality in protocol['modalities']:
            mat={};ids={}
            for part in ('train','validation'):
                ids[part],mat[part]=assemble_development(m,[r for r in u if r['partition']==part],[r for r in d if r['partition']==part],partition=part,modality=modality)
            est=make_unfitted_model(protocol,model,cfg['primary_seed']);est.fit(mat['train'],[index[s]['label'] for s in ids['train']])
            for sid,score in zip(ids['validation'],est.predict_proba(mat['validation'])[:,1]):
                refs.append(dict(condition=f'{model}/{modality}/baseline',sample_id=sid,label=index[sid]['label'],partition='validation',score=float(score)))
    out=tmp_path/'public';out.mkdir()
    result=analyze(m,u,d,context,c,protocol,cfg,refs,out)
    assert result['replayed_fits']==6 and result['maximum_score_difference']==0
    assert result['test_feature_rows']==result['test_predictions']==0
    ledger=[json.loads(x) for x in (out/'error_ledger.jsonl').read_text().splitlines()]
    assert len(ledger)==48 and all(r['sample_id']!='sealed' for r in ledger)
    bad=refs.copy();bad[0]={**bad[0],'score':.99999}
    with pytest.raises(ValueError,match='score replay failed'):analyze(m,u,d,context,c,protocol,cfg,bad,out)
