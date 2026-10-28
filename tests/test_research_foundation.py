"""Software fixtures only: scores here are not research performance evidence."""
import json
import random

import joblib
import numpy as np
import pandas as pd
import pytest

from phishing_url.experiment import _choose_groups, _load, _pipeline, run, validate_split
from phishing_url.feature_registry import FeatureExtractor, resolve_feature_set
from phishing_url.ingestion import ParsedRow
from phishing_url.phase1_diagnostics import run as run_phase1_diagnostics
from phishing_url.prepare import prepare_dataset
from phishing_url.randomness import load_seed_plan, main as seed_main, make_seed_plan
from phishing_url.url_cleaning import clean_url, registered_domain


def fixture_frame():
    rows = []
    for label in (0, 1):
        for i in range(24):
            for j in range(2):
                url = f"{'http' if i % 3 == 0 else 'https'}://class{label}-{i}.example/{'login' if label else 'about'}/{j}?n={i}"
                rows.append(dict(url_raw=url, url_clean=clean_url(url), label=label,
                                 source="synthetic_test_fixture", registered_domain=registered_domain(url)))
    return pd.DataFrame(rows)


def test_seed_plan_replay_and_no_overwrite(tmp_path):
    plan = make_seed_plan(100)
    assert plan == make_seed_plan(100) and plan != make_seed_plan(101)
    values = [plan['sampling_seed'],plan['test_seed'],plan['model_seed'],*plan['development_seeds']]
    assert len(set(values)) == len(values)
    path = tmp_path/'seeds.json'
    seed_main(['--master-seed','100','--output',str(path)])
    assert load_seed_plan(path) == plan
    with pytest.raises(FileExistsError):seed_main(['--output',str(path)])
    with pytest.raises(ValueError):make_seed_plan(-1)


def test_sampling_independent_of_input_order_and_global_rng():
    frame = fixture_frame()
    rows = [ParsedRow('phishtank' if r.label else 'tranco', r.label,i,r.url_raw) for i,r in frame.iterrows()]
    rows.append(ParsedRow('openphish',1,999,rows[-1].url_raw))
    first = prepare_dataset(rows,12,81)
    random.shuffle(rows); random.seed(999)
    again = prepare_dataset(rows,12,81)
    assert first.records == again.records
    assert first.sampling_manifest == again.sampling_manifest
    assert first.records != prepare_dataset(rows,12,82).records
    assert len({r.url_clean for r in first.records}) == 24


@pytest.mark.parametrize('label',[.5,2,-1])
def test_loader_rejects_fractional_or_unknown_labels(tmp_path,label):
    frame=fixture_frame();frame['label']=frame.label.astype(float);frame.loc[0,'label']=label
    path=tmp_path/'bad.csv';frame.to_csv(path,index=False)
    with pytest.raises(ValueError,match='label'):_load(path)


def test_loader_order_invariance_and_provenance_checks(tmp_path):
    frame=fixture_frame();path=tmp_path/'data.csv';frame.to_csv(path,index=False);first=_load(path)
    frame.sample(frac=1,random_state=10).to_csv(path,index=False)
    pd.testing.assert_frame_equal(first,_load(path))
    frame.loc[0,'registered_domain']='wrong.example';frame.to_csv(path,index=False)
    with pytest.raises(ValueError,match='PSL'):_load(path)
    frame=fixture_frame();frame.loc[0,'url_raw']='https://different.example/';frame.to_csv(path,index=False)
    with pytest.raises(ValueError,match='url_raw'):_load(path)


def test_vectorized_group_search_preserves_existing_protocol():
    frame=fixture_frame().assign(domain_group=lambda f:f.registered_domain)
    groups=frame.groupby('domain_group').agg(size=('label','size'),positives=('label','sum'))
    rng=np.random.default_rng(2025);best=None
    for _ in range(500):
        selected=set();count=positives=0
        for name in rng.permutation(groups.index.to_numpy()):
            if count >= len(frame)*.15:break
            selected.add(name);count+=int(groups.loc[name,'size']);positives+=int(groups.loc[name,'positives'])
        score=abs(count/len(frame)-.15)+abs(positives/count-frame.label.mean())
        if best is None or score<best[0]:best=(score,selected)
    assert _choose_groups(frame,.15,2025)==best[1]


def test_16_18_21_and_actual_hostname_only():
    url='https://host12.example:8443/a%20b?token=3'
    for name,width in [('compact16',16),('baseline',18),('expanded21',21)]:
        assert len(FeatureExtractor(resolve_feature_set(name)).transform_one(url))==width
    extras=FeatureExtractor(('hostname_digit_ratio','percent_encoded_count','has_nondefault_port'))
    assert extras.transform_one(url)==[2/14,1.,1.]
    assert extras.transform_one('https://host12.example:443/')[-1]==0
    host=FeatureExtractor(resolve_feature_set('hostname_only'))
    assert host.transform_one(url)==host.transform_one('http://host12.example/long999?x=123')
    small=FeatureExtractor(('query_length','url_length'))
    assert small.transform_mapping({'url_length':20,'query_length':0,'uses_https':1})==[0,20]
    assert np.isnan(small.transform_mapping({'url_length':20},allow_missing=True)[0])
    with pytest.raises(ValueError,match='missing'):small.transform_mapping({'url_length':20})
    with pytest.raises(ValueError,match='unknown'):small.transform_mapping({'new_unregistered':1})


@pytest.mark.parametrize('model,params',[
    ('logistic_regression',{'C':1}),
    ('decision_tree',{'max_depth':3,'min_samples_leaf':2}),
    ('random_forest',{'n_estimators':10,'max_depth':3,'min_samples_leaf':1,'max_features':'sqrt'}),
    ('gradient_boosting',{'n_estimators':10,'learning_rate':.1,'max_depth':2,'min_samples_leaf':1}),
])
def test_missing_columns_preserved_and_preprocessing_training_only(model,params):
    X=pd.DataFrame({'url_length':[10.,20.,np.nan,30.], 'query_length':[np.nan]*4})
    pipe=_pipeline(model,params,tuple(X),5).fit(X,pd.Series([0,1,0,1]))
    before=pipe.named_steps['preprocess'].named_transformers_['numeric'].named_steps['imputer'].statistics_.copy()
    assert before[0]==20.
    score=pipe.predict_proba(pd.DataFrame({'url_length':[10000.], 'query_length':[7.]}))
    assert np.isfinite(score).all()
    np.testing.assert_array_equal(before,pipe.named_steps['preprocess'].named_transformers_['numeric'].named_steps['imputer'].statistics_)
    names=pipe.named_steps['preprocess'].get_feature_names_out()
    assert 'query_length' in names and 'missingindicator_query_length' in names


def test_end_to_end_development_then_explicit_fixture_test(tmp_path):
    path=tmp_path/'fixtures.csv';fixture_frame().to_csv(path,index=False)
    dev=tmp_path/'development';run(path,dev)
    assert not (dev/'final_test_metrics.csv').exists()
    assert json.loads((dev/'experiment_manifest.json').read_text())['test_evaluated'] is False
    splits=pd.read_csv(dev/'development_split_manifest.csv')
    assert len(splits)==5*len(fixture_frame())
    assert splits[splits.split=='test'].groupby('sample_id').size().eq(5).all()
    for _,part in splits.groupby('development_seed'):
        assert part.groupby('domain_group').split.nunique().eq(1).all()
    paired=pd.read_csv(dev/'paired_validation_comparison.csv')
    assert len(paired)==10
    assert 'gradient_boosting_minus_logistic_regression_f1' in paired.columns
    with pytest.raises(ValueError,match='requires --development-run'):
        run(path,tmp_path/'blocked',evaluate_test=True)
    with pytest.raises(ValueError,match='differs'):
        run(path,tmp_path/'mismatch',feature_sets=('compact16',),evaluate_test=True,development_run=dev)
    expanded=tmp_path/'expanded_development';run(path,expanded,feature_sets=('compact16','expanded21'))
    final=tmp_path/'explicit_fixture_test';run(path,final,feature_sets=('compact16','expanded21'),evaluate_test=True,development_run=expanded)
    assert len(pd.read_csv(final/'final_test_metrics.csv'))==8
    for feature_set,width in [('compact16',16),('expanded21',21)]:
        artifact=joblib.load(final/'models'/f'{feature_set}_logistic_regression.joblib')
        assert len(artifact['feature_names'])==width
        X=pd.DataFrame([FeatureExtractor(tuple(artifact['feature_names'])).transform_one('https://demo.example/')],columns=artifact['feature_names'])
        assert artifact['pipeline'].predict_proba(X).shape==(1,2)
    phase1=tmp_path/'phase1_diagnostics'
    run_phase1_diagnostics(path,dev,phase1,fractions=(.5,1.0))
    size=pd.read_csv(phase1/'training_size_stability.csv')
    assert set(size.model)=={'logistic_regression','decision_tree','random_forest','gradient_boosting'}
    assert set(size.training_fraction)=={.5,1.0}
    split=pd.read_csv(phase1/'split_strategy_comparison.csv')
    assert set(split.split_strategy)=={'domain_grouped','random_url'}
    assert split[split.split_strategy=='domain_grouped'].domain_overlap_count.eq(0).all()
    config=json.loads((phase1/'diagnostic_config.json').read_text())
    assert config['test_sample_count_locked']>0
    assert config['scope'].startswith('development only')
    with pytest.raises(FileExistsError):run_phase1_diagnostics(path,dev,phase1)

    with pytest.raises(FileExistsError):run(path,final,overwrite=True)
