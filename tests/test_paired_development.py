import json
from pathlib import Path

import numpy as np
import pytest
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             roc_auc_score, average_precision_score, brier_score_loss)

from phishing_url.formal_candidates import sha
from phishing_url.modality_contract import read_protocol
from phishing_url.paired_development import (weighted_metrics, extract_development,
                                            bootstrap_intervals, run_models)

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("seed", [1, 3, 11, 21])
def test_weighted_metrics_against_sklearn_with_ties_and_zero_weights(seed):
    rng = np.random.default_rng(seed)
    y = np.tile([0, 1], 30)
    s = rng.choice([0, .1, .5, .8, 1], len(y))
    w = rng.integers(0, 5, len(y))
    m = weighted_metrics(y, s, w)
    pred = s >= .5
    for name, function in [('accuracy',accuracy_score),('precision',precision_score),
                           ('recall',recall_score),('f1',f1_score)]:
        assert m[name] == pytest.approx(function(y, pred, sample_weight=w))
    assert m['roc_auc'] == pytest.approx(roc_auc_score(y, s, sample_weight=w))
    assert m['average_precision'] == pytest.approx(average_precision_score(y, s, sample_weight=w))
    assert m['brier_score'] == pytest.approx(brier_score_loss(y, s, sample_weight=w))
    assert sum(m[k] for k in ('tn','fp','fn','tp')) == w.sum()


def test_metric_edges():
    m = weighted_metrics([0, 0], [.1, .8])
    assert m['roc_auc'] is None and m['average_precision'] is None
    assert m['fp'] == 1 and m['fpr'] == .5
    assert weighted_metrics([0,1], [.1,.1])['precision'] == 0
    with pytest.raises(ValueError): weighted_metrics([0,1], [float('nan'),.5])
    with pytest.raises(ValueError): weighted_metrics([0,1], [.2,.5], [0,0])


def fixture_rows():
    manifest, chosen, payload = [], [], []
    for i in range(24):
        sid, label = str(i).zfill(3), i%2
        part = 'train' if i < 16 else 'validation'
        h = f'<html><form><input type="{"password" if label else "text"}"></form><p>{i}</p></html>'
        domain = f'page{i}.example.org'
        # Domain field here is deterministic fixture identity, independently matched below.
        manifest.append(dict(sample_id=sid, partition=part, label=label, final_group=f'g{i//2}',
                             html_sha256=sha(h.encode()), eligible=True, source_file='data/train-001.parquet',
                             source_row=i, registered_domain_sha256=sha(domain.encode())))
        chosen.append(dict(sample_id=sid,label=label,source_file='data/train-001.parquet',source_row=i,
                           registered_domain=domain,url_clean=f'https://{domain}/a{i}',
                           capture_date='2025-01-01', lang='en',target=None))
        payload.append((sid,h))
    manifest.append(dict(sample_id='sealed',partition='test',eligible=True))
    return manifest, chosen, payload


def test_extraction_exact_coverage_and_failure_preserved(tmp_path):
    m,c,p = fixture_rows()
    u,d,ctx,summary = extract_development(m,c,p,tmp_path/'ok')
    assert len(u)==len(d)==len(ctx)==24
    assert summary['failures']==summary['test_feature_rows']==0
    bad = p.copy(); bad[0]=(bad[0][0], '<p>tampered</p>')
    with pytest.raises(ValueError,match='stop before training'):
        extract_development(m,c,bad,tmp_path/'bad')
    status=[json.loads(x) for x in (tmp_path/'bad/extraction_status.jsonl').read_text().splitlines()]
    assert len(status)==24 and status[0]['extraction_status']=='failed'
    assert 'hash mismatch' in status[0]['reason']


def test_test_payload_rejected_before_extractor(tmp_path,monkeypatch):
    m,c,p=fixture_rows()
    def forbidden(*args): raise AssertionError('test must not be inspected')
    monkeypatch.setattr('phishing_url.paired_development.extract_dom_features',forbidden)
    with pytest.raises(ValueError,match='test never'):
        extract_development(m,c,[('sealed','<p>secret</p>')],tmp_path/'bad')


def test_missing_duplicate_payloads_and_candidate_ids_stop(tmp_path):
    m,c,p=fixture_rows()
    with pytest.raises(ValueError,match='stop before training'):
        extract_development(m,c,p[:-1],tmp_path/'missing')
    with pytest.raises(ValueError,match='duplicate payload'):
        extract_development(m,c,p+p[:1],tmp_path/'duplicate')
    with pytest.raises(ValueError,match='candidate IDs'):
        extract_development(m,c[:-1],p,tmp_path/'candidate')


def test_paired_bootstrap_identical_scores_have_zero_difference():
    y=np.array([0,1,0,1,0,1]); s=np.array([.1,.7,.6,.9,.2,.4])
    scores={f'random_forest/{m}/baseline':s for m in ('url_only','dom_only','url_dom')}
    cfg={'resamples':80,'seed':4941490}
    a=bootstrap_intervals(y,scores,['a','a','b','b','c','c'],cfg)
    assert a==bootstrap_intervals(y,scores,['a','a','b','b','c','c'],cfg)
    assert a['group_count']==3
    for row in a['paired_differences'].values():
        assert all(v['low']==v['high']==0 and v['valid_replicates']==80 for v in row.values())


def test_small_end_to_end_train_only_and_no_private_model_leak(tmp_path,monkeypatch):
    m,c,p=fixture_rows()
    u,d,ctx,_=extract_development(m,c,p,tmp_path/'features')
    protocol=read_protocol(ROOT/'config/assignment03_modeling_protocol_v1.json')
    protocol['model_seeds']=protocol['model_seeds'][:2]
    protocol['uncertainty']['resamples']=10
    for params in protocol['models'].values(): params['n_estimators']=2
    out=tmp_path/'run/public/models';out.parent.mkdir(parents=True)
    fit_sizes=[]
    # Use a fit spy at class level so joblib retains normal estimator serialization.
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    for cls in (RandomForestClassifier,GradientBoostingClassifier):
        original=cls.fit
        def spy(self,x,y,*a,_original=original,**kw):
            fit_sizes.append(len(y));assert len(y)==16
            return _original(self,x,y,*a,**kw)
        monkeypatch.setattr(cls,'fit',spy)
    s=run_models(m,u,d,ctx,protocol,out)
    assert s['completed_fits']==28 and len(fit_sizes)==28
    assert s['test_predictions']==0 and not s['test_evaluated']
    assert not list(out.parent.rglob('*.joblib'))
    assert len(list((tmp_path/'run/private_models').glob('*.joblib')))==28
    pred=[json.loads(x) for x in (out/'validation_predictions.jsonl').read_text().splitlines()]
    assert len(pred)==8*28 and {r['partition'] for r in pred}=={'validation'}
