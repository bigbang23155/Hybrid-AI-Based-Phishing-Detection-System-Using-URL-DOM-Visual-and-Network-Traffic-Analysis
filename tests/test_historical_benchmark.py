import json
from pathlib import Path
import pytest
from phishing_url.historical_benchmark import audit, freeze, sha
from phishing_url.randomness import make_seed_plan


def inputs(tmp_path):
    raw=tmp_path/'raw';raw.mkdir()
    sources=[]
    for label in (0,1):
        p=raw/f'{label}.json'
        rows=[f'https://c{label}-{i}.example/path' for i in range(8)]
        rows += [rows[0], 'scheme-missing.example', 'https://conflict.example/']
        p.write_text(json.dumps(rows))
        sources.append({'filename':p.name,'source':f'published_class_{label}','label':label,'sha256':sha(p)})
    spec={'dataset_id':'fixture','sources':sources,'target_per_label':4,'min_domains_per_class_heuristic':3,
          'label_semantics':'synthetic software fixture only','limitations':[]}
    return raw,spec


def test_audit_conflicts_invalids_and_generic_source_summary(tmp_path):
    raw,spec=inputs(tmp_path);a=tmp_path/'audit';result=audit(raw,a,spec)
    assert result['invalid_rows']==2 and result['conflicting_normalized_urls']==1
    assert result['profiles']['0']['rows']==8 and result['profiles']['1']['rows']==8
    seeds=tmp_path/'seed.json';seeds.write_text(json.dumps(make_seed_plan(123)))
    out=tmp_path/'frozen';freeze(raw,a,out,spec,seeds)
    import pandas as pd
    sources=pd.read_csv(out/'source_summary.csv');actual=sources[sources.raw_records>0]
    assert actual.label.tolist()==[0,1] and actual.selected_records.tolist()==[4,4]
    assert json.loads((out/'frozen_manifest.json').read_text())['order_invariance_verified']
    with pytest.raises(FileExistsError):freeze(raw,a,out,spec,seeds)


def test_source_integrity_and_no_fabricated_scheme(tmp_path):
    raw,spec=inputs(tmp_path)
    (raw/'0.json').write_text('[]')
    with pytest.raises(ValueError,match='checksum'):audit(raw,tmp_path/'bad',spec)
