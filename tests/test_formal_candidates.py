import copy
import json
from pathlib import Path
import pytest
from phishing_url.formal_candidates import select, run, file_sha, validate_frame

ROOT = Path(__file__).resolve().parents[1]

def policy():
    p = json.loads((ROOT/'config/assignment03_paired_release_policy_v1.json').read_text())
    p['sampling']['planned_candidates_per_label'] = 3
    p['sampling']['per_domain_cap_per_label'] = 1
    return p

def rows():
    return [dict(source_file=f'data/train-{s:03}.parquet', source_file_sha256=str(s)*64,
                 source_row=y*10+i, url=f'https://d{y}-{i}.example/path',
                 label='phish' if y else 'benign', date='2025-01-01', lang='en')
            for s in (1,2) for y in (0,1) for i in range(4)]

def test_global_dedup_order_invariance_and_shortfall():
    r = rows()
    chosen, audit = select(r, policy())
    assert len(chosen) == 6
    assert audit['metadata_exclusions']['duplicate_normalized_url'] == 8
    assert select(list(reversed(r)), policy()) == (chosen, audit)
    p = policy()
    p['sampling']['planned_candidates_per_label'] = 5
    _, audit = select(r,p)
    assert not audit['candidate_target_met']
    assert audit['per_label']['0']['shortfall'] == 1

def test_cross_shard_conflict_and_global_cap():
    r = rows()
    r.append({**r[0], 'source_row':99, 'label':'phish'})
    _, audit = select(r,policy())
    assert audit['metadata_exclusions']['conflicting_url_label'] == 3
    r = rows()
    for x in r:
        x['url'] = f"https://one.example/{x['source_file_sha256']}/{x['source_row']}"
    _, audit = select(r,policy())
    assert all(v['selected']==1 and v['shortfall']==2 for v in audit['per_label'].values())
    with pytest.raises(ValueError, match='duplicate source'):
        select(r+[r[0]],policy())

def test_adapter_does_not_decode_html_and_persists_shortfall(tmp_path, monkeypatch):
    pa = pytest.importorskip('pyarrow')
    import pyarrow.parquet as pq
    import phishing_url.formal_candidates as module
    p = policy()
    frame = json.loads((ROOT/'config/assignment03_paired_source_frame_v1.json').read_text())
    source = tmp_path/'source'
    (source/'data').mkdir(parents=True)
    raw = [{k:r.get(k) for k in module.METADATA_COLUMNS} | {'html':'DO NOT READ'} for r in rows()[:8]]
    path = source/'data/train-001.parquet'
    pq.write_table(pa.Table.from_pylist(raw),path)
    frame['sampling_frame'].update(fixed_shards=[dict(path='data/train-001.parquet',sha256=file_sha(path),size_bytes=path.stat().st_size)],fixed_shard_count=1,
        expected_total_source_bytes=path.stat().st_size,sample_target_before_content_inspection=3)
    real = pq.ParquetFile
    calls=[]
    class Guard:
        def __init__(self,path):
            self.inner=real(path)
            self.schema_arrow=self.inner.schema_arrow
        def read(self,columns):
            calls.append(columns)
            assert 'html' not in columns
            return self.inner.read(columns=columns)
    monkeypatch.setattr(pq,'ParquetFile',Guard)
    f,pol=tmp_path/'frame.json',tmp_path/'policy.json'
    f.write_text(json.dumps(frame));pol.write_text(json.dumps(p))
    out=tmp_path/'output'
    result=run(source,out,f,pol)
    assert calls == [module.METADATA_COLUMNS]
    assert result['candidate_target_met']
    assert result['html_column_read'] is False
    assert result['training_approved'] is False
    assert 'url_clean' not in (out/'public/candidate_replay.jsonl').read_text()
    with pytest.raises(FileExistsError):
        run(source,out,f,pol)
    path.write_bytes(b'tampered')
    with pytest.raises(ValueError,match='integrity'):
        run(source,tmp_path/'other',f,pol)

def test_reject_pilot_and_policy_mismatch():
    p=policy()
    f=json.loads((ROOT/'config/assignment03_paired_source_frame_v1.json').read_text())
    with pytest.raises(ValueError,match='sampling policy'):
        validate_frame(f,p)
    f['sampling_frame']['fixed_shards'][0]['path']='data/train-000.parquet'
    with pytest.raises(ValueError,match='shard frame'):
        validate_frame(f,p)
