"""Offline schema, label, selection and destination-guard regression tests."""
import copy
import json
from pathlib import Path
import pytest
from jsonschema.exceptions import ValidationError
from phishing_url.observation import artifact,audit,digest,label_assertion,now,validate_record,write_json
from phishing_url.pilot_capture import eligibility,select_phishing
from phishing_url.public_proxy import destination,public_address

ROOT=Path(__file__).resolve().parents[1]
SCHEMA=json.loads((ROOT/'schemas/observation_v1.schema.json').read_text())


@pytest.mark.parametrize('value',['127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:127.0.0.1','192.168.1.1','224.0.0.1'])
def test_nonpublic_destinations_fail(value):
    with pytest.raises(ValueError):public_address(value)


def test_proxy_ports_and_authority():
    assert public_address('8.8.8.8')=='8.8.8.8'
    assert destination('CONNECT','example.com:443')[:2]==('example.com',443)
    for target in ('https://user@example.com/','http://localhost/','http://example.com:22/'):
        with pytest.raises(ValueError):destination('GET',target)


def test_candidate_selection_seed_conflict_and_no_replacements():
    lines=[f'https://case{i}.example/path' for i in range(30)]+['not-url','https://case1.example/path']
    first,rejected,profile=select_phishing(lines,8,1,{'https://case2.example/path'})
    second,_,_=select_phishing(list(reversed(lines)),8,1,{'https://case2.example/path'})
    assert [r['url_clean'] for r in first]==[r['url_clean'] for r in second]
    assert len(first)==8 and len({r['url_clean'] for r in first})==8
    assert all(r['url_clean']!='https://case2.example/path' for r in first)
    assert len(select_phishing(lines,8,2,set())[0])==8
    assert len(select_phishing(['https://only.example/'],8,1,set())[0])==1
    assert any(r['reason']=='cross_source_label_conflict' for r in rejected)
    for raw in ('https://x.example/?token=secret','https://@x.example/','https://x.example:8080/'):
        with pytest.raises(ValueError):eligibility(raw)


def record(tmp_path,i=0):
    start=now();folder=tmp_path/'observations'/str(i);folder.mkdir(parents=True)
    modalities={}
    for name in ('url','dom','screenshot','network'):
        p=folder/(name+'.fixture')
        data=json.dumps({'observation_id':digest(str(i).encode())}).encode() if name in ('url','network') else (b'\x89PNG\r\n\x1a\nfixture' if name=='screenshot' else b'test-only')
        p.write_bytes(data);modalities[name]=artifact(tmp_path,p,now())
    r={'schema_version':'observation-v1','observation_id':digest(str(i).encode()),'candidate_id':digest(f'test_fixture\nhttps://case{i}.example/'.encode()),
       'candidate_class':i%2,'source':'test_fixture','url_raw':f'https://case{i}.example/','url_clean':f'https://case{i}.example/',
       'domain_group':f'case{i}.example','label':label_assertion(i%2,{'source':'test-only'}),'started_at':start,'ended_at':now(),
       'status':'complete','reason':None,'final_url':f'https://case{i}.example/','http_status':200,'navigation_chain':[],
       'modalities':modalities,'session':{'browser_version':'test','viewport':{},'locale':'en-US','timezone_id':'UTC',
        'sandbox_enabled':True,'fresh_context':True},'capture_duration_ms':1}
    return r,folder


def test_source_assertion_never_grants_training_label(tmp_path):
    r,folder=record(tmp_path);validate_record(r,tmp_path,SCHEMA)
    r['label']['project_label']=0
    with pytest.raises(ValidationError):validate_record(r,tmp_path,SCHEMA)


def test_artifact_integrity_and_path_escape(tmp_path):
    r,folder=record(tmp_path);(folder/'dom.fixture').write_bytes(b'changed')
    with pytest.raises(ValueError,match='checksum'):validate_record(r,tmp_path,SCHEMA)
    r['modalities']['dom']['path']='../outside'
    with pytest.raises(ValueError,match='escapes'):validate_record(r,tmp_path,SCHEMA)


def test_technical_success_does_not_approve_expansion(tmp_path):
    candidates=[]
    for i in range(16):
        r,folder=record(tmp_path,i);write_json(folder/'observation.json',r);candidates.append({k:r[k] for k in ('candidate_id','url_clean','candidate_class','source')})
    write_json(tmp_path/'plan.json',{'candidates':candidates});write_json(tmp_path/'preflight.json',{'passed':True})
    config=json.loads((ROOT/'config/observation_pilot_v1.json').read_text())
    result=audit(tmp_path,config,SCHEMA)
    assert result['technical_pass'] and not result['expansion_allowed'] and not result['label_gate_pass']
    assert result['pending_label_reviews']==16
    (tmp_path/'observations/0/observation.json').unlink()
    assert not audit(tmp_path,config,SCHEMA)['technical_pass']
