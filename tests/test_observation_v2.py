import asyncio
import copy
import json
from pathlib import Path
import pytest
from phishing_url.capture_policy_v2 import check_robots,nonblank,wait_visible
from phishing_url.label_review import append,derive_labels
from phishing_url.observation import now,write_json,artifact,validate_record
from test_observation_pilot import record


class Response:
    def __init__(self,status,body=b'',headers=None):self.status_code=status;self.body=body;self.headers=headers or {}
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def iter_content(self,size):yield self.body


class Session:
    def __init__(self,responses):self.responses=iter(responses);self.urls=[]
    def get(self,url,**kwargs):
        assert kwargs['allow_redirects'] is False
        self.urls.append(url);return next(self.responses)


def test_robots_redirect_body_evidence_and_exact_origin(tmp_path):
    session=Session([Response(302,b'redirect',{'location':'/rules.txt'}),Response(200,b'User-agent: *\nAllow: /\n',{'content-type':'text/plain'})])
    allowed,_=check_robots('https://safe.example/page','http://guard:8888','ResearchBot',tmp_path,tmp_path,session=session)
    assert allowed and len(session.urls)==2
    evidence=json.loads((tmp_path/'robots_decision.json').read_text())
    assert len(evidence['hops'])==2 and (tmp_path/'robots_1.txt').read_bytes().startswith(b'User-agent')
    session=Session([Response(302,headers={'location':'https://other.example/robots.txt'})])
    allowed,reason=check_robots('https://safe.example/page','http://guard:8888','ResearchBot',tmp_path,tmp_path,session=session)
    assert not allowed and reason=='robots_cross_origin_redirect' and len(session.urls)==1


@pytest.mark.parametrize('response,reason',[(Response(403),'robots_http_403'),(Response(200,b'User-agent: *\nDisallow: /'),'robots_disallow'),(Response(200,b'<html>challenge</html>',{'content-type':'text/html'}),'robots_html_instead_of_rules')])
def test_robots_does_not_bypass_denial_or_html(tmp_path,response,reason):
    allowed,actual=check_robots('https://safe.example/page','http://guard:8888','ResearchBot',tmp_path,tmp_path,session=Session([response]))
    assert not allowed and actual==reason


def test_visual_readiness_needs_visible_content_and_stability():
    config={'min_visible_text_chars':80,'min_image_viewport_fraction':.2,'max_wait_ms':200,'min_wait_ms':0,'poll_ms':1,'stable_polls':3}
    assert not nonblank({'visible_text_chars':20,'largest_visible_image_fraction':.01},config)
    class Page:
        count=0
        async def evaluate(self,script):
            self.count+=1
            return {'ready_state':'complete','visible_text_chars':100 if self.count>1 else 20,'loaded_visible_images':0,'largest_visible_image_fraction':0,'body_width':1280,'body_height':720}
        async def wait_for_timeout(self,n):await asyncio.sleep(n/1000)
    result=asyncio.run(wait_visible(Page(),config));assert result['passed'] and len(result['states'])>=4


def review_for(r,who='software-fixture',kind='human',decision='benign'):
    return {'observation_id':r['observation_id'],'policy_version':'label-policy-v1','reviewer_id':who,
      'reviewer_type':kind,'reviewed_at':now(),'source_assertion':r['label']['status'],'decision':decision,
      'reason':'Synthetic software test evidence, never a research label.',
      'evidence':[{'path':x['path'],'sha256':x['sha256']} for x in r['modalities'].values()]}


def test_review_is_append_only_automated_not_final_and_conflicts_excluded(tmp_path):
    r,folder=record(tmp_path);write_json(folder/'observation.json',r);original=(folder/'observation.json').read_bytes()
    first=review_for(r,kind='automated');key=append(tmp_path,first);assert append(tmp_path,first)==key
    assert derive_labels(tmp_path)['pending']==1
    append(tmp_path,review_for(r));assert derive_labels(tmp_path)['label_counts']=={'0':1}
    append(tmp_path,review_for(r,who='second-software-fixture',decision='phishing'))
    result=derive_labels(tmp_path);assert result['conflicting']==1 and not result['all_reviewed'] and not result['label_counts']
    assert (folder/'observation.json').read_bytes()==original


def test_review_rejects_evidence_mismatch_and_incomplete_label(tmp_path):
    r,folder=record(tmp_path);write_json(folder/'observation.json',r)
    review=review_for(r);review['evidence'][0]['sha256']='0'*64
    with pytest.raises(ValueError,match='evidence'):append(tmp_path,review)
    r['status']='partial';write_json(folder/'observation.json',r)
    with pytest.raises(ValueError,match='incomplete'):append(tmp_path,review_for(r))


def test_v2_policy_evidence_is_verified(tmp_path):
    r,folder=record(tmp_path);r['schema_version']='observation-v2';r['readiness_pass']=True
    body=folder/'robots.txt';body.write_text('User-agent: *\nAllow: /\n')
    write_json(folder/'robots.json',{'allowed':True,'hops':[{'body':artifact(tmp_path,body,now())}]})
    write_json(folder/'readiness.json',{'passed':True})
    r['capture_evidence']={name:artifact(tmp_path,folder/(name+'.json'),now()) for name in ('robots','readiness')}
    r['ended_at']=now();schema=json.loads((Path(__file__).parents[1]/'schemas/observation_v2.schema.json').read_text())
    validate_record(r,tmp_path,schema)
    body.write_text('altered rules')
    with pytest.raises(ValueError,match='checksum'):validate_record(r,tmp_path,schema)
