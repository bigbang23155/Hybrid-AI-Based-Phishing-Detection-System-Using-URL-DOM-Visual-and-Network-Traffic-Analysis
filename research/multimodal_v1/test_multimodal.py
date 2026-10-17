"""Synthetic offline software checks; never inference on the sealed test set."""
from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image

from research.urlscan_v1.collector import capture
from research.urlscan_v1.client import Response
from research.multimodal_v1 import network_http as http
from research.multimodal_v1 import forensics
from research.multimodal_v1.adapters import from_checkpoint
from research.multimodal_v1.contract import (MODALITIES, assemble, encoded, feature_set,
    freshness, fusion_view, modality, sha, unavailable_features)
from research.multimodal_v1.pipeline import ROOT, build

TIME = '2026-10-17T00:00:00Z'
AS_OF = '2026-10-17T01:00:00+00:00'
UUID = '00000000-0000-4000-8000-000000000001'
CANDIDATE = {'review_id': 'example-com-smoke', 'url': 'https://example.com/', 'scope': 'smoke_test', 'scan_uuid': UUID}


def transaction(url='https://example.com/', method='GET', kind='Document', status=200,
                mime='text/html', encoded_bytes=10, decoded_bytes=20):
    # Synthetic values follow nested provider shape, not a live capture.
    return {'request': {'request': {'url': url, 'method': method}, 'type': kind},
            'response': {'response': {'status': status, 'mimeType': mime},
                         'encodedDataLength': encoded_bytes, 'dataLength': decoded_bytes}}


def result():
    return {'task': {'uuid': UUID, 'url': CANDIDATE['url'], 'time': TIME, 'visibility': 'public'},
            'page': {'url': CANDIDATE['url'], 'status': '200'},
            'data': {'requests': [transaction(), transaction('http://cdn.example.net/a.js', 'POST', 'Fetch', 404, 'application/javascript', 0, 0)],
                     'cookies': [{'secure': True, 'httpOnly': False}, {'secure': False, 'httpOnly': True}]}}


def png():
    stream = io.BytesIO()
    Image.new('RGB', (32, 24), 'white').save(stream, format='PNG')
    return stream.getvalue()


class FakeClient:
    def result(self, uuid):
        return Response(200, {}, encoded(result()))
    def dom(self, uuid):
        return Response(200, {}, b'<html><body><script>eval(atob("YWJj"));</script></body></html>')
    def screenshot(self, uuid):
        return Response(200, {}, png())


class HTTPTests(unittest.TestCase):
    def test_hand_calculated_values(self):
        out = http.extract(result())
        self.assertEqual(tuple(out['values']), http.NAMES)
        self.assertEqual(out['missing_reasons'], {})
        expected = {'request_record_count': 2, 'http_request_count': 2, 'unique_http_host_count': 2,
                    'https_request_ratio': .5, 'cross_host_request_ratio': .5, 'post_request_ratio': .5,
                    'xhr_fetch_request_ratio': .5, 'response_3xx_ratio': 0., 'response_4xx_ratio': .5,
                    'response_5xx_ratio': 0., 'unique_mime_count': 2, 'javascript_response_ratio': .5,
                    'encoded_bytes_total': 10, 'decoded_bytes_total': 20, 'cookie_count': 2,
                    'secure_cookie_ratio': .5, 'httponly_cookie_ratio': .5, 'main_status': 200,
                    'main_uses_https': 1, 'main_host_changed': 0}
        self.assertEqual(out['values'], expected)

    def test_missing_does_not_become_zero(self):
        r = result(); del r['data']['requests'][1]['response']['encodedDataLength']
        out = http.extract(r)
        self.assertIsNone(out['values']['encoded_bytes_total'])
        self.assertEqual(out['support']['encoded_bytes_total'], {'observed': 1, 'expected': 2})
        self.assertEqual(out['values']['decoded_bytes_total'], 20)
        self.assertEqual(out['values']['response_5xx_ratio'], 0)

    def test_empty_list_versus_absent_list(self):
        r = result(); r['data']['requests'] = []; r['data']['cookies'] = []
        out = http.extract(r)
        for key in ('request_record_count','http_request_count','unique_mime_count','encoded_bytes_total','cookie_count'):
            self.assertEqual(out['values'][key], 0)
        for key in ('https_request_ratio','post_request_ratio','secure_cookie_ratio'):
            self.assertIsNone(out['values'][key])
            self.assertEqual(out['missing_reasons'][key], 'empty_denominator')
        del r['data']['requests']
        self.assertIsNone(http.extract(r)['values']['request_record_count'])

    def test_bad_schema_is_not_flattened_or_guessed(self):
        for request in (None, 1, {}, {'request': {'url': 'https://example.com/'}}):
            with self.subTest(request=request):
                r=result(); r['data']['requests']=[request]
                out=http.extract(r)
                self.assertEqual(out['values']['request_record_count'], 1)
                self.assertIsNone(out['values']['http_request_count'])
                self.assertIsNone(out['values']['response_4xx_ratio'])

    def test_non_http_excluded_without_diluting_https(self):
        r=result(); r['data']['requests']=[transaction(), transaction('data:text/plain,hi')]
        out=http.extract(r)['values']
        self.assertEqual(out['http_request_count'], 1)
        self.assertEqual(out['https_request_ratio'], 1)

    def test_failed_response_not_assumed_success(self):
        r=result(); r['data']['requests'][1]['response']={'failed':True}
        out=http.extract(r)['values']
        self.assertIsNone(out['response_4xx_ratio'])
        self.assertEqual(out['http_request_count'], 2)

    def test_invalid_numeric_fields(self):
        for bad in (True, -1, 1.5, '12', float('nan'), float('inf')):
            with self.subTest(bad=bad):
                r=result(); r['data']['requests'][0]['response']['dataLength']=bad
                self.assertIsNone(http.extract(r)['values']['decoded_bytes_total'])
        for bad in (True, 0, 999, 'unknown', '200.0'):
            r=result(); r['page']['status']=bad
            self.assertIsNone(http.extract(r)['values']['main_status'])

    def test_cookie_missing_flag_and_invalid_rows(self):
        r=result(); del r['data']['cookies'][0]['secure']
        self.assertIsNone(http.extract(r)['values']['secure_cookie_ratio'])
        self.assertEqual(http.extract(r)['values']['httponly_cookie_ratio'], .5)
        r['data']['cookies']=[None]
        self.assertIsNone(http.extract(r)['values']['cookie_count'])

    def test_allowlist_no_label_or_secret_leakage(self):
        base=http.extract(result()); r=result()
        r.update(verdicts={'urlscan':{'score':100}}, labels=['phishing'], meta={'secret':'CANARY'})
        r['task']['tags']=['phishing']
        r['data']['requests'][0]['request']['request']['postData']='CANARY'
        r['data']['cookies'][0]['value']='CANARY'
        self.assertEqual(http.extract(r), base)
        self.assertNotIn(b'CANARY', encoded(http.extract(r)))

    def test_limits_and_malformed_root(self):
        self.assertTrue(all(v is None for v in http.extract([])['values'].values()))
        with patch.object(http, 'MAX_REQUESTS', 1):
            self.assertTrue(all(v is None for v in http.extract(result())['values'].values()))

    def test_order_and_metadata_change_invariance(self):
        r=result(); expected=http.extract(r)
        r['data']['requests'].reverse()
        self.assertEqual(http.extract(r), expected)
        self.assertEqual(sha(encoded(http.registry())), http.REGISTRY_SHA256)


class ContractTests(unittest.TestCase):
    def test_age_boundary_unknown_future_and_timezone(self):
        for capture, status in ((TIME,'fresh'), ('2026-10-16T23:59:59Z','stale'),
                                (None,'unknown'), ('2026-10-17T02:00:00Z','future'),
                                ('2026-10-17T00:00:00','unknown')):
            with self.subTest(capture=capture):
                self.assertEqual(freshness(capture,as_of=AS_OF,max_age_seconds=3600)['status'],status)
        for bad in (-1, float('nan'), True):
            with self.assertRaises(ValueError): freshness(TIME,as_of=AS_OF,max_age_seconds=bad)

    def test_invalid_values_and_missing_reasons_rejected(self):
        for values in ({'x':None}, {'x':float('nan')}, {'x':True}):
            with self.assertRaises(ValueError): feature_set('v1',values)
        with self.assertRaises(ValueError): feature_set('v1',{'x':0}, reasons={'x':'missing'})

    def make(self, name='network_http', stale=False):
        f=feature_set('v1',{'zero':0,'missing':None},reasons={'missing':'not_observed'})
        t=freshness(TIME,as_of=AS_OF,max_age_seconds=0 if stale else 3600,applicable=name!='url')
        return modality(name,f,acquisition='available',extraction='partial',temporal=t,provenance={})

    def test_stale_values_retained_but_masked(self):
        m=self.make(stale=True)
        self.assertEqual(m['features']['values']['zero'],0)
        self.assertEqual(m['observed_mask']['zero'],1)
        self.assertEqual(m['usable_mask']['zero'],0)

    def test_serialization_preserves_feature_order(self):
        rows={n:self.make(n) for n in MODALITIES}
        r=assemble('synthetic',rows,scope='smoke_test')
        view=fusion_view(r)
        self.assertEqual(view,fusion_view(json.loads(encoded(r))))
        self.assertEqual(view['values'][:2],[0,None])
        self.assertEqual(view['feature_mask'][:2],[1,0])
        self.assertIsNone(view['attention_weights'])

    def test_missing_fourth_modality_and_sealed_scope_rejected(self):
        with self.assertRaises(ValueError): assemble('x',{},scope='smoke_test')
        with self.assertRaises(ValueError): assemble('x',{},scope='test')

    def test_forged_mask_or_time_not_trusted(self):
        rows={n:self.make(n) for n in MODALITIES}
        rows['dom']['usable_mask']['missing']=1
        self.assertEqual(fusion_view(assemble('x',rows,scope='smoke_test'))['feature_mask'][3],0)
        rows['dom']['temporal']['status']='stale'
        with self.assertRaises(ValueError): assemble('x',rows,scope='smoke_test')

    def test_absent_artifact_cannot_have_zero_features(self):
        m=self.make()
        with self.assertRaises(ValueError):
            modality('network_http',m['features'],acquisition='not_found',extraction='unavailable',
                     temporal=m['temporal'],provenance={})

    def test_all_missing_explicit_abstention_input(self):
        rows={}
        for n in MODALITIES:
            rows[n]=modality(n,unavailable_features('v1',['x'],'not_supplied'),
                acquisition='not_supplied',extraction='unavailable',
                temporal=freshness(None,as_of=AS_OF,max_age_seconds=3600,applicable=n!='url'),provenance={})
        out=fusion_view(assemble('x',rows,scope='smoke_test'))
        self.assertTrue(out['all_missing']); self.assertEqual(out['values'],[None]*4)


class ForensicsTests(unittest.TestCase):
    def test_metrics_and_offsets_are_byte_based(self):
        data=b'\xff%41\\x41\\u0041&#65; eval(atob("YQ=="));'
        out=forensics.inspect(data,run_yara=False)
        for name in ('percent_escape_count','js_hex_escape_count','js_unicode_escape_count',
                     'html_numeric_entity_count','eval_call_count','atob_call_count'):
            self.assertEqual(out['features']['values'][name],1)
        self.assertEqual(out['signals']['percent_escape_count']['byte_spans'][0]['offset'],1)
        self.assertIsNone(out['label']); self.assertFalse(out['execution_performed'])

    def test_entropy_and_base64_run_are_not_verdicts(self):
        out=forensics.inspect(b'A'*100,run_yara=False)
        self.assertEqual(out['features']['values']['byte_entropy'],0)
        self.assertEqual(out['features']['values']['base64_like_byte_ratio'],1)
        self.assertFalse(out['label_assignment'])

    def test_actual_yara_positive_and_negative_controls(self):
        out=forensics.inspect(b'eval(atob("YQ=="));')['yara']
        if out['status']=='dependency_missing' and not os.environ.get('REQUIRE_YARA'):
            self.skipTest('optional YARA not installed')
        self.assertEqual(out['status'],'ok')
        self.assertIn('CF_Decode_And_Eval_v1',[m['rule_id'] for m in out['matches']])
        self.assertEqual(forensics.inspect(b'<html>Hello</html>')['yara']['matches'],[])

    def test_all_rules_compile_and_match(self):
        examples={'CF_Packed_JavaScript_v1':b'eval(function(p,a,c,k,e,d){})',
                  'CF_Encoded_HTML_v1':b'data:text/html;base64,PGh0bWw+',
                  'CF_Decode_And_Write_v1':b'document.write(atob("YQ=="))'}
        for name,data in examples.items():
            out=forensics.inspect(data)['yara']
            if out['status']=='dependency_missing' and not os.environ.get('REQUIRE_YARA'):
                self.skipTest('optional YARA not installed')
            self.assertEqual(out['status'],'ok')
            self.assertIn(name,[m['rule_id'] for m in out['matches']])

    def test_missing_engine_not_no_hits(self):
        with patch.dict(sys.modules,{'yara':None}):
            out=forensics.inspect(b'hello')['yara']
            self.assertEqual(out['status'],'dependency_missing'); self.assertIsNone(out['matches'])

    def test_timeout_and_compile_failure_not_no_hits(self):
        import yara
        for error, expected in ((yara.TimeoutError('test'),'timeout'), (yara.Error('test'),'engine_error')):
            with patch.object(yara,'compile',side_effect=error):
                out=forensics.inspect(b'hello')['yara']
                self.assertEqual(out['status'],expected); self.assertIsNone(out['matches'])

    def test_empty_and_oversized_are_unavailable(self):
        for data in (b'',b'x'*(forensics.MAX_BYTES+1)):
            out=forensics.inspect(data)
            self.assertTrue(all(v is None for v in out['features']['values'].values()))
            self.assertEqual(out['yara']['status'],'input_unavailable')

    def test_spans_bounded_and_no_matched_content(self):
        out=forensics.inspect(b'%41 '*100)
        signal=out['signals']['percent_escape_count']
        self.assertEqual(signal['count'],100); self.assertEqual(len(signal['byte_spans']),32)
        self.assertTrue(signal['spans_truncated'])
        self.assertNotIn(b'%41',encoded(out))


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.run=self.root/'input'; self.folder=self.run/'private'/'synthetic'
        self.folder.mkdir(parents=True)
        self.record=capture(FakeClient(),CANDIDATE,self.folder)
        self.checkpoint=self.folder/'record.json'
        self.save()
    def tearDown(self): self.temp.cleanup()
    def save(self): self.checkpoint.write_bytes(encoded(self.record))
    def extract(self,age=3600):
        return from_checkpoint(self.checkpoint,as_of=AS_OF,max_age_seconds=age)

    def test_collector_to_four_modalities_without_network(self):
        with patch.object(socket,'socket',side_effect=AssertionError('network_forbidden')):
            row=self.extract()
        self.assertEqual(set(row['modalities']),set(MODALITIES))
        for m in row['modalities'].values():
            self.assertEqual(m['acquisition_status'],'available')
            self.assertEqual(m['extraction_status'],'ok')
        self.assertFalse(row['eligible_for_training']); self.assertIsNone(row['label'])
        self.assertEqual(row['modalities']['dom']['features']['values']['password_input_count'],0)
        self.assertEqual(row['sidecars']['content_forensics']['yara']['status'],'ok')

    def test_stale_not_download_failure(self):
        m=self.extract(age=0)['modalities']['visual']
        self.assertEqual(m['acquisition_status'],'available')
        self.assertEqual(m['temporal']['status'],'stale')
        self.assertEqual(m['modality_available_mask'],1); self.assertEqual(m['modality_usable_mask'],0)

    def test_distinct_screenshot_absence_states(self):
        del self.record['artifacts']['screenshot']
        for error, expected in ((None,'not_supplied'), ({'code':'http_error','http_status':404},'not_found'),
                                ({'code':'timeout'},'download_failed'), ({'code':'invalid_png'},'invalid_artifact')):
            with self.subTest(expected=expected):
                self.record['errors']={} if error is None else {'screenshot':error}; self.save()
                m=self.extract()['modalities']['visual']
                self.assertEqual(m['acquisition_status'],expected)
                self.assertTrue(all(v is None for v in m['features']['values'].values()))

    def test_search_no_hit_does_not_make_negative_label(self):
        self.record['artifacts']={}
        self.record['errors']={'capture':{'code':'no_exact_public_scan_in_search_window'}}
        self.save(); row=self.extract()
        self.assertEqual(row['modalities']['network_http']['acquisition_status'],'not_found')
        self.assertIsNone(row['label']); self.assertFalse(row['eligible_for_training'])

    def test_hash_tamper_rejects_artifact(self):
        (self.folder/'dom.html.txt').write_bytes(b'<html>changed</html>')
        row=self.extract()
        self.assertEqual(row['modalities']['dom']['acquisition_status'],'integrity_failed')
        self.assertNotIn('content_forensics',row['sidecars'])

    def test_result_identity_mismatch_blocks_paired_modalities(self):
        r=result(); r['task']['uuid']='different'
        data=encoded(r); (self.folder/'result.json').write_bytes(data)
        self.record['artifacts']['result'].update(sha256=sha(data),bytes=len(data)); self.save()
        for name in ('dom','visual','network_http'):
            self.assertEqual(self.extract()['modalities'][name]['acquisition_status'],'integrity_failed')

    def test_path_escape_and_symlink_rejected(self):
        target=self.root/'outside'; target.write_bytes(b'CANARY')
        self.record['artifacts']['dom'].update(file=str(target),sha256=sha(b'CANARY'),bytes=6); self.save()
        self.assertEqual(self.extract()['modalities']['dom']['acquisition_status'],'integrity_failed')
        link=self.folder/'link'; link.symlink_to(target)
        self.record['artifacts']['dom']['file']='link'; self.save()
        self.assertEqual(self.extract()['modalities']['dom']['acquisition_status'],'integrity_failed')

    def test_malformed_html_does_not_suppress_forensic_audit(self):
        data=b'\xffeval(atob("YQ=="))'
        (self.folder/'dom.html.txt').write_bytes(data)
        self.record['artifacts']['dom'].update(sha256=sha(data),bytes=len(data)); self.save()
        row=self.extract()
        self.assertEqual(row['modalities']['dom']['extraction_status'],'failed')
        self.assertEqual(row['sidecars']['content_forensics']['features']['values']['eval_call_count'],1)

    def test_batch_repeatable_and_private(self):
        with patch.object(socket,'socket',side_effect=AssertionError('network_forbidden')):
            for name in ('a','b'):
                summary=build(self.run,self.root/name,as_of=AS_OF,max_age_seconds=3600)
                self.assertEqual(summary['records'],1); self.assertEqual(summary['network_requests'],0)
        for name in ('features.jsonl','fusion_inputs.jsonl'):
            self.assertEqual((self.root/'a/private'/name).read_bytes(),(self.root/'b/private'/name).read_bytes())
        self.assertNotIn(b'example.com',(self.root/'a/public/summary.json').read_bytes())
        self.assertTrue(json.loads((self.root/'a/run.json').read_bytes())['complete'])
        with self.assertRaises(FileExistsError): build(self.run,self.root/'a',as_of=AS_OF,max_age_seconds=3600)

    def test_frozen_output_and_unknown_scope_rejected(self):
        with self.assertRaises(ValueError): build(self.run,ROOT/'results/new-test',as_of=AS_OF,max_age_seconds=3600)
        self.record['scope']='test'; self.save()
        with self.assertRaises(ValueError): self.extract()

    def test_all_75_frozen_files_unchanged(self):
        lock=json.loads((ROOT/'config/assignment03_final_evaluation_v1.json').read_text())
        self.assertEqual(len(lock['file_sha256']),75)
        for name,expected in lock['file_sha256'].items():
            self.assertEqual(sha((ROOT/name).read_bytes()),expected,name)


if __name__ == '__main__':
    unittest.main()
