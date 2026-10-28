"""Offline behavioral tests: no key, live requests, fitting or test inference."""
import copy
import csv
import gzip
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import zlib

from research.urlscan_v1.client import Client, CaptureError, Response, json_object, decode_body
from research.urlscan_v1.collector import (ROOT, QUEUE, capture, collect, encoded,
    normalized_url, rows, sha, validate_candidates, validate_png)
from research.urlscan_v1.ai_review import HEADERS, import_ai
from research.robustness_v1.review_intake import import_forms

UUID = '11111111-1111-4111-8111-111111111111'
CANDIDATE = {'review_id': 'example-com-smoke', 'url': 'https://example.com/', 'scope': 'smoke_test'}
TASK = {'uuid': UUID, 'url': CANDIDATE['url'], 'time': '2026-10-16T00:00:00Z', 'visibility': 'public'}


def png():
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind+data) & 0xffffffff)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(b'\x00\x00\x00\x00')) + chunk(b'IEND', b'')


def response(obj, status=200, headers=None):
    return Response(status, headers or {}, encoded(obj))


def successful():
    return [response({'results': [{'_id': UUID, 'task': TASK}]}),
        response({'task': TASK, 'page': {'url': CANDIDATE['url'], 'status': '200'},
                  'data': {'requests': [{'request': {'url': 'private-test-query'}}]}}),
        Response(200, {}, b'<html><body>Example domain</body></html>'), Response(200, {}, png())]


class Fake:
    def __init__(self, responses, budget=30):
        self.responses, self.urls, self.sleeps, self.now = list(responses), [], [], 0
        self.client = Client('secret-test-value', interval=0, request_limit=budget,
            send=self.send, sleep=self.sleep, clock=lambda: self.now)
    def sleep(self, seconds):
        self.sleeps.append(seconds); self.now += seconds
    def send(self, url, headers, timeout, max_bytes):
        self.urls.append(url)
        assert headers['api-key'] == 'secret-test-value'
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class ClientTests(unittest.TestCase):
    def test_compressed_dom_with_and_without_encoding_header(self):
        raw = b'<html><body>Example domain</body></html>'
        for headers in ({'Content-Encoding': 'gzip'}, {}):
            decoded, info = decode_body(gzip.compress(raw), headers, 1000)
            self.assertEqual(decoded, raw); self.assertEqual(info['decoded_from'], 'gzip')
        decoded, _ = decode_body(zlib.compress(raw), {'Content-Encoding': 'deflate'}, 1000)
        self.assertEqual(decoded, raw)

    def test_compression_expansion_and_truncation_rejected(self):
        with self.assertRaisesRegex(CaptureError, 'too_large'):
            decode_body(gzip.compress(b'x'*1000), {}, 100)
        with self.assertRaisesRegex(CaptureError, 'invalid_compressed'):
            decode_body(gzip.compress(b'hello')[:-3], {}, 100)

    def test_search_escapes_query(self):
        f = Fake([response({'results': []})]); f.client.search('https://example.com/?x=a&y="z"')
        q = parse_qs(urlsplit(f.urls[0]).query)['q'][0]
        self.assertIn(r'\&', q); self.assertIn(r'\"z\"', q)
        self.assertNotIn('secret-test-value', f.urls[0])

    def test_foreign_redirect_never_receives_key(self):
        for destination in ('https://evil.example/a', 'http://urlscan.io/dom/'+UUID+'/', 'https://urlscan.io@evil.example/'):
            f = Fake([Response(302, {'Location': destination}, b'')])
            with self.assertRaisesRegex(CaptureError, 'rejected'):
                f.client.dom(UUID)
            self.assertEqual(len(f.urls), 1)

    def test_same_origin_redirect_and_post_path_guard(self):
        f = Fake([Response(302, {'Location': '/dom/'+UUID+'/'}, b''), Response(200, {}, b'HTML')])
        self.assertEqual(f.client.dom(UUID).body, b'HTML')
        with self.assertRaises(CaptureError):
            f.client.get('/api/v1/scan/')

    def test_retry_after_and_server_error(self):
        f = Fake([Response(429, {'Retry-After': '5'}, b''), response({'ok': True})])
        self.assertTrue(json_object(f.client.get('/api/v1/search/'))['ok'])
        self.assertIn(5, f.sleeps)
        f = Fake([Response(503, {}, b''), response({})]); f.client.get('/api/v1/search/')
        self.assertEqual(len(f.urls), 2)

    def test_rate_limit_reset_header(self):
        f = Fake([Response(200, {'X-Rate-Limit-Remaining': '0', 'X-Rate-Limit-Reset-After': '7'}, b'{}'), response({})])
        f.client.get('/api/v1/search/'); f.client.get('/api/v1/search/')
        self.assertIn(7, f.sleeps)

    def test_long_delay_defers(self):
        for headers in ({'Retry-After': '3600'}, {'X-Rate-Limit-Reset-After': '3600'}):
            f = Fake([Response(429, headers, b'')])
            with self.assertRaisesRegex(CaptureError, 'retry_deferred'):
                f.client.get('/api/v1/search/')
            self.assertEqual(f.sleeps, [])

    def test_auth_fails_without_echo(self):
        for status in (401, 403):
            f = Fake([Response(status, {}, b'secret-test-value')])
            with self.assertRaisesRegex(CaptureError, 'authentication_or_access_denied') as ctx:
                f.client.result(UUID)
            self.assertNotIn('secret-test-value', str(ctx.exception)); self.assertEqual(len(f.urls), 1)

    def test_404_result_retries_but_attachment_does_not(self):
        f = Fake([Response(404, {}, b''), response({})]); f.client.result(UUID)
        self.assertEqual(len(f.urls), 2)
        f = Fake([Response(404, {}, b'')])
        with self.assertRaisesRegex(CaptureError, 'attachment_missing'):
            f.client.dom(UUID)
        self.assertEqual(len(f.urls), 1)

    def test_410_budget_and_invalid_uuid(self):
        f = Fake([Response(410, {}, b'')], budget=1)
        with self.assertRaisesRegex(CaptureError, 'scan_deleted'): f.client.result(UUID)
        with self.assertRaisesRegex(CaptureError, 'request_budget_exhausted'): f.client.result(UUID)
        with self.assertRaisesRegex(CaptureError, 'invalid_scan_uuid'): f.client.result('../../x')

    def test_malformed_json(self):
        for body in (b'<html>error</html>', b'[]'):
            with self.assertRaises(CaptureError): json_object(Response(200, {}, body))


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.folder = Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()

    def test_complete_and_public_redaction(self):
        f = Fake(successful())
        result = collect([CANDIDATE], self.folder/'run', f.client, smoke=True)
        self.assertEqual(result['completeness_counts'], {'COMPLETE': 1})
        self.assertEqual(result['training_eligible_added'], 0)
        public = ''.join(p.read_text() for p in (self.folder/'run/public').iterdir())
        for value in ('https://', UUID, 'private-test-query', 'secret-test-value', 'Example domain'):
            self.assertNotIn(value, public)

    def test_diagnostic_host_hit_cannot_replace_target(self):
        other = dict(TASK, url='https://example.com/other')
        f = Fake([response({'results': []}), response({'results': []}),
                  response({'results': [{'_id': UUID, 'task': other}], 'has_more': True})])
        r = capture(f.client, CANDIDATE, self.folder, search_diagnostics=True)
        self.assertEqual(r['completeness'], 'NONE')
        self.assertEqual(r['search_diagnostics'][-1]['rejected'], {'different_submitted_url': 1})
        self.assertTrue(r['search_diagnostics'][-1]['has_more'])
        self.assertEqual(f.client.requests, 3)

    def test_diagnostic_recovers_exact_task_and_validates_result_again(self):
        for mismatch in (False, True):
            data = successful()
            if mismatch:
                data[1] = response({'task': dict(TASK, url='https://example.com/other'),
                                    'page': {'url': CANDIDATE['url']}})
            f = Fake([response({'results': []})] + data)
            r = capture(f.client, CANDIDATE, self.folder, search_diagnostics=True)
            self.assertEqual(r['selected_search_strategy'], 'final_url_exact')
            self.assertEqual(r['completeness'], 'NONE' if mismatch else 'COMPLETE')
            if mismatch:
                self.assertEqual(r['errors']['capture']['code'], 'scan_identity_mismatch')

    def test_diagnostic_budget_stops_and_public_report_has_no_urls(self):
        f = Fake([response({'results': []})], budget=1)
        result = collect([CANDIDATE], self.folder/'run', f.client,
                         smoke=True, search_diagnostics=True)
        self.assertEqual(result['run_status'], 'STOPPED')
        self.assertEqual(f.client.requests, 1)
        self.assertEqual(result['search_strategy_counts'], {'submitted_exact': 1})
        self.assertNotIn('https://', ''.join(p.read_text() for p in (self.folder/'run/public').iterdir()))

    def test_diagnostic_normalized_variant_and_query_injection_guard(self):
        candidate = dict(CANDIDATE, url='https://EXAMPLE.com:443')
        f = Fake([response({'results': []})] + successful())
        r = capture(f.client, candidate, self.folder, search_diagnostics=True)
        self.assertEqual(r['selected_search_strategy'], 'normalized_exact')
        self.assertEqual(r['completeness'], 'COMPLETE')
        q = parse_qs(urlsplit(f.urls[1]).query)['q'][0]
        self.assertIn('AND task.visibility:public', q)
        with self.assertRaises(ValueError):
            f.client.search('x', field='task.url OR *')

    def test_partial_missing_attachments(self):
        data = successful(); data[2:] = [Response(404, {}, b''), Response(404, {}, b'')]
        r = capture(Fake(data).client, CANDIDATE, self.folder)
        self.assertEqual(r['completeness'], 'PARTIAL'); self.assertEqual(len(r['errors']), 2)

    def test_same_domain_different_path_does_not_match(self):
        task = dict(TASK, url='https://example.com/login')
        r = capture(Fake([response({'results': [{'_id': UUID, 'task': task}]})]).client, CANDIDATE, self.folder)
        self.assertEqual(r['completeness'], 'NONE')
        self.assertEqual(r['errors']['capture']['code'], 'no_exact_public_scan_in_search_window')

    def test_result_identity_mismatch(self):
        data = successful(); data[1] = response({'task': dict(TASK, uuid='bad'), 'page': {'url': CANDIDATE['url']}})
        r = capture(Fake(data).client, CANDIDATE, self.folder)
        self.assertEqual(r['errors']['capture']['code'], 'scan_identity_mismatch'); self.assertEqual(r['artifacts'], {})

    def test_no_network_metadata_not_complete(self):
        data = successful(); obj = json.loads(data[1].body); obj.pop('data'); data[1] = response(obj)
        r = capture(Fake(data).client, CANDIDATE, self.folder)
        self.assertEqual(r['completeness'], 'PARTIAL'); self.assertIn('http_metadata_missing_or_empty', r['quality_flags'])

    def test_temporal_separation(self):
        r = capture(Fake(successful()).client, dict(CANDIDATE, publisher_date='2025-01-01'), self.folder)
        self.assertIsNone(r['capture_time_delta_seconds']); self.assertIsNone(r['original_captured_at'])
        self.assertEqual(r['historical_equivalence'], 'unverified'); self.assertFalse(r['eligible_for_training'])

    def test_corrupt_png_and_dom(self):
        with self.assertRaises(CaptureError): validate_png(png()[:-2])
        data = successful(); data[2] = Response(200, {}, b'plain error'); data[3] = Response(200, {}, b'not png')
        r = capture(Fake(data).client, CANDIDATE, self.folder)
        self.assertEqual(r['completeness'], 'PARTIAL'); self.assertEqual(len(r['errors']), 2)

    def test_resume_no_network_and_tamper_rejected(self):
        out = self.folder/'run'; collect([CANDIDATE], out, Fake(successful()).client, smoke=True)
        empty = Fake([]); result = collect([CANDIDATE], out, empty.client, smoke=True, resume=True)
        self.assertEqual(result['requests_this_invocation'], 0)
        next((out/'private').glob('*/dom.html.txt')).write_text('changed')
        with self.assertRaisesRegex(ValueError, 'integrity'):
            collect([CANDIDATE], out, empty.client, smoke=True, resume=True)

    def test_scope_and_membership_guard(self):
        q = rows(QUEUE)[0]
        c = dict(q, url='https://example.com/')
        validate_candidates([c])
        for change in ({'scope': 'test'}, {'review_id': 'unknown'}, {'html_sha256': '0'*64}):
            with self.assertRaises(ValueError): validate_candidates([dict(c, **change)])
        with self.assertRaises(ValueError): validate_candidates([c, c])

    def test_frozen_files_byte_identical(self):
        lock = json.loads((ROOT/'config/assignment03_final_evaluation_v1.json').read_text())
        self.assertEqual(len(lock['file_sha256']), 75)
        for relative, expected in lock['file_sha256'].items():
            self.assertEqual(sha((ROOT/relative).read_bytes()), expected, relative)

    def test_url_normalization_conservative(self):
        self.assertEqual(normalized_url('https://EXAMPLE.com:443'), 'https://example.com/')
        self.assertNotEqual(normalized_url('https://example.com/#a'), normalized_url('https://example.com/#b'))
        self.assertNotEqual(normalized_url('https://example.com/A'), normalized_url('https://example.com/a'))


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.folder = Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()

    def test_ai_annotations_are_never_human_votes(self):
        q = rows(QUEUE)[0]; wb = self.folder/'input.xlsx'; wb.write_bytes(b'test-workbook')
        record = dict(zip(HEADERS, ['1', q['review_id'], 'uncertain', 'low', 'insufficient evidence',
            'static content', 'need capture time', 'example.com', 'Example',
            'snapshots/'+q['review_id']+'.html.txt', '2025-01-01', 'en', q['html_sha256'], '2026-10-17T00:00:00Z']))
        with patch('research.urlscan_v1.ai_review.read_ai_sheet', return_value=[record]):
            result = import_ai(wb, self.folder/'out')
        self.assertEqual(result['human_reviews_added'], 0)
        annotation = rows(self.folder/'out/private/ai_annotations.jsonl')[0]
        self.assertEqual(annotation['reviewer_type'], 'ai'); self.assertNotIn('reviews', annotation)
        record['快照 SHA-256'] = '0'*64
        with patch('research.urlscan_v1.ai_review.read_ai_sheet', return_value=[record]):
            with self.assertRaisesRegex(ValueError, 'binding'): import_ai(wb, self.folder/'bad')

    def test_human_csv_rejects_known_ai_identity(self):
        packets = self.folder/'packets.jsonl'
        packets.write_text(json.dumps({'review_id': 'r1', 'html_sha256': 'a'*64, 'snapshot_path': 'snapshots/r1.html.txt'})+'\n')
        fields = ['review_id', 'reviewer_id', 'label']
        for name, identity in [('a', 'real-person'), ('b', 'AI_ASSISTANT_NOT_HUMAN')]:
            with (self.folder/(name+'.csv')).open('w') as f:
                writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader()
                writer.writerow({'review_id': 'r1', 'reviewer_id': identity, 'label': 'uncertain'})
        with self.assertRaisesRegex(ValueError, 'AI annotations'):
            import_forms(packets, self.folder/'a.csv', self.folder/'b.csv', self.folder/'out')


if __name__ == '__main__':
    unittest.main()
