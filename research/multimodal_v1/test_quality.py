"""Coverage, alignment and encrypted public-control integration regressions."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from research.multimodal_v1.test_multimodal import (
    AS_OF, CANDIDATE, FakeClient, UUID, png, result)
from research.multimodal_v1.adapters import from_checkpoint
from research.multimodal_v1.contract import encoded, freshness, sha
from research.multimodal_v1.pipeline import build
from research.multimodal_v1.quality import Coverage, alignment
from research.multimodal_v1.smoke import run
from research.urlscan_v1.collector import capture
from research.urlscan_v1.client import Response
from research.urlscan_v1.secure_store import keygen, unseal
from research.urlscan_v1.test_urlscan import Fake, response
import io
import zipfile


class QualityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root/'input/private/synthetic'; self.folder.mkdir(parents=True)
        self.record = capture(FakeClient(), CANDIDATE, self.folder)
        self.path = self.folder/'record.json'
        self.path.write_bytes(encoded(self.record))
        self.row = from_checkpoint(self.path, as_of=AS_OF, max_age_seconds=3600)

    def test_complete_zero_is_observed_and_public_output_is_sanitized(self):
        self.row['modalities']['url']['quality_flags'].append('CANARY-secret')
        c = Coverage(); c.add(self.row); report = c.report()
        self.assertEqual(report['column_count'], 64)
        self.assertEqual(report['alignment_counts'], {'aligned': 1})
        z = report['features']['network_http__response_5xx_ratio']
        self.assertEqual((z['observed_zero_records'], z['missing_records'], z['usable_fraction']), (1, 0, 1))
        for private in (b'CANARY', b'example.com', UUID.encode(), b'synthetic'):
            self.assertNotIn(private, encoded(report))

    def test_missing_screenshot_kept_in_denominator(self):
        c = Coverage(); c.add(self.row)
        del self.record['artifacts']['screenshot']
        self.record['candidate_sha256'] = 'a'*64
        self.path.write_bytes(encoded(self.record))
        row = from_checkpoint(self.path, as_of=AS_OF, max_age_seconds=3600)
        # Distinct attempted item; same source artifacts are acceptable for this fixture.
        row['item_id'] = 'second-attempt'
        c.add(row); report = c.report()
        self.assertEqual(report['records'], 2)
        self.assertEqual(report['alignment_counts'], {'aligned': 1, 'incomplete': 1})
        for n, f in report['features'].items():
            if n.startswith('visual__'):
                self.assertEqual(f['observed_fraction'], .5)
                self.assertEqual(f['missing_records'], 1)

    def test_stale_retains_observed_but_not_usable(self):
        row = from_checkpoint(self.path, as_of=AS_OF, max_age_seconds=0)
        c = Coverage(); c.add(row); r = c.report()
        self.assertEqual(r['all_modalities_usable_records'], 0)
        f = r['features']['network_http__http_request_count']
        self.assertEqual((f['observed_fraction'], f['usable_fraction']), (1, 0))

    def test_source_pairing_conflicts(self):
        for field, value, code in (
                ('checkpoint_sha256', 'a'*64, 'checkpoint_mismatch'),
                ('scan_uuid', 'different', 'scan_identity_mismatch'),
                ('submitted_url_sha256', 'a'*64, 'submitted_url_sha256_mismatch'),
                ('final_url_sha256', 'a'*64, 'final_url_sha256_mismatch'),
                ('source_sha256', None, 'missing_source_hash')):
            row = copy.deepcopy(self.row)
            row['modalities']['dom']['provenance'][field] = value
            state, reasons = alignment(row)
            self.assertEqual(state, 'failed'); self.assertIn(code, reasons)
        row = copy.deepcopy(self.row)
        row['modalities']['dom']['temporal'] = freshness('2026-10-17T00:30:00Z', as_of=AS_OF, max_age_seconds=3600)
        self.assertIn('capture_time_mismatch', alignment(row)[1])

    def test_stored_mask_registry_label_and_duplicates_rejected(self):
        c = Coverage(); c.add(self.row)
        with self.assertRaisesRegex(ValueError, 'duplicate'): c.add(self.row)
        for mutation, error in (
                (lambda r: r.update(label='phishing'), 'unlabelled'),
                (lambda r: r['modalities']['url']['usable_mask'].update(url_length=0), 'mask'),
                (lambda r: r['modalities']['url']['features'].update(registry_version='wrong'), 'registry')):
            row = copy.deepcopy(self.row); mutation(row)
            with self.assertRaisesRegex(ValueError, error): Coverage().add(row)

    def test_partial_support_and_unknown_reason_do_not_leak(self):
        row = copy.deepcopy(self.row); m = row['modalities']['network_http']
        n = 'encoded_bytes_total'
        m['features']['values'][n] = None
        m['features']['missing_reasons'][n] = 'CANARY-secret'
        m['features']['support'][n] = {'observed': 1, 'expected': 2}
        m['extraction_status'] = 'partial'; m['observed_mask'][n] = m['usable_mask'][n] = 0
        c = Coverage(); c.add(row); r = c.report()
        f = r['features']['network_http__'+n]
        self.assertEqual(f['missing_reasons'], {'other_reason': 1})
        self.assertEqual((f['support_observed_total'], f['support_expected_total']), (1, 2))
        self.assertNotIn(b'CANARY', encoded(r))

    def test_alignment_failure_leaves_incomplete_batch(self):
        self.row['modalities']['dom']['provenance']['scan_uuid'] = 'wrong'
        with patch('research.multimodal_v1.pipeline.from_checkpoint', return_value=self.row):
            with self.assertRaisesRegex(ValueError, 'alignment'):
                build(self.root/'input', self.root/'output', as_of=AS_OF, max_age_seconds=3600)
        self.assertFalse(json.loads((self.root/'output/run.json').read_bytes())['complete'])


class SmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.private = Path(cls.keys.name)/'private.pem'; cls.public = Path(cls.keys.name)/'public.pem'
        keygen(cls.private, cls.public)

    @classmethod
    def tearDownClass(cls): cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def execute(self, data=None, screenshot=None):
        data = result() if data is None else data
        data['verdicts'] = {'secret': 'CANARY-secret'}
        f = Fake([response({'results': [{'_id': UUID, 'task': data['task']}]}), response(data),
            Response(200, {}, b'<html><body>Example</body></html>'),
            screenshot or Response(200, {}, png())])
        report = run(self.root/'work', self.root/'publish', self.public, f.client, as_of=AS_OF)
        self.assertEqual(f.client.requests, 4)
        self.assertTrue(all('/scan/' not in u for u in f.urls))
        return report

    def test_success_encrypted_archive_roundtrip_and_private_public_boundary(self):
        report = self.execute(); self.assertEqual(report['status'], 'PASS')
        pub = self.root/'publish'
        self.assertEqual({p.name for p in pub.iterdir()},
                         {'evidence.enc', 'encryption_receipt.json', 'readiness.json', 'feature_quality.json'})
        for p in pub.glob('*.json'):
            self.assertNotIn(b'CANARY', p.read_bytes()); self.assertNotIn(UUID.encode(), p.read_bytes())
        raw = unseal((pub/'evidence.enc').read_bytes(), self.private.read_bytes())
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertTrue(any(n.endswith('result.json') for n in archive.namelist()))
            feature_path = next(n for n in archive.namelist() if n.endswith('private/features.jsonl'))
            row = json.loads(archive.read(feature_path))
            self.assertIsNone(row['label']); self.assertFalse(row['eligible_for_training'])

    def test_empty_cookie_denominator_passes_with_explicit_gaps(self):
        data = result(); data['data']['cookies'] = []
        report = self.execute(data)
        self.assertEqual(report['status'], 'PASS_WITH_GAPS')
        self.assertEqual(set(report['unusable_columns']),
                         {'network_http__secure_cookie_ratio', 'network_http__httponly_cookie_ratio'})

    def test_missing_screenshot_fails_but_preserves_ciphertext(self):
        report = self.execute(screenshot=Response(404, {}, b''))
        self.assertEqual(report['status'], 'FAIL')
        self.assertFalse(report['four_modalities_aligned'])
        self.assertTrue((self.root/'publish/evidence.enc').is_file())

    def test_empty_requests_cannot_pass_public_control(self):
        data = result(); data['data']['requests'] = []
        report = self.execute(data)
        self.assertEqual(report['status'], 'FAIL')
        self.assertFalse(report['core_http_fields_usable'])

    def test_invalid_recipient_fails_before_requests(self):
        bad = self.root/'bad.pem'; bad.write_text('invalid')
        f = Fake([])
        with self.assertRaises(ValueError):
            run(self.root/'work', self.root/'publish', bad, f.client)
        self.assertEqual(f.client.requests, 0)
        self.assertFalse((self.root/'work').exists())


if __name__ == '__main__': unittest.main()
