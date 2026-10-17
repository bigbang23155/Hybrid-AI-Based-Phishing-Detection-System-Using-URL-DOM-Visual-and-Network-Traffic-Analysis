"""Privacy, archive integrity, candidate retrieval and packet binding regression tests."""
import io
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography.exceptions import InvalidTag
from PIL import Image, ImageDraw

from research.urlscan_v1.batch_plan import plan
from research.urlscan_v1.collector import encoded, rows, sha
from research.urlscan_v1.encrypted_batch import prepare_candidates, run
from research.urlscan_v1.secure_store import (keygen, seal, unseal, pack, unpack,
    input_encrypt, input_decrypt, b64, seal_directory)
from research.urlscan_v1.similarity import dom_signature, visual_signature, build
from research.urlscan_v1.test_urlscan import CANDIDATE, Fake, successful


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.private = Path(cls.keys.name)/'private.pem'
        cls.public = Path(cls.keys.name)/'public.pem'
        keygen(cls.private, cls.public)
    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()

    def test_envelope_roundtrip_tamper_and_randomness(self):
        data=b'private URL and raw evidence'
        a=seal(data,self.public.read_bytes());b=seal(data,self.public.read_bytes())
        self.assertNotEqual(a,b);self.assertNotIn(data,a)
        self.assertEqual(unseal(a,self.private.read_bytes()),data)
        with self.assertRaises(InvalidTag): unseal(a[:-1]+bytes([a[-1]^1]),self.private.read_bytes())
        with self.assertRaises(ValueError): keygen(self.private,self.public)

    def test_wrong_recipient_rejected(self):
        keygen(self.root/'private.pem',self.root/'public.pem')
        a=seal(b'data',self.public.read_bytes())
        with self.assertRaises(ValueError): unseal(a,(self.root/'private.pem').read_bytes())

    def test_zip_traversal_and_symlink_rejected(self):
        for name in ('../escape','/absolute','x\\..\\escape','C:/escape'):
            buf=io.BytesIO()
            with zipfile.ZipFile(buf,'w') as z:z.writestr(name,b'x')
            with self.assertRaises(ValueError): unpack(buf.getvalue(),self.root/'out')
        folder=self.root/'folder';folder.mkdir();(folder/'link').symlink_to(self.public)
        with self.assertRaises(ValueError):pack(folder)

    def test_archive_restore_preserves_files_and_no_overwrite(self):
        folder=self.root/'folder';folder.mkdir();(folder/'test.txt').write_bytes(b'private')
        archive=self.root/'evidence.enc'
        receipt=seal_directory(folder,archive,self.public)
        self.assertEqual(sha(archive.read_bytes()),receipt['encrypted_archive_sha256'])
        unpack(unseal(archive.read_bytes(),self.private.read_bytes()),self.root/'restore')
        self.assertEqual((self.root/'restore/test.txt').read_bytes(),b'private')
        with self.assertRaises(FileExistsError):seal_directory(folder,archive,self.public)

    def test_input_authenticated_and_integrity_binding(self):
        key=b'1'*32;blob=input_encrypt(b'private candidates',key)
        self.assertEqual(input_decrypt(blob,key),b'private candidates')
        with self.assertRaises(InvalidTag):input_decrypt(blob,b'2'*32)
        with self.assertRaises(InvalidTag):input_decrypt(blob[:-1]+bytes([blob[-1]^1]),key)

    def test_cloud_input_scope_full_pool_hash_and_bounds(self):
        from research.urlscan_v1.collector import QUEUE
        q = rows(QUEUE)[0]
        data = encoded(dict(q, url='https://example.com/')) + b'\n'
        blob = gzip.compress(data,mtime=0)
        config = {'version':1, 'enabled':True, 'compressed_input_sha256':sha(blob),
            'plaintext_input_sha256':sha(data), 'offset':0, 'limit':1, 'request_limit':5}
        self.assertEqual(len(prepare_candidates(config,b64(blob))),1)
        for change in ({'offset':1}, {'limit':21}, {'request_limit':101}, {'plaintext_input_sha256':'0'*64}):
            with self.assertRaises(ValueError):prepare_candidates(dict(config,**change),b64(blob))
        invalid = data + encoded(dict(q, review_id='unknown', url='https://example.com/')) + b'\n'
        blob = gzip.compress(invalid,mtime=0)
        config.update(compressed_input_sha256=sha(blob),plaintext_input_sha256=sha(invalid))
        with self.assertRaises(ValueError):prepare_candidates(config,b64(blob))

    def packet_fixture(self):
        source=self.root/'packets';source.mkdir();(source/'snapshots').mkdir()
        packets=[];annotations=[]
        for n,url in enumerate(['https://one.example/','https://one.example/other','https://two.example/','https://user:pass@blocked.example/']):
            rid=f'r{n}';data=f'<html><body><p>{n}</p></body></html>'.encode()
            (source/f'snapshots/{rid}.html.txt').write_bytes(data)
            p={'review_id':rid,'sample_id':f's{n}','html_sha256':sha(data),'url':url,
               'scope':'historical_development_audit','snapshot_path':f'snapshots/{rid}.html.txt','publisher_date':'2025-01-01'}
            packets.append(p)
            annotations.append(dict(p,reviewer_type='ai',annotation_only=True,eligible_for_training=False,ai_suggested_label='uncertain'))
        for path,data in [(source/'packets_blinded.jsonl',packets),(self.root/'annotations.jsonl',annotations),(self.root/'queue.jsonl',packets)]:
            path.write_bytes(b''.join(encoded(r)+b'\n' for r in data))
        return source/'packets_blinded.jsonl',self.root/'annotations.jsonl',self.root/'queue.jsonl'

    def test_plan_binding_uncertain_retention_and_determinism(self):
        packet,annotation,queue=self.packet_fixture()
        first=plan(packet,annotation,self.root/'out1',queue_path=queue,batch_size=2)
        second=plan(packet,annotation,self.root/'out2',queue_path=queue,batch_size=2)
        self.assertEqual(first,second);self.assertEqual(first['uncertain_blocked'],1)
        self.assertEqual(first['uncertain_candidates'],3)
        out=rows(self.root/'out1/private/uncertain_candidates.jsonl')
        self.assertNotIn('ai_suggested_label',out[0]);self.assertNotIn('captured_at',out[0])
        (packet.parent/'snapshots/r0.html.txt').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'bytes binding'):plan(packet,annotation,self.root/'bad',queue_path=queue)

    def test_plan_rejects_annotation_join_mismatch(self):
        packet,annotation,queue=self.packet_fixture()
        data=rows(annotation);data[0]['sample_id']='wrong'
        annotation.write_bytes(b''.join(encoded(r)+b'\n' for r in data))
        with self.assertRaisesRegex(ValueError,'identity'):plan(packet,annotation,self.root/'out',queue_path=queue)

    def test_dom_same_structure_different_text_is_not_label_evidence(self):
        a=dom_signature(b'<html><body><form><input name="a"></form></body></html>')
        b=dom_signature(b'<html><body><form><input name="b"></form></body></html>')
        self.assertEqual(a['canonical_sha256'],b['canonical_sha256'])
        self.assertNotEqual(a['raw_sha256'],b['raw_sha256'])
        self.assertEqual(a['minhash64'],b['minhash64'])
        self.assertIsNone(dom_signature(b'<br>')['minhash64'])

    def test_visual_hash_and_flat_image_handling(self):
        im=Image.new('RGB',(320,180),'white');draw=ImageDraw.Draw(im)
        draw.rectangle((30,20,190,80),fill='black');draw.ellipse((100,90,150,130),fill='red')
        p=self.root/'a.png';q=self.root/'b.png';im.save(p);im.save(q)
        a,b=visual_signature(p),visual_signature(q)
        self.assertEqual(a,b);self.assertFalse(a['flat_image']);self.assertEqual(len(a['phash64']),16)
        Image.new('RGB',(256,256),'white').save(q)
        self.assertTrue(visual_signature(q)['flat_image'])
        q.write_bytes(b'corrupt')
        with self.assertRaises(OSError):visual_signature(q)

    def test_top_k_has_no_label_transfer_and_missing_visual_stays_missing(self):
        p=self.root/'a.html';p.write_bytes(b'<html><body><p>a</p></body></html>')
        records=[{'item_id':str(i),'review_id':str(i),'scope':'historical_development_audit','dom_path':p,'screenshot_path':None} for i in range(4)]
        result=build(records,self.root/'out',top_k=1)
        self.assertEqual(result['visual_available'],0)
        self.assertFalse(result['thresholds_calibrated'])
        pairs=rows(self.root/'out/private/candidate_pairs.jsonl')
        self.assertTrue(pairs)
        self.assertTrue(all(r['label_transfer'] is False and r['same_template'] is None for r in pairs))
        self.assertTrue(all(r['eligible_for_training'] is False for r in rows(self.root/'out/private/index.jsonl')))

    def test_cloud_wrapper_only_publishes_ciphertext_and_aggregates(self):
        result=run(self.root/'work',self.root/'publish',self.public,Fake(successful()).client,candidates=[CANDIDATE],smoke=True)
        self.assertEqual(result['completeness_counts'],{'COMPLETE':1})
        for p in (self.root/'publish').iterdir():
            self.assertNotIn(b'https://example.com/',p.read_bytes())
            self.assertNotIn(b'PRIVATE KEY',p.read_bytes())
        restored=unseal((self.root/'publish/evidence.enc').read_bytes(),self.private.read_bytes())
        unpack(restored,self.root/'restore')
        self.assertEqual(rows(self.root/'restore/input.jsonl'),[CANDIDATE])
        self.assertTrue(list((self.root/'restore/capture/private').glob('*/screenshot.png')))

    def test_partial_evidence_encrypted_even_if_index_fails(self):
        with patch('research.urlscan_v1.encrypted_batch.build',side_effect=ValueError('index problem')):
            with self.assertRaises(ValueError):run(self.root/'work',self.root/'publish',self.public,Fake(successful()).client,candidates=[CANDIDATE],smoke=True)
        self.assertTrue((self.root/'publish/evidence.enc').is_file())
        self.assertTrue(unseal((self.root/'publish/evidence.enc').read_bytes(),self.private.read_bytes()))

    def test_bad_public_key_makes_no_api_request(self):
        p=self.root/'bad.pem';p.write_bytes(b'not a key');fake=Fake([])
        with self.assertRaises(ValueError):run(self.root/'work',self.root/'publish',p,fake.client,candidates=[CANDIDATE],smoke=True)
        self.assertEqual(fake.client.requests,0)


if __name__=='__main__':unittest.main()
