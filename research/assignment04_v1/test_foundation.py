import copy
import io
import tempfile
import unittest
from pathlib import Path
from PIL import Image
from . import visual
from .integration import inventory, validate, evidence_demo, upgrade
from research.multimodal_v1.contract import (assemble, modality, freshness, feature_set,
    unavailable_features, fusion_view, MODALITIES)


def fixture():
    modalities={}
    for name in MODALITIES:
        f = feature_set('synthetic-v1', {'a':0.0})
        modalities[name]=modality(name,f,acquisition='available',extraction='ok',
            temporal=freshness('2026-11-05T00:00:00Z',as_of='2026-11-05T01:00:00Z',max_age_seconds=7200,applicable=name!='url'),
            provenance={'checkpoint_sha256':'synthetic','scan_uuid':'synthetic'})
    return assemble('synthetic',modalities,scope='smoke_test')


class Tests(unittest.TestCase):
    def test_standardization_hand_calculated(self):
        from .audit_a03 import balanced_complexity
        rows=[{'label':y,'complexity_bin':b,'outcome':'tp' if y else 'tn'} for y in (0,1) for b in range(4)]
        self.assertEqual(balanced_complexity(rows)['f1'],1.0)
        rows[-1]['outcome']='fn'
        self.assertAlmostEqual(balanced_complexity(rows)['f1'],6/7)
        self.assertIsNone(balanced_complexity(rows[:-1]))

    def test_source_assertions_remain_unadopted(self):
        r=fixture();r['source_label']=1
        out=inventory([r])
        self.assertEqual(out['by_source_assertion_not_adjudicated_label']['1']['attempted'],1)
        self.assertEqual(out['training_eligible'],0)
        self.assertIsNone(r['label'])

    def test_checkpoint_end_to_end_and_stale(self):
        import json
        from unittest.mock import patch
        import socket
        from research.multimodal_v1.test_multimodal import FakeClient, CANDIDATE, AS_OF
        from research.urlscan_v1.collector import capture
        with tempfile.TemporaryDirectory() as t:
            folder=Path(t)
            raw=capture(FakeClient(), CANDIDATE, folder)
            p=folder/'record.json';p.write_text(json.dumps(raw))
            with patch.object(socket,'socket',side_effect=AssertionError('offline_only')):
                r=upgrade(p,as_of=AS_OF,max_age_seconds=7200)
                view=fusion_view(validate(r))
                self.assertEqual(len(view['values']),165)
                self.assertEqual(view['modality_mask'],[1,1,1,1])
                self.assertEqual(inventory([r])['attempted'],1)
                stale=upgrade(p,as_of=AS_OF,max_age_seconds=0)
                self.assertEqual(fusion_view(validate(stale))['modality_mask'],[1,0,0,0])
            # Corrupt bytes cannot become usable visual evidence.
            (folder/raw['artifacts']['screenshot']['file']).write_bytes(b'bad')
            r=upgrade(p,as_of=AS_OF,max_age_seconds=7200)
            self.assertEqual(r['modalities']['visual']['modality_usable_mask'],0)

    def test_solid_red_hand_calculated(self):
        b=io.BytesIO();Image.new('RGB',(30,50),'red').save(b,format='PNG')
        a=visual.extract(b.getvalue())
        self.assertEqual(a,visual.extract(b.getvalue()))
        self.assertEqual(len(a['values']),104)
        self.assertEqual(a['values']['r_hist_15'],1)
        self.assertEqual(a['values']['g_hist_00'],1)
        self.assertEqual(a['values']['grid_0_0_r_mean'],1)
        self.assertEqual(sum(a['values'][f'gradient_orientation_{i}'] for i in range(8)),0)

    def test_corrupt_and_budget(self):
        with self.assertRaises((OSError,ValueError)):visual.extract(b'not an image')
        with self.assertRaises(ValueError):visual.extract(b'')
        b=io.BytesIO();Image.new('RGB',(20,20)).save(b,format='PNG')
        old=visual.MAX_PIXELS
        try:
            visual.MAX_PIXELS=10
            with self.assertRaises(ValueError):visual.extract(b.getvalue())
        finally:visual.MAX_PIXELS=old

    def test_pending_and_zero(self):
        r=fixture(); out=inventory([r]);self.assertEqual(out['attempted'],1)
        self.assertEqual(out['training_eligible'],0)
        self.assertEqual(fusion_view(validate(r))['values'],[0.0]*4)
        self.assertIn('Prediction unavailable',evidence_demo(r))

    def test_test_rejected_before_artifacts(self):
        import json
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'c.json';p.write_text(json.dumps({'scope':'smoke_test','partition':'test'}))
            with self.assertRaisesRegex(ValueError,'partition_forbidden'):
                upgrade(p,as_of='2026-11-05T01:00:00Z',max_age_seconds=10)

    def test_tamper_labels_duplicates_alignment(self):
        for field,value in [('label',1),('eligible_for_training',True),('partition','test')]:
            r=fixture();r[field]=value
            with self.assertRaises(ValueError):inventory([r])
        r=fixture()
        with self.assertRaises(ValueError):inventory([r,r])
        for key in ('usable_mask','observed_mask'):
            r=fixture();r['modalities']['dom'][key]['a']=0
            with self.assertRaises(ValueError):validate(r)
        r=fixture();r['modalities']['visual']['provenance']['scan_uuid']='other'
        with self.assertRaises(ValueError):validate(r)

    def test_missing_not_zero_and_schema_mismatch(self):
        r=fixture();m=r['modalities']['visual']
        r['modalities']['visual']=modality('visual',unavailable_features('synthetic-v1',['a'],'not_supplied'),
            acquisition='not_supplied',extraction='unavailable',temporal=m['temporal'],provenance=m['provenance'])
        self.assertIsNone(fusion_view(validate(r))['values'][2])
        other=copy.deepcopy(r);other['item_id']='other'
        other['modalities']['visual']['features']['registry_version']='different'
        with self.assertRaises(ValueError):inventory([r,other])

if __name__=='__main__':unittest.main()
