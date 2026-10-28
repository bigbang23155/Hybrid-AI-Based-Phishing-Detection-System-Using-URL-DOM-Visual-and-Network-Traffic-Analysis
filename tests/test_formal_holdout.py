import copy
import json
from pathlib import Path

import pytest

from phishing_url.formal_candidates import json_bytes, sha
from phishing_url.formal_holdout import connected_groups, exposure, freeze_rows, validate_partition, verify_pilot

ROOT = Path(__file__).resolve().parents[1]


def policy(n=100):
    p = json.loads((ROOT/'config/assignment03_holdout_policy_v1.json').read_text())
    p['eligibility'].update(expected_candidates=n, expected_usable=n)
    return p


def rows(n=100):
    return [dict(sample_id=f'{i:04}', label=i%2, registered_domain=f'd{i}.test',
                 url_clean=f'https://d{i}.test/p', html_sha256=f'html{i}',
                 structural_tag_sequence_sha256=f'structure{i}', tag_count=30,
                 usable_pair=True, parse_status='parsed_markup', exclusion_reasons=[],
                 source_file='train', source_row=i) for i in range(n)]


def test_transitive_domain_html_structure_and_pilot_exposure():
    r = rows(4)
    r[1]['html_sha256'] = r[0]['html_sha256']
    r[2]['structural_tag_sequence_sha256'] = r[1]['structural_tag_sequence_sha256']
    g = connected_groups(r)
    assert g['0000'] == g['0001'] == g['0002'] != g['0003']
    pilot = [{**r[0], 'sample_id': 'pilot', 'html_sha256': 'different',
              'structural_tag_sequence_sha256': None, 'tag_count': None, 'usable_pair': False}]
    direct, exposed = exposure(r, pilot, g)
    assert direct['0000'] and not direct['0001'] and not direct['0002']
    assert set(exposed) == {g['0000']}
    assert g == connected_groups(list(reversed(r)))


def test_short_generic_structures_do_not_group():
    r = rows(2)
    for a in r:
        a['structural_tag_sequence_sha256'] = 'same'
        a['tag_count'] = 19
    assert len(set(connected_groups(r).values())) == 2
    for a in r:
        a['tag_count'] = 20
    assert len(set(connected_groups(r).values())) == 1


def test_freeze_reproducibility_exposure_and_excluded_rows(tmp_path):
    r = rows()
    r[1]['html_sha256'] = r[0]['html_sha256']
    r[2]['structural_tag_sequence_sha256'] = r[1]['structural_tag_sequence_sha256']
    failed = {**rows(101)[100], 'usable_pair': False, 'parse_status': 'oversize_html', 'exclusion_reasons': ['oversize_html']}
    p = policy();p['eligibility']['expected_candidates'] = 101
    pilot = [{**r[0], 'sample_id': 'pilot', 'html_sha256': 'unknown', 'structural_tag_sequence_sha256': None, 'tag_count': None}]
    result = freeze_rows(r+[failed], pilot, p, tmp_path/'first')
    result2 = freeze_rows(list(reversed(r+[failed])), pilot, p, tmp_path/'second')
    assert result['partition_manifest_sha256'] == result2['partition_manifest_sha256']
    assert result['overlap']['train_only_due_to_pilot_rows'] == 3
    assert result['overlap']['transitive_additional_train_only_rows'] == 2
    assert not result['training_approved'] and not result['test_evaluated']
    manifest = [json.loads(l) for l in (tmp_path/'first/partition_manifest.jsonl').read_text().splitlines()]
    assert all(r['partition']=='train' for r in manifest[:3])
    assert manifest[-1]['partition']=='excluded'
    assert not any('url_clean' in r for r in manifest)
    with pytest.raises(FileExistsError):
        freeze_rows(r+[failed],pilot,p,tmp_path/'first')


def test_giant_component_stops_before_split_without_dropping_rows(tmp_path):
    r = rows()
    for a in r[:11]:
        a['structural_tag_sequence_sha256'] = 'giant'
    with pytest.raises(ValueError, match='component exceeds'):
        freeze_rows(r, [], policy(), tmp_path/'bad')
    assert not (tmp_path/'bad').exists()


def test_cannot_move_exposed_component_into_holdout():
    r = rows()
    for a in r:
        a['final_group'] = a['sample_id']
    assignment = {a['sample_id']: 'test' if i<15 else 'validation' if i<30 else 'train' for i,a in enumerate(r)}
    with pytest.raises(ValueError, match='pilot-exposed'):
        validate_partition(r,assignment,{'0000'},policy())
    r[16]['html_sha256'] = r[0]['html_sha256']
    with pytest.raises(ValueError, match='overlap'):
        validate_partition(r,assignment,set(),policy())


def test_all_exposed_fails_without_reselection(tmp_path):
    r = rows()
    pilot = [{**a, 'sample_id': 'pilot'+a['sample_id']} for a in r]
    with pytest.raises(ValueError, match='unexposed'):
        freeze_rows(r,pilot,policy(),tmp_path/'bad')


def test_pilot_legacy_projection_and_bytes_integrity(tmp_path):
    (tmp_path/'public').mkdir();(tmp_path/'html').mkdir()
    raw=b'<html><p>hello</p></html>'
    (tmp_path/'html/a.txt').write_bytes(raw)
    row={**rows(1)[0], 'html_sha256': sha(raw), 'html_path':'html/a.txt'}
    enriched={**row,'target':None,'lang':'en','lang_score':.9}
    (tmp_path/'paired_manifest.jsonl').write_text(json.dumps(enriched,sort_keys=True)+'\n')
    (tmp_path/'public/replay_index.csv').write_text('sample_id\n0000\n')
    verification={'paired_manifest_sha256':sha((json.dumps(row,sort_keys=True)+'\n').encode()),
                  'artifact_replay_index_sha256':sha(b'sample_id\n0000\n'),'selected_candidates':1}
    v=tmp_path/'verification.json';v.write_bytes(json_bytes(verification))
    result,evidence=verify_pilot(tmp_path,v,20)
    assert result[0]['structural_tag_sequence_sha256']
    assert evidence['original_manifest_projection_sha256']==verification['paired_manifest_sha256']
    (tmp_path/'html/a.txt').write_bytes(b'wrong')
    with pytest.raises(ValueError,match='HTML integrity'):
        verify_pilot(tmp_path,v,20)
