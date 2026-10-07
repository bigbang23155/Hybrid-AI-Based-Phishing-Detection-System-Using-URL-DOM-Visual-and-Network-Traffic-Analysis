import json
from pathlib import Path

import pytest

from phishing_url.formal_candidates import file_sha, json_bytes, run as select_run
from phishing_url.formal_html import inspect_html, materialize, diagnostics, run

ROOT = Path(__file__).resolve().parents[1]


def test_static_semantics_base_nonhttp_and_missing_denominators():
    html = '''<html><head><base href="https://outside.example/"></head><body>
    <a href="/x">one</a><a href="mailto:x@example.com">mail</a>
    <input type=" PASSWORD "/><input type="hidden"><div hidden style="display: none">x</div>
    <script src="/a.js">verify you are human</script><form action="/go"></form>
    <iframe src="https://inside.test/frame"></iframe><meta http-equiv="Refresh" content="0">
    </body></html>'''
    r = inspect_html(html, 'https://inside.test/', 10000)
    assert r['parse_status'] == 'parsed_markup'
    assert r['password_input_count'] == 1
    assert r['link_count'] == 2 and r['http_link_count'] == 1
    assert r['external_link_count'] == 1 and r['external_link_ratio'] == 1
    assert r['external_resource_count'] == 1 and r['external_resource_ratio'] == .5
    assert r['external_script_count'] == 1 and r['external_form_action_count'] == 1
    assert r['hidden_attribute_count'] == r['hidden_input_count'] == r['inline_hidden_style_count'] == 1
    assert not r['challenge_marker']
    assert r['meta_refresh_count'] == 1
    assert inspect_html('<p>abc</p>', 'https://inside.test', 100)['external_link_ratio'] is None


def test_failure_states_and_utf8_size_boundary():
    assert inspect_html(None, 'https://a.test', 10)['parse_status'] == 'missing_html'
    assert inspect_html(12, 'https://a.test', 10)['parse_status'] == 'non_string_html'
    assert inspect_html('  ', 'https://a.test', 10)['parse_status'] == 'empty_html'
    assert inspect_html('\ud800', 'https://a.test', 10)['parse_status'] == 'encoding_error'
    value = '<p>字</p>'
    size = len(value.encode())
    assert inspect_html(value, 'https://a.test', size)['parse_status'] == 'parsed_markup'
    assert inspect_html(value, 'https://a.test', size - 1)['parse_status'] == 'oversize_html'
    r = inspect_html('ordinary text', 'https://a.test', 100)
    assert r['parse_status'] == 'no_markup'
    assert inspect_html(None, 'https://a.test', 100)['password_input_count'] is None


def test_quarantine_all_conflict_members_no_backfill_and_keep_parse_status(tmp_path):
    policy = json.loads((ROOT/'config/assignment03_paired_release_policy_v1.json').read_text())
    selected = [dict(sample_id=str(i), label=i % 2, url_clean=f'https://a{i}.test/',
                     registered_domain=f'a{i}.test', capture_date=None, lang=None, target=None,
                     source_file='train', source_row=i) for i in range(4)]
    html = [(str(i), '<p>same</p>' if i < 2 else None if i == 2 else '<p>unique</p>') for i in range(4)]
    rows, conflicts = materialize(selected, html, tmp_path/'output', policy, {'revision': 'fixed'})
    assert len(rows) == 4 and len(conflicts) == 1
    assert [r['usable_pair'] for r in rows] == [False, False, False, True]
    assert rows[0]['parse_status'] == 'parsed_markup'
    assert rows[0]['exclusion_reasons'] == ['cross_label_exact_html_conflict']
    d = diagnostics(rows, conflicts)
    assert d['cohorts']['selected']['0']['rates']['password_input']['missing'] == 1
    assert d['cohorts']['selected']['0']['rates']['password_input']['denominator'] == 1
    assert d['cohorts']['usable']['0']['numeric']['html_bytes']['n'] == 0
    assert d['attrition_strata']['month'][0]['loss_rate'] == 1
    with pytest.raises(ValueError, match='rows missing'):
        materialize(selected, html[:2], tmp_path/'incomplete', policy, {'revision': 'fixed'})


def source_fixture(tmp_path):
    pa = pytest.importorskip('pyarrow')
    import pyarrow.parquet as pq
    p = json.loads((ROOT/'config/assignment03_paired_release_policy_v1.json').read_text())
    p['sampling']['planned_candidates_per_label'] = 2
    frame = json.loads((ROOT/'config/assignment03_paired_source_frame_v1.json').read_text())
    source = tmp_path/'source'
    (source/'data').mkdir(parents=True)
    raw = [dict(url=f'https://domain{i}.test/page', label='phish' if i%2 else 'benign',
                date='2025-01-01', sha256='source-id', target=None, lang='en', lang_score=.9,
                html=f'<html><p>page {i}</p></html>') for i in range(20)]
    path = source/'data/train-001.parquet'
    pq.write_table(pa.Table.from_pylist(raw), path, row_group_size=3)
    frame['sampling_frame'].update(fixed_shards=[dict(path='data/train-001.parquet', sha256=file_sha(path), size_bytes=path.stat().st_size)],
        fixed_shard_count=1, expected_total_source_bytes=path.stat().st_size, sample_target_before_content_inspection=2)
    f, pol = tmp_path/'frame.json', tmp_path/'policy.json'
    f.write_bytes(json_bytes(frame)); pol.write_bytes(json_bytes(p))
    summary = select_run(source, tmp_path/'selection', f, pol)
    freeze = {k: summary[k] for k in ('candidate_count', 'candidate_manifest_sha256', 'candidate_replay_sha256', 'source_frame_sha256', 'policy_sha256')}
    freeze['selected_per_label'] = {'0': 2, '1': 2}
    frozen = tmp_path/'freeze.json'; frozen.write_bytes(json_bytes(freeze))
    return source, f, pol, frozen


def test_replay_adapter_exact_membership_and_audit(tmp_path):
    source, f, pol, frozen = source_fixture(tmp_path)
    out = tmp_path/'html-output'
    result = run(source, out, f, pol, frozen)
    assert result['candidate_count'] == result['usable_pairs'] == 4
    assert not result['training_approved'] and not result['final_partition_created']
    original = (tmp_path/'selection/public/candidate_replay.jsonl').read_bytes()
    assert original == (out/'public/candidate_replay.jsonl').read_bytes()
    records = [json.loads(line) for line in (out/'paired_manifest.jsonl').read_text().splitlines()]
    for r in records:
        assert f"page {r['source_row']}" in (out/r['html_path']).read_text()
    public = (out/'public/sample_audit.jsonl').read_text()
    assert 'url_clean' not in public and 'html_path' not in public
    assert json.loads((out/'public/quality_report.json').read_text())['bias_review_required']


def test_membership_tampering_stops_before_html(tmp_path, monkeypatch):
    source, f, pol, frozen = source_fixture(tmp_path)
    freeze = json.loads(frozen.read_text()); freeze['candidate_replay_sha256'] = 'bad'
    frozen.write_bytes(json_bytes(freeze))
    def forbidden(*args):
        raise AssertionError('HTML read before membership check')
    monkeypatch.setattr('phishing_url.formal_html.selected_html', forbidden)
    with pytest.raises(ValueError, match='membership mismatch'):
        run(source, tmp_path/'bad', f, pol, frozen)
    assert not (tmp_path/'bad').exists()


def test_integrity_tampering_stops_before_html(tmp_path):
    source, f, pol, frozen = source_fixture(tmp_path)
    with (source/'data/train-001.parquet').open('ab') as stream:
        stream.write(b'tampered')
    with pytest.raises(ValueError, match='integrity'):
        run(source, tmp_path/'bad', f, pol, frozen)


def test_same_label_duplicate_is_retained_and_grouped(tmp_path):
    p = json.loads((ROOT/'config/assignment03_paired_release_policy_v1.json').read_text())
    chosen = [dict(sample_id=str(i), label=0, url_clean=f'https://a{i}.test/', registered_domain=f'a{i}.test') for i in range(2)]
    rows, conflicts = materialize(chosen, [('0', '<p>same</p>'), ('1', '<p>same</p>')], tmp_path/'out', p, {'revision':'fixed'})
    assert not conflicts and all(r['usable_pair'] for r in rows)
    assert rows[0]['leakage_group'] == rows[1]['leakage_group']
