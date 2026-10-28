"""Offline software fixtures only; no real-site access or research scores."""
import hashlib
import json
from pathlib import Path

import pytest

from phishing_url.dom_dataset import (
    grouped_partitions, leakage_groups, materialize_pilot, probe_html, select_candidates,
)

ROOT = Path(__file__).resolve().parents[1]


def configuration():
    c = json.loads((ROOT / 'config/assignment03_dom_pilot.json').read_text())
    c.update(dataset_id='synthetic_unit_fixture', source='synthetic_unit_fixture',
             target_candidates_per_label=24, per_domain_cap_per_label=1,
             technical_min_pairs_per_label=10, technical_min_domains_per_label=10)
    return c


def metadata():
    return [dict(source_row=y*100+i, url=f'https://site{y}-{i}.example/page',
                 label='phish' if y else 'benign', date='2025-01-01', sha256=None)
            for y in (0, 1) for i in range(40)]


def test_frozen_url_code_unchanged():
    freeze = json.loads((ROOT / 'config/assignment03_phase1_freeze.json').read_text())
    for name, expected in freeze['implementation_sha256'].items():
        assert hashlib.sha256((ROOT / 'src/phishing_url' / name).read_bytes()).hexdigest() == expected
    assert hashlib.sha256((ROOT / freeze['seed_plan_path']).read_bytes()).hexdigest() == freeze['seed_plan_sha256']
    assert freeze['phase1_test_evaluated'] is False
    assert freeze['historical_assignment02_test_previously_evaluated'] is True


def test_markup_probe_is_static_not_javascript_execution():
    result = probe_html('<script>throw new Error("never execute"); document.write("<input type=password>")</script><form><input TYPE=password></form>', 10000)
    assert result['parse_status'] == 'parsed_markup'
    assert result['script_count'] == 1
    assert result['password_input_count'] == 1
    assert result['form_count'] == 1


@pytest.mark.parametrize('html,status', [(None, 'missing_html'), ('   ', 'missing_html'),
                                        ('plain text', 'no_markup'), ('<p>'*20, 'oversize_html')])
def test_missing_and_oversize_are_not_zero_features(html, status):
    result = probe_html(html, 50)
    assert result['parse_status'] == status


def test_selection_is_order_invariant_and_has_fixed_domain_cap():
    cfg = configuration()
    selected, audit = select_candidates(metadata(), cfg)
    replay, _ = select_candidates(list(reversed(metadata())), cfg)
    assert selected == replay
    assert len(selected) == 48
    assert len({r['registered_domain'] for r in selected}) == 48
    assert audit['failed_candidate_replacement'] is False


def test_conflicting_urls_removed_before_sampling_and_no_scheme_invention():
    data = metadata()
    data += [dict(source_row=900, url=data[0]['url'], label='phish'),
             dict(source_row=901, url='example.com/path', label='benign')]
    chosen, audit = select_candidates(data, configuration())
    assert all(r['url_clean'] != data[0]['url'] for r in chosen)
    assert audit['metadata_exclusions']['conflicting_url_label'] == 2
    assert audit['metadata_exclusions']['invalid_or_schemeless_url'] == 1


def test_duplicate_source_row_rejected():
    data = metadata()
    with pytest.raises(ValueError, match='source row'):
        select_candidates(data + [data[0]], configuration())


def test_connected_groups_include_domains_html_and_final_domains():
    records = [
        dict(sample_id='a', registered_domain='one.example', html_sha256='content1', final_url=None),
        dict(sample_id='b', registered_domain='two.example', html_sha256='content1', final_url=None),
        dict(sample_id='c', registered_domain='three.example', html_sha256='content2', final_url='https://two.example/login'),
    ]
    groups = leakage_groups(records)
    assert len(set(groups.values())) == 1
    assert groups == leakage_groups(list(reversed(records)))


def test_paired_pilot_no_backfill_no_training_and_reproducible(tmp_path, monkeypatch):
    import phishing_url.experiment as experiment
    def forbid_fit(*args, **kwargs):
        raise AssertionError('dataset preparation must not train a model')
    monkeypatch.setattr(experiment, '_fit', forbid_fit)
    cfg = configuration()
    chosen, inventory = select_candidates(metadata(), cfg)
    content = {r['source_row']: f'<html><body><p>{r["sample_id"]}</p></body></html>' for r in chosen}
    content[chosen[0]['source_row']] = None
    out = tmp_path / 'pilot'
    result = materialize_pilot(chosen, content, out, cfg, inventory)
    assert result['candidate_count'] == 48 and result['usable_pairs'] == 47
    assert result['status_counts']['missing_html'] == 1
    assert result['training_approved'] is False and result['test_evaluated'] is False
    assert result['model_training_performed'] is False
    pairs = [json.loads(line) for line in (out / 'paired_manifest.jsonl').read_text().splitlines()]
    assert all(r['final_url'] is None and r['http_status'] is None and r['redirect_chain'] is None for r in pairs)
    for row in pairs:
        if row['usable_pair']:
            assert hashlib.sha256((out / row['html_path']).read_bytes()).hexdigest() == row['html_sha256']
    assert set(result['pilot_split_counts']) == {'train', 'validation', 'test'}
    by_group = {}
    for row in pairs:
        if row['usable_pair']:
            by_group.setdefault(row['leakage_group'], set()).add(row['pilot_split'])
    assert all(len(s) == 1 for s in by_group.values())
    public = (out / 'public/replay_index.csv').read_text()
    assert 'https://' not in public and '<html' not in public
    again = tmp_path / 'replay'
    materialize_pilot(chosen, content, again, cfg, inventory)
    assert (out / 'paired_manifest.jsonl').read_bytes() == (again / 'paired_manifest.jsonl').read_bytes()
    with pytest.raises(FileExistsError):
        materialize_pilot(chosen, content, out, cfg, inventory)


def test_same_html_with_conflicting_labels_is_quarantined(tmp_path):
    cfg = configuration()
    chosen, inventory = select_candidates(metadata(), cfg)
    content = {r['source_row']: f'<p>{r["sample_id"]}</p>' for r in chosen}
    for label in (0, 1):
        row = next(r for r in chosen if r['label'] == label)
        content[row['source_row']] = '<p>identical conflicting evidence</p>'
    result = materialize_pilot(chosen, content, tmp_path / 'conflicts', cfg, inventory)
    assert result['status_counts']['conflicting_identical_html_labels'] == 2
    assert result['usable_pairs'] == 46


def test_empty_pairs_fail_without_fabricating_split():
    with pytest.raises(ValueError, match='no usable'):
        grouped_partitions([], 1, 2)
