import csv
import hashlib

import pytest

from phishing_url.supplement_collection import merge_tables, supplemental_sample
from phishing_url.url_cleaning import registered_domain


def test_new_sample_excludes_original_groups_and_is_reproducible():
    rows = [(1001, 'a.example.com'), (1002, 'b.example.com')]
    rows += [(1003+i, f'site{i}.org') for i in range(20)]
    prior = [(1001, 'a.example.com')]
    first = supplemental_sample(rows, prior, size=10, seed=12)
    assert first == supplemental_sample(rows, prior, size=10, seed=12)
    groups = {registered_domain('https://'+domain+'/') for _, domain in first}
    assert 'example.com' not in groups
    assert len(first) == len(groups) == 10
    with pytest.raises(ValueError, match='Insufficient'):
        supplemental_sample(rows, prior, size=100)


def table(path, fields, rows):
    with path.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def test_merge_preserves_inputs_deduplicates_and_keeps_failure_evidence(tmp_path):
    old, new = tmp_path/'old', tmp_path/'new'
    for p in (old, new):
        p.mkdir()
        table(p/'collection_failures.csv', ['reason'], [{'reason': 'timeout'}])
    table(old/'observed_legitimate_urls.csv', ['url_clean'], [{'url_clean': 'https://example.com/a'}])
    table(new/'observed_legitimate_urls.csv', ['url_clean'], [{'url_clean': 'https://other.org/a'}]*2)
    before = hashlib.sha256((old/'observed_legitimate_urls.csv').read_bytes()).hexdigest()
    result = merge_tables(old, new, tmp_path/'merged')
    assert result['merged_urls'] == 2
    assert result['duplicates_removed'] == 1
    assert result['original_failures'] == result['supplement_failures'] == 1
    assert hashlib.sha256((old/'observed_legitimate_urls.csv').read_bytes()).hexdigest() == before
    with pytest.raises(FileExistsError):
        merge_tables(old, new, tmp_path/'merged')
    table(new/'observed_legitimate_urls.csv', ['url_clean'], [{'url_clean': 'https://www.example.com/b'}])
    with pytest.raises(ValueError, match='overlaps'):
        merge_tables(old, new, tmp_path/'overlap')
