"""Metadata-only selection across the frozen formal frame; no HTML decoding."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from .url_cleaning import clean_url, registered_domain

METADATA_COLUMNS = ['url', 'label', 'date', 'sha256', 'target', 'lang', 'lang_score']

def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def file_sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()

def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def validate_frame(frame, policy):
    source, sampling = policy['source'], frame['sampling_frame']
    if (source['inventory_status'] != 'frozen_and_hashed' or
        frame['revision'] != source['revision'] or
        frame['source_inventory']['inventory_sha256'] != source['inventory_sha256']):
        raise ValueError('source identity mismatch')
    shards = sampling['fixed_shards']
    if (sampling['source_split'] != 'train' or sampling['official_source_test_split_used'] is not False or
        len(shards) != sampling['fixed_shard_count'] or
        len({x['path'] for x in shards}) != len(shards) or
        any(not x['path'].startswith('data/train-') or '..' in x['path'] or
            x['path'] == sampling['exclude_pilot_shard'] for x in shards) or
        sum(x['size_bytes'] for x in shards) != sampling['expected_total_source_bytes']):
        raise ValueError('invalid frozen shard frame')
    if (sampling['sample_target_before_content_inspection'] != policy['sampling']['planned_candidates_per_label'] or
        sampling['selection_seed'] != policy['sampling']['seed']):
        raise ValueError('sampling policy mismatch')

def acquire(frame, root):
    import requests
    root.mkdir(parents=True, exist_ok=False)
    evidence = []
    for item in frame['sampling_frame']['fixed_shards']:
        dest = root / item['path']
        dest.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://huggingface.co/datasets/phreshphish/phreshphish/resolve/{frame['revision']}/{item['path']}"
        count = 0
        with requests.get(url, stream=True, timeout=(30, 120)) as response:
            response.raise_for_status()
            with dest.open('xb') as stream:
                for block in response.iter_content(1 << 20):
                    count += len(block)
                    if count > item['size_bytes']:
                        raise ValueError('source exceeds frozen size')
                    stream.write(block)
        actual = file_sha(dest)
        record = {**item, 'actual_sha256': actual, 'actual_bytes': count,
                  'verified': actual == item['sha256'] and count == item['size_bytes']}
        evidence.append(record)
        (root / 'acquisition.json').write_bytes(json_bytes({'files': evidence, 'retrieved_at_utc': datetime.now(timezone.utc).isoformat()}))
        print(json.dumps(record), flush=True)
        if not record['verified']:
            raise ValueError('source checksum mismatch; no substitution')

def read_metadata(root, frame):
    import pyarrow.parquet as pq
    rows, inventory = [], []
    for item in frame['sampling_frame']['fixed_shards']:
        path = root / item['path']
        if path.stat().st_size != item['size_bytes'] or file_sha(path) != item['sha256']:
            raise ValueError('source integrity failure')
        source = pq.ParquetFile(path)
        if not set(METADATA_COLUMNS + ['html']).issubset(source.schema_arrow.names):
            raise ValueError('missing required paired source columns')
        metadata = source.read(columns=METADATA_COLUMNS).to_pylist()
        inventory.append({**item, 'rows': len(metadata), 'source_labels': dict(Counter(str(r['label']) for r in metadata))})
        for index, row in enumerate(metadata):
            rows.append({**row, 'source_row': index, 'source_file': item['path'], 'source_file_sha256': item['sha256']})
    return rows, inventory

def select(metadata, policy):
    sampling = policy['sampling']
    target, cap, seed = sampling['planned_candidates_per_label'], sampling['per_domain_cap_per_label'], sampling['seed']
    if any(type(x) is not int or x < 1 for x in (target, cap, seed)):
        raise ValueError('invalid sampling parameters')
    ids = [(r['source_file_sha256'], r['source_row']) for r in metadata]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate source identities')
    by_url, exclusions = defaultdict(list), Counter()
    for r in metadata:
        if r['label'] not in policy['label_policy']['mapping']:
            exclusions['unknown_source_label'] += 1
            continue
        try:
            url = clean_url(r['url'])
            domain = registered_domain(url)
        except ValueError:
            exclusions['invalid_or_schemeless_url'] += 1
            continue
        date = r.get('date')
        if hasattr(date, 'isoformat'):
            date = date.isoformat()
        row = dict(sample_id=sha(f"{r['source_file_sha256']}:{r['source_row']}".encode()),
                   source_file=r['source_file'], source_file_sha256=r['source_file_sha256'], source_row=r['source_row'],
                   url_clean=url, registered_domain=domain, label=policy['label_policy']['mapping'][r['label']],
                   source_label=r['label'], source_sample_id=r.get('sha256'), capture_date=str(date) if date is not None else None,
                   lang=r.get('lang'), target=r.get('target'))
        by_url[url].append(row)
    unique = []
    for group in by_url.values():
        if len({r['label'] for r in group}) > 1:
            exclusions['conflicting_url_label'] += len(group)
        else:
            unique.append(min(group, key=lambda r: r['sample_id']))
            exclusions['duplicate_normalized_url'] += len(group) - 1
    chosen, per_label = [], {}
    for label in (0, 1):
        eligible = [r for r in unique if r['label'] == label]
        ranked = sorted(eligible, key=lambda r: (sha(f"{seed}:{r['sample_id']}".encode()), r['sample_id']))
        counts, selected, capped = Counter(), [], 0
        for row in ranked:
            if counts[row['registered_domain']] >= cap:
                capped += 1
            else:
                counts[row['registered_domain']] += 1
                selected.append(row)
        capacity = len(selected)
        selected = selected[:target]
        chosen.extend(selected)
        domains = Counter(r['registered_domain'] for r in selected)
        n = len(selected)
        per_label[str(label)] = dict(eligible_unique_urls=len(eligible), eligible_domains=len({r['registered_domain'] for r in eligible}),
            domain_capped_capacity=capacity, excluded_by_domain_cap=capped,
            selected=n, shortfall=max(0, target-n), selected_domains=len(domains),
            maximum_urls_per_domain=max(domains.values(), default=0),
            largest_domain_share=max(domains.values(), default=0)/n if n else None,
            root_path_rate=sum(urlsplit(r['url_clean']).path in ('','/') for r in selected)/n if n else None,
            https_rate=sum(urlsplit(r['url_clean']).scheme == 'https' for r in selected)/n if n else None,
            missing_date=sum(not r['capture_date'] for r in selected),
            date_month_counts=dict(sorted(Counter((r['capture_date'] or 'missing')[:7] for r in selected).items())),
            language_counts=dict(sorted(Counter(str(r['lang']) for r in selected).items())),
            selected_per_shard=dict(sorted(Counter(r['source_file'] for r in selected).items())))
    chosen.sort(key=lambda r: r['sample_id'])
    return chosen, dict(source_rows=len(metadata), metadata_exclusions=dict(exclusions),
        unique_eligible_url_rows=len(unique), per_label=per_label,
        candidate_target_met=all(p['shortfall'] == 0 for p in per_label.values()))

def run(root, output, frame_path, policy_path):
    frame, policy = json.loads(frame_path.read_text()), json.loads(policy_path.read_text())
    validate_frame(frame, policy)
    if output.exists():
        raise FileExistsError('preserve selection evidence; use a new directory')
    rows, inventory = read_metadata(root, frame)
    chosen, summary = select(rows, policy)
    output.mkdir(parents=True)
    public = output / 'public'
    public.mkdir()
    private = ''.join(json.dumps(r, sort_keys=True, allow_nan=False)+'\n' for r in chosen).encode()
    (output / 'candidate_manifest.jsonl').write_bytes(private)
    keys = ['sample_id', 'source_file', 'source_file_sha256', 'source_row', 'label']
    replay = ''.join(json.dumps({k:r[k] for k in keys}, sort_keys=True)+'\n' for r in chosen).encode()
    (public / 'candidate_replay.jsonl').write_bytes(replay)
    summary.update(schema_version='formal-metadata-selection-v1', dataset_id=policy['dataset_id'],
        status='candidate_membership_frozen' if summary['candidate_target_met'] else 'candidate_shortfall_stop',
        source_revision=frame['revision'], source_inventory=inventory,
        candidate_count=len(chosen), candidate_manifest_sha256=sha(private), candidate_replay_sha256=sha(replay),
        source_frame_sha256=file_sha(frame_path), policy_sha256=file_sha(policy_path),
        implementation_sha256=file_sha(Path(__file__)), sampling_seed=policy['sampling']['seed'],
        metadata_columns_read=METADATA_COLUMNS, html_column_read=False, html_inspected=False,
        html_present_in_downloaded_parquet=True, selection_precedes_html_inspection=True,
        official_source_test_split_used=False, pilot_shard_excluded=frame['sampling_frame']['exclude_pilot_shard'],
        failed_candidate_replacement=False, training_approved=False, model_training_performed=False,
        final_partition_created=False, final_dom_dataset_frozen=False, test_evaluated=False)
    (public / 'selection_summary.json').write_bytes(json_bytes(summary))
    (public / frame_path.name).write_bytes(frame_path.read_bytes())
    (public / policy_path.name).write_bytes(policy_path.read_bytes())
    return summary

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--frame', type=Path, required=True)
    p.add_argument('--policy', type=Path, required=True)
    p.add_argument('--output', type=Path)
    p.add_argument('--download', action='store_true')
    a = p.parse_args()
    frame, policy = json.loads(a.frame.read_text()), json.loads(a.policy.read_text())
    validate_frame(frame, policy)
    if a.download:
        acquire(frame, a.source_root)
        return 0
    if a.output is None:
        p.error('--output required for selection')
    result = run(a.source_root, a.output, a.frame, a.policy)
    print(json.dumps(result, indent=2))
    return 0 if result['candidate_target_met'] else 2

if __name__ == '__main__':
    raise SystemExit(main())
