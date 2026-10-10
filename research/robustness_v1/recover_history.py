"""Recover hash-only exposure identities from the saved A02 delivery.

Only pinned URL data and observation metadata/DOM are read; prediction files
are never opened. Hashes provide provenance, not independent label verification.
"""
import argparse
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import zipfile
from .intake import digest, read_rows, write_json
from phishing_url.url_cleaning import clean_url, registered_domain
from phishing_url.formal_html import inspect_html


def sha(value):
    return hashlib.sha256(value).hexdigest()


def recover(root, delivery, output):
    prefix = 'assignment02_baseline_and_pilot_v2/'
    expected = json.loads((root/'results/assignment02/historical_baseline_v2/frozen_manifest.json').read_text())
    obs_expected = json.loads((root/'results/assignment02/observation_pilot_v2/verification.json').read_text())
    history_path = root/'research/robustness_v1/evidence/history_v2/historical_exposure_registry.jsonl'
    rows = read_rows(history_path)
    with zipfile.ZipFile(delivery) as bundle:
        payload = bundle.read(prefix+'frozen/urls.csv')
        if sha(payload) != expected['dataset_sha256']:
            raise ValueError('historical URL dataset checksum mismatch')
        baseline = list(csv.DictReader(io.StringIO(payload.decode())))
        if len(baseline)!=4000:
            raise ValueError('unexpected historical dataset size')
        for r in baseline:
            url = clean_url(r['url_clean'])
            if url != r['url_clean'] or registered_domain(url) != r['registered_domain']:
                raise ValueError('historical normalization drift')
            rows.append(dict(sample_id=sha(url.encode()), normalized_url_sha256=sha(url.encode()),
                             registered_domain_sha256=sha(r['registered_domain'].encode()),
                             exposure_origin='assignment02_historical_url_baseline'))
        obs_bytes = bundle.read(prefix+'pilot_v2/observation_pilot_v2_original.zip')
    if sha(obs_bytes) != obs_expected['artifact_sha256']:
        raise ValueError('observation archive checksum mismatch')
    observed = []
    with zipfile.ZipFile(io.BytesIO(obs_bytes)) as archive:
        checksums = json.loads(archive.read('CHECKSUMS.json'))
        # Validate every declared file before using this archive's metadata.
        for name, expected_hash in checksums.items():
            if sha(archive.read(name)) != expected_hash:
                raise ValueError('observation member checksum mismatch')
        for name in sorted(archive.namelist()):
            if not name.endswith('/observation.json'):
                continue
            r = json.loads(archive.read(name))
            url = clean_url(r['url_clean'])
            record = dict(sample_id=r['observation_id'],
                          normalized_url_sha256=sha(url.encode()),
                          registered_domain_sha256=sha(registered_domain(url).encode()),
                          exposure_origin='observation_pilot_v2',
                          historical_capture_status=r['status'])
            dom = r.get('modalities',{}).get('dom')
            if dom and dom.get('path'):
                html = archive.read(dom['path'])
                if sha(html) != dom['sha256']:
                    raise ValueError('DOM binding mismatch')
                record['html_sha256'] = sha(html)
                parsed = inspect_html(html.decode('utf-8'), url, 2097152)
                if parsed.get('tag_count',0)>=20:
                    record['structural_sha256'] = parsed['structural_tag_sequence_sha256']
            observed.append(record)
            rows.append(record)
    if len(observed)!=16:
        raise ValueError('observation membership mismatch')
    output.mkdir(parents=True,exist_ok=False)
    registry = output/'historical_exposure_registry.jsonl.gz'
    raw = ''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows).encode()
    registry.write_bytes(gzip.compress(raw,mtime=0))
    keys = ['sample_id','registered_domain_sha256','normalized_url_sha256','html_sha256','structural_sha256','campaign_id']
    summary = dict(status='partial_history_not_novelty_certification',
                   historical_records=len(rows),baseline_url_records=len(baseline),
                   observation_records=len(observed),
                   present_records={k:sum(bool(r.get(k)) for r in rows) for k in keys},
                   delivery_sha256=digest(delivery),url_dataset_sha256=sha(payload),
                   observation_artifact_sha256=sha(obs_bytes),verified_observation_members=len(checksums),
                   inherited_registry_sha256=digest(history_path),registry_sha256=digest(registry),
                   remaining_gaps=['Assignment01 and other URL collections',
                                   'observation pilot v1 identities',
                                   'formal/DOM-pilot normalized URL and structural history',
                                   'campaign evidence'],
                   new_samples=0,human_reviews=0,real_model_fits=0,test_predictions_read=False)
    write_json(output/'summary.json',summary)
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','delivery','output'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(recover(a.root,a.delivery,a.output),indent=2))
