"""Extend exposure history from a checksum-pinned public DOM pilot index.

Reads identities only, never test predictions or raw pages. Missing URL,
domain, template and campaign history remains an explicit blocking gap.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import zipfile
from .intake import digest, read_rows, write_rows, write_json


def build(root, archive, output):
    verification_path = root / 'results/assignment03/dom_data_pilot_v1/verification.json'
    verification = json.loads(verification_path.read_text())
    if digest(archive) != verification['artifact_sha256']:
        raise ValueError('pilot archive checksum mismatch')
    with zipfile.ZipFile(archive) as z:
        payload = z.read('output/pilot/public/replay_index.csv')
    if hashlib.sha256(payload).hexdigest() != verification['artifact_replay_index_sha256']:
        raise ValueError('pilot index checksum mismatch')
    pilot = list(csv.DictReader(io.StringIO(payload.decode('utf-8'))))
    if len(pilot) != verification['selected_candidates'] or len({r['sample_id'] for r in pilot}) != len(pilot):
        raise ValueError('pilot membership invalid')
    history_path = root / 'research/robustness_v1/evidence/intake/historical_exposure_denylist.jsonl'
    history = read_rows(history_path)
    revision = verification['source_integrity']['revision']
    rows = [dict(r, source_revision=revision, exposure_origin='formal_candidates') for r in history]
    known = {r['sample_id'] for r in history}
    pilot_only = 0
    for r in pilot:
        if r['sample_id'] not in known:
            pilot_only += 1
        # Keep both provenance records for shared samples; no labels needed.
        rows.append(dict(sample_id=r['sample_id'], html_sha256=r['html_sha256'],
                         source_revision=revision,
                         source_file=verification['source_integrity']['source_file'],
                         source_row=int(r['source_row']), exposure_origin='dom_pilot',
                         partition='historical_pilot', final_group=r['leakage_group']))
    keys = ['sample_id', 'html_sha256', 'registered_domain_sha256',
            'normalized_url_sha256', 'structural_sha256', 'campaign_id']
    summary = dict(status='partial_history_not_novelty_certification',
                   formal_records=len(history), pilot_records=len(pilot),
                   pilot_only_sample_ids=pilot_only,
                   shared_sample_ids=len(pilot)-pilot_only,
                   pilot_records_matching_formal_html=sum(r['html_sha256'] in {h['html_sha256'] for h in history} for r in pilot),
                   unique_sample_ids=len({r['sample_id'] for r in rows}),
                   registry_records=len(rows),
                   present_records={k:sum(bool(r.get(k)) for r in rows) for k in keys},
                   artifact_sha256=digest(archive),
                   index_sha256=hashlib.sha256(payload).hexdigest(),
                   original_history_sha256=digest(history_path),
                   verification_sha256=digest(verification_path),
                   remaining_gaps=['URL baseline and observation pilot identities',
                                   'pilot-only registered domains',
                                   'normalized URL history', 'structural template history',
                                   'campaign evidence; unknown is not unseen'],
                   model_fits=0, new_samples=0, human_reviews=0,
                   test_predictions_read=False)
    output.mkdir(parents=True, exist_ok=False)
    write_rows(output / 'historical_exposure_registry.jsonl', rows)
    summary['registry_sha256'] = digest(output / 'historical_exposure_registry.jsonl')
    write_json(output / 'summary.json', summary)
    return summary


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'archive', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(build(a.root, a.archive, a.output), indent=2))
