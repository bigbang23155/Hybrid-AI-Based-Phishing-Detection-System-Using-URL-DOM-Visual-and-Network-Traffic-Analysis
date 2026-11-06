"""Inventory archived evidence only; unknown modality coverage remains null."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path


def run(root):
    hashes={}
    def read(p):
        data=(root/p).read_bytes();hashes[p]=hashlib.sha256(data).hexdigest()
        return gzip.decompress(data).decode() if p.endswith('.gz') else data.decode()
    rows=[json.loads(s) for s in read('results/assignment03/holdout_v1/partition_manifest.jsonl.gz').splitlines()]
    # Historical membership metadata only; no held-out feature artifacts or predictions.
    counts=Counter((r['partition'],r['label']) for r in rows)
    exposed=[r for r in rows if r['component_pilot_exposed']]
    if len(exposed)!=464 or any(r['partition']!='train' for r in exposed):
        raise ValueError('historical_exposure_invariant_failed')
    queue=[json.loads(s) for s in read('research/robustness_v1/evidence/intake/coordinator_key.jsonl').splitlines()]
    review=json.loads(read('research/robustness_v1/evidence/review_v2/blank_import_summary.json'))
    material=json.loads(read('research/robustness_v1/evidence/review_v2/material_summary.json'))
    historical=[]
    for partition in ('train','validation','test','excluded'):
        for label in (0,1):
            n=counts[(partition,label)]
            historical.append({'partition':partition,'publisher_label':label,'rows':n,
                'paired_url_html_rows':n if partition!='excluded' else 0,
                'matched_screenshot_rows':None,'matched_http_rows':None,
                'note':'Historical A03 metadata, not a new A04 cohort. Unknown coverage is null.'})
    return {'historical_a03':historical,'forced_training':{'rows':len(exposed),
        'groups':len({r['final_group'] for r in exposed})},
        'review_queue':{'rows':len(queue),'publisher_label_counts':dict(Counter(str(r['source_label']) for r in queue)),
            'recorded_human_entries':review['recorded_human_review_entries'],
            'pending_at_archived_import':review['decision_counts']['pending'],
            'snapshots_verified_in_archive':material['snapshots_verified'],
            'exact_capture_timestamps_in_archive':material['exact_capture_timestamps'],
            'note':'Archived repository status; does not inspect unsynced human review files.'},
        'a04_cohort':{'status':'not_materialized_or_approved','class_counts':None,'coverage':None,
                      'new_test_locked':False,'training_executed':False},
        'source_sha256':hashes}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=Path('.'));p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    with a.output.open('x') as f: json.dump(run(a.root),f,indent=2);f.write('\n')
