"""Append-only evidence-linked review input and derived labels; never edit raw captures."""
from __future__ import annotations
import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from collections import Counter
from jsonschema import Draft202012Validator, FormatChecker


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def records(root):
    return {r['observation_id']:r for r in (json.loads(p.read_text()) for p in (root/'observations').glob('*/observation.json'))}


def validate_review(review, observations):
    schema=json.loads((Path(__file__).resolve().parents[2]/'schemas/label_review_v1.schema.json').read_text())
    Draft202012Validator(schema,format_checker=FormatChecker()).validate(review)
    original=observations[review['observation_id']]
    if review['source_assertion']!=original['label']['status']:raise ValueError('source assertion mismatch')
    if datetime.fromisoformat(review['reviewed_at'])<datetime.fromisoformat(original['ended_at']):raise ValueError('review predates capture')
    if datetime.fromisoformat(review['reviewed_at']).timestamp()>__import__('time').time()+300:raise ValueError('review timestamp is in the future')
    available={v['path']:v['sha256'] for v in original['modalities'].values()}
    if not review['evidence'] or any(available.get(e['path'])!=e['sha256'] for e in review['evidence']):
        raise ValueError('review evidence does not match immutable observation')
    if review['decision'] in ('benign','phishing'):
        if original['status']!='complete':raise ValueError('incomplete capture cannot receive a final class label')
        required={original['modalities'][name]['path'] for name in ('dom','screenshot')}
        if not required.issubset({e['path'] for e in review['evidence']}):raise ValueError('class decision requires DOM and screenshot evidence')


def append(root, review):
    observations=records(root);validate_review(review,observations)
    from .observation import validate_record
    original=observations[review['observation_id']]
    schema_path=Path(__file__).resolve().parents[2]/'schemas'/('observation_v2.schema.json' if original['schema_version']=='observation-v2' else 'observation_v1.schema.json')
    validate_record(original,root,json.loads(schema_path.read_text()))
    identifier=hashlib.sha256(canonical(review)).hexdigest();folder=root/'reviews';folder.mkdir(exist_ok=True)
    path=folder/(identifier+'.json')
    if path.exists():
        if json.loads(path.read_text())!=review:raise ValueError('review identity collision')
        return identifier
    with path.open('x') as f:f.write(json.dumps(review,indent=2)+'\n')
    return identifier


def derive_labels(root):
    observations=records(root);reviews=[]
    from .observation import validate_record
    schemas={}
    for original in observations.values():
        version=original['schema_version']
        if version not in schemas:
            name='observation_v2.schema.json' if version=='observation-v2' else 'observation_v1.schema.json'
            schemas[version]=json.loads((Path(__file__).resolve().parents[2]/'schemas'/name).read_text())
        validate_record(original,root,schemas[version])
    for p in sorted((root/'reviews').glob('*.json')):
        review=json.loads(p.read_text());validate_review(review,observations)
        if hashlib.sha256(canonical(review)).hexdigest()!=p.stem:raise ValueError('review hash mismatch')
        reviews.append((p.stem,review))
    table=[]
    for oid,original in observations.items():
        human=[(key,r) for key,r in reviews if r['observation_id']==oid and r['reviewer_type']=='human']
        decisions={r['decision'] for _,r in human};label=None
        status='pending'
        if len(decisions)>1:status='conflicting'
        elif decisions:
            decision=next(iter(decisions));status=decision
            if decision in ('benign','phishing'):label=int(decision=='phishing')
        table.append({'observation_id':oid,'status':status,'project_label':label,'training_eligible':label is not None,
            'review_ids':[key for key,_ in human],'reviewer_identity':'self-declared named human, not independently authenticated'})
    result={'pending':sum(r['status']=='pending' for r in table),'conflicting':sum(r['status']=='conflicting' for r in table),
        'label_counts':dict(Counter(str(r['project_label']) for r in table if r['project_label'] is not None)),
        'all_reviewed':bool(table) and all(r['status'] not in ('pending','conflicting') for r in table),
        'two_adjudicated_classes':{r['project_label'] for r in table if r['project_label'] is not None}=={0,1},
        'labels':table,'policy':'Raw observations unchanged; automated reviews never assign training labels; disagreements remain excluded.'}
    (root/'derived_labels.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['append','derive'])
    p.add_argument('--root',type=Path,required=True);p.add_argument('--input',type=Path)
    a=p.parse_args()
    if a.command=='append':print(append(a.root,json.loads(a.input.read_text())))
    else:print(json.dumps({k:v for k,v in derive_labels(a.root).items() if k!='labels'},indent=2))


if __name__=='__main__':main()
