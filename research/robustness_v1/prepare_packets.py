"""Reconstruct queued historical development snapshots; passive checks only."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from .intake import read_rows, write_rows, write_json, digest
from phishing_url.formal_html import frozen_candidates, selected_html, inspect_html
from phishing_url.dom_features import extract_dom_features

COUNTERS=('tag_count','form_count','input_count','password_input_count','script_count','iframe_count')


def inspect_packet(queued, source, html, maximum):
    if not isinstance(html,str) or hashlib.sha256(html.encode()).hexdigest()!=queued['html_sha256']:
        raise ValueError('snapshot identity mismatch')
    audit=inspect_html(html,source['url_clean'],maximum)
    features=extract_dom_features(html,source['url_clean'])
    disagreements=[k for k in COUNTERS if audit[k]!=features[k]]
    return dict(review_id=queued['review_id'],sample_id=queued['sample_id'],html_sha256=queued['html_sha256'],
                status='technical_checks_passed' if audit['parse_status']=='parsed_markup' and not disagreements else 'requires_technical_review',
                counter_disagreements=disagreements,
                counters={k:features[k] for k in COUNTERS},
                flags={k:audit[k] for k in ('challenge_marker','access_error_marker','parking_marker','low_static_content_flag')},
                source_date_present=bool(source.get('capture_date')),source_language_present=bool(source.get('lang')),
                label_status='not_independently_adjudicated')


def run(root, source_root, queue_path, output):
    queue=read_rows(queue_path);lookup={r['sample_id']:r for r in queue}
    if len(lookup)!=len(queue):raise ValueError('duplicate queued ID')
    manifest=read_rows(root/'results/assignment03/holdout_v1/partition_manifest.jsonl.gz')
    allowed={r['sample_id']:r for r in manifest if r['partition'] in ('train','validation')}
    if not set(lookup)<=set(allowed):raise ValueError('test or excluded sample in review queue')
    for sid,row in lookup.items():
        if any(row[k]!=allowed[sid][k] for k in ('html_sha256','source_file','source_row')):
            raise ValueError('queue binding mismatch')
    chosen,frame,policy,_,_=frozen_candidates(source_root,root/'config/assignment03_paired_source_frame_v1.json',
        root/'config/assignment03_paired_release_policy_v1.json',root/'config/assignment03_formal_candidate_freeze_v1.json')
    selected=[r for r in chosen if r['sample_id'] in lookup];sources={r['sample_id']:r for r in selected}
    if set(sources)!=set(lookup):raise ValueError('source membership mismatch')
    output.mkdir(parents=True,exist_ok=False)
    private=output/'private';private.mkdir();(private/'snapshots').mkdir()
    public=output/'public';public.mkdir()
    checks=[];packets=[];seen=set()
    for sid,html in selected_html(source_root,frame,selected):
        if sid in seen:raise ValueError('duplicate payload')
        seen.add(sid)
        q=lookup[sid];s=sources[sid]
        try:
            result=inspect_packet(q,s,html,policy['content']['max_html_bytes'])
            path=private/'snapshots'/(q['review_id']+'.html.txt');path.write_text(html)
            # Evidence and human reviews intentionally empty. Date is publisher metadata,
            # not invented as a more precise capture timestamp.
            packets.append(dict(review_id=q['review_id'],sample_id=sid,html_sha256=q['html_sha256'],
                                url=s['url_clean'],publisher_date=s.get('capture_date'),language=s.get('lang'),
                                snapshot_path='snapshots/'+path.name,evidence=[],reviews=[],
                                scope='historical_development_audit'))
        except (ValueError,TypeError,UnicodeError) as exc:
            result=dict(sample_id=sid,status='failed',reason=type(exc).__name__+':'+str(exc))
        checks.append(result)
    for sid in sorted(set(lookup)-seen):checks.append(dict(sample_id=sid,status='missing_payload'))
    write_rows(private/'packets_blinded.jsonl',packets)
    write_rows(public/'technical_checks.jsonl',sorted(checks,key=lambda r:r['sample_id']))
    summary=dict(status='snapshot_preparation_completed',queued=len(queue),materialized=len(packets),
                 statuses=dict(Counter(r['status'] for r in checks)),
                 flags=dict(Counter(k for r in checks for k,v in r.get('flags',{}).items() if v)),
                 reviewed_labels=0,new_samples=0,model_fits=0,test_html_selected=0,
                 queue_sha256=digest(queue_path),source_revision=frame['revision'],
                 crosscheck_limit='Two count implementations share Python HTMLParser; this checks implementation consistency, not independent content truth.',
                 marker_limit='Markers and password inputs are review triggers, not labels; publisher date is not necessarily capture time.')
    if any(r['status']!='technical_checks_passed' for r in checks):summary['status']='blocked_technical_review'
    write_json(public/'summary.json',summary)
    print(json.dumps(summary,indent=2))
    if summary['status'].startswith('blocked'):raise ValueError('snapshot preparation has retained failures/disagreements')
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','source-root','queue','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();run(a.root,a.source_root,a.queue,a.output)
