"""Complete recoverable URL/template history and prepare campaign proxies.

Campaign components are conservative leakage proxies built from domain, URL,
exact HTML and structural equality. They are not confirmed campaigns.
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
from phishing_url.formal_html import frozen_candidates, selected_html, inspect_html
from phishing_url.url_cleaning import clean_url, registered_domain


def sha(value): return hashlib.sha256(value).hexdigest()


def observation_rows(delivery):
    with zipfile.ZipFile(delivery) as outer:
        raw=outer.read('pilot_delivery/original_artifacts/pilot_capture_36289927306.zip')
    rows=[]
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        checks=json.loads(archive.read('CHECKSUMS.json'))
        for name,expected in checks.items():
            if sha(archive.read(name))!=expected: raise ValueError('observation v1 checksum mismatch')
        for name in sorted(archive.namelist()):
            if not name.endswith('/observation.json'): continue
            r=json.loads(archive.read(name));url=clean_url(r['url_clean'])
            out=dict(sample_id=r['observation_id'],normalized_url_sha256=sha(url.encode()),
                     registered_domain_sha256=sha(registered_domain(url).encode()),
                     exposure_origin='observation_pilot_v1',historical_capture_status=r['status'],
                     suspected_campaign_component_id='observation-v1:'+r['observation_id'],
                     campaign_status='unknown_no_independent_campaign_evidence')
            dom=r.get('modalities',{}).get('dom')
            if dom and dom.get('path'):
                html=archive.read(dom['path'])
                if sha(html)!=dom['sha256']:raise ValueError('observation v1 DOM mismatch')
                out['html_sha256']=sha(html);parsed=inspect_html(html.decode('utf-8'),url,2097152)
                if (parsed.get('tag_count') or 0)>=20:out['structural_sha256']=parsed['structural_tag_sequence_sha256']
            rows.append(out)
    if len(rows)!=16:raise ValueError('observation v1 membership mismatch')
    return rows,sha(raw),len(checks)


def run(root,source_root,observation_delivery,output):
    previous=root/'research/robustness_v1/evidence/history_v3/historical_exposure_registry.jsonl.gz'
    rows=read_rows(previous)
    manifest={r['sample_id']:r for r in read_rows(root/'results/assignment03/holdout_v1/partition_manifest.jsonl.gz')}
    chosen,frame,policy,_,_=frozen_candidates(source_root,root/'config/assignment03_paired_source_frame_v1.json',
        root/'config/assignment03_paired_release_policy_v1.json',root/'config/assignment03_formal_candidate_freeze_v1.json')
    if len(chosen)!=5000 or set(manifest)!={r['sample_id'] for r in chosen}:raise ValueError('formal membership mismatch')
    sources={r['sample_id']:r for r in chosen};seen=set();formal=[]
    for sid,html in selected_html(source_root,frame,chosen):
        if sid in seen:raise ValueError('duplicate formal payload')
        seen.add(sid);s=sources[sid];m=manifest[sid];parsed=inspect_html(html,s['url_clean'],policy['content']['max_html_bytes'])
        if sha(html.encode())!=m['html_sha256']:raise ValueError('formal HTML mismatch')
        r=dict(sample_id=sid,registered_domain_sha256=m['registered_domain_sha256'],
               normalized_url_sha256=sha(s['url_clean'].encode()),html_sha256=m['html_sha256'],
               final_group=m['final_group'],source_revision=frame['revision'],source_file=m['source_file'],
               source_row=m['source_row'],exposure_origin='formal_candidate_enriched',
               suspected_campaign_component_id='formal:'+(m['final_group'] or 'excluded-'+sid),
               campaign_status='proxy_component_not_confirmed_campaign')
        if (parsed.get('tag_count') or 0)>=20:r['structural_sha256']=parsed['structural_tag_sequence_sha256']
        formal.append(r)
    if seen!=set(manifest):raise ValueError('missing formal payload')
    obs,obs_hash,obs_members=observation_rows(observation_delivery)
    rows.extend(formal);rows.extend(obs)
    output.mkdir(parents=True,exist_ok=False);registry=output/'historical_exposure_registry.jsonl.gz'
    registry.write_bytes(gzip.compress(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows).encode(),mtime=0))
    keys=['sample_id','registered_domain_sha256','normalized_url_sha256','html_sha256','structural_sha256','campaign_id','suspected_campaign_component_id']
    summary=dict(status='recoverable_history_complete_campaign_truth_unavailable',historical_records=len(rows),
                 formal_candidates_enriched=len(formal),observation_v1_records=len(obs),
                 present_records={k:sum(bool(r.get(k)) for r in rows) for k in keys},
                 unique_values={k:len({r[k] for r in rows if r.get(k)}) for k in keys},
                 previous_registry_sha256=digest(previous),registry_sha256=digest(registry),
                 source_revision=frame['revision'],observation_v1_artifact_sha256=obs_hash,
                 verified_observation_v1_members=obs_members,
                 campaign_interpretation='suspected components prevent leakage but cannot establish operator, kit, family, or unseen campaign',
                 remaining_gaps=['Assignment01 snapshot bytes unavailable; its 4,000 selected URL identities are described but not recoverable here',
                                 'independent campaign/kit/operator annotations absent'],
                 new_samples=0,human_reviews=0,real_model_fits=0,test_predictions_read=False)
    write_json(output/'summary.json',summary);return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('root','source-root','observation-delivery','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();print(json.dumps(run(a.root,a.source_root,a.observation_delivery,a.output),indent=2))
