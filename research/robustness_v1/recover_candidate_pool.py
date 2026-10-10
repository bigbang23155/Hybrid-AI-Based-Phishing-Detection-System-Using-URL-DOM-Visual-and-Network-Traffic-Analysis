"""Recover the already-inspected PhiUSIIL URL pool, not new training data."""
import argparse
from collections import Counter
import csv
import gzip
import io
import json
from pathlib import Path
import zipfile
from .intake import digest, read_rows, write_json, write_rows
from .extend_history import sha, connect, KEYS
from phishing_url.url_cleaning import clean_url, registered_domain

DELIVERY_SHA='429571a3e8764ca2136a5106b43ddde428b12b4f7f05f7de36e3fd924860cb7b'


def run(root,delivery,output):
    expected=json.loads((root/'results/assignment02/candidate_audit_20260926/audit_summary.json').read_text())
    if digest(delivery)!=DELIVERY_SHA:raise ValueError('candidate delivery checksum')
    with zipfile.ZipFile(delivery) as z: archive=z.read('inputs/phiusiil_original.zip')
    if sha(archive)!=expected['phiusiil_archive']['sha256']:raise ValueError('candidate archive checksum')
    with zipfile.ZipFile(io.BytesIO(archive)) as z:raw=z.read('PhiUSIIL_Phishing_URL_Dataset.csv')
    if sha(raw)!=expected['phiusiil_csv_sha256']:raise ValueError('candidate CSV checksum')
    prior=root/'research/robustness_v1/evidence/history_v5/historical_exposure_registry.jsonl.gz'
    rows=read_rows(prior);old_ids={r['sample_id'] for r in rows}
    count=0;invalid=Counter();source_labels=Counter();overlap=set()
    for index,r in enumerate(csv.DictReader(io.StringIO(raw.decode('utf-8-sig')))):
        count+=1;source_labels[r['label']]+=1
        item=dict(source_revision=expected['phiusiil_csv_sha256'],source_file='PhiUSIIL_Phishing_URL_Dataset.csv',
            source_row=index,exposure_origin='phiusiil_historical_inspected_candidate_pool',
            exposure_role='inspected_pool_not_selected_training',raw_url_sha256=sha(r['URL']))
        try:
            url=clean_url(r['URL']);domain=registered_domain(url)
            if not domain:raise ValueError('empty registered domain')
            item.update(sample_id=sha(url),normalized_url_sha256=sha(url),registered_domain_sha256=sha(domain))
        except ValueError as exc:
            invalid[str(exc)]+=1;item.update(sample_id='invalid-url:'+sha(r['URL']),url_status='invalid_historical_url')
        if item['sample_id'] in old_ids:overlap.add(item['sample_id'])
        rows.append(item)
    if count!=235795 or dict(source_labels)!=expected['phiusiil_original_label_counts']:
        raise ValueError('candidate pool membership mismatch')
    components,matches=connect(rows)
    for r in rows:
        # Versioned global proxy, not publisher campaign truth.
        r['suspected_campaign_component_id']=components[r['sample_id']].replace('proxy-v5:','proxy-v6:')
        r['campaign_status']='proxy_component_not_confirmed_campaign'
    output.mkdir(parents=True,exist_ok=False)
    registry=output/'historical_exposure_registry.jsonl.gz'
    with registry.open('wb') as f:
        with gzip.GzipFile(filename='',fileobj=f,mode='wb',mtime=0) as g:
            for r in rows:g.write((json.dumps(r,sort_keys=True)+'\n').encode())
    write_rows(output/'duplicate_groups.jsonl',matches)
    origins=Counter(r['exposure_origin'] for r in rows)
    coverage={origin:dict(records=number,present={k:0 for k in (*KEYS,'campaign_id')}) for origin,number in origins.items()}
    for r in rows:
        for k in (*KEYS,'campaign_id'):coverage[r['exposure_origin']]['present'][k]+=bool(r.get(k))
    write_json(output/'coverage.json',coverage)
    summary=dict(status='partial_history_unknown_campaign_not_novelty_certification',
        historical_records=len(rows),unique_sample_ids=len(components),inspected_candidate_rows=count,
        candidate_ids_already_present=len(overlap),invalid_candidate_url_reasons=dict(invalid),
        source_csv_sha256=sha(raw),source_archive_sha256=sha(archive),delivery_sha256=digest(delivery),
        previous_registry_sha256=digest(prior),registry_sha256=digest(registry),
        duplicate_groups_by_key=dict(Counter(m['match_type'] for m in matches)),
        suspected_components=len(set(components.values())),
        components_with_multiple_ids=sum(n>1 for n in Counter(components.values()).values()),
        confirmed_campaigns=0,completed_human_reviews=0,new_training_samples=0,real_model_fits=0,test_predictions_read=False,
        remaining_gaps=['Assignment01 original 4000 URL identities not recovered',
            'Earlier local failed legitimate collection raw identities not recovered',
            'URL-only histories lack archived HTML; near-template and independent campaign attribution unavailable'],
        component_interpretation='Conservative exact-key exclusion proxy only; unknown campaign is not unseen',
        attribution='Prasad and Chandra (2024), PhiUSIIL, UCI dataset 967, CC BY 4.0; retained source hashes match historical audit')
    write_json(output/'summary.json',summary);return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for n in ('root','delivery','output'):parser.add_argument('--'+n,type=Path,required=True)
    a=parser.parse_args();print(json.dumps(run(a.root,a.delivery,a.output),indent=2))
