"""Replay missing pilot identities and audit cross-source exact leakage links.

No label inference, live URL requests, model fitting, or test predictions.
Components are conservative exclusion proxies, never campaign attribution.
"""
import argparse
from collections import Counter, defaultdict
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import zipfile
from .intake import digest, read_rows, write_json, write_rows
from phishing_url.formal_holdout import verify_pilot
from phishing_url.url_cleaning import clean_url, registered_domain

SUPPLEMENT_SHA = '7ae33290b473e233e11dd8b4184b23b1b4edffdee5edc864807e1f7b7b108ffd'
KEYS = ('normalized_url_sha256', 'registered_domain_sha256', 'html_sha256', 'structural_sha256')


def sha(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def collection_rows(path):
    if digest(path) != SUPPLEMENT_SHA:
        raise ValueError('supplement archive checksum mismatch')
    records = []
    with zipfile.ZipFile(path) as z:
        checks = json.loads(z.read('CHECKSUMS.json'))
        for name, expected in checks.items():
            if sha(z.read(name)) != expected:
                raise ValueError('supplement member checksum mismatch')
        def csv_rows(name):
            if name not in checks:
                raise ValueError('unbound archive member')
            return list(csv.DictReader(io.StringIO(z.read(name).decode('utf-8-sig'))))
        files = {
            'batch2/combined/observed_legitimate_urls.csv': ('legitimate_collection_combined', 2643),
            'prior/data/collection/cloud_diagnostic/observed_legitimate_urls.csv': ('legitimate_collection_diagnostic', 16),
        }
        for name, (origin, count) in files.items():
            source = csv_rows(name)
            if len(source) != count:
                raise ValueError('collection membership mismatch')
            for index, row in enumerate(source):
                url = clean_url(row['url_clean'])
                if url != row['url_clean']:
                    raise ValueError('collection normalization drift')
                records.append(dict(sample_id=sha(url), normalized_url_sha256=sha(url),
                    registered_domain_sha256=sha(registered_domain(url)),
                    exposure_origin=origin, source_revision=SUPPLEMENT_SHA,
                    source_file=name, source_row=index,
                    campaign_status='unknown_no_independent_campaign_evidence'))
                # Evidence URLs were also inspected by the historical collector.
                evidence_url = clean_url(row['evidence_url'])
                if evidence_url != url:
                    records.append(dict(sample_id=sha(evidence_url), normalized_url_sha256=sha(evidence_url),
                        registered_domain_sha256=sha(registered_domain(evidence_url)),
                        exposure_origin=origin+'_evidence_url', source_revision=SUPPLEMENT_SHA,
                        source_file=name+':evidence_url', source_row=index))
        for name, count in [('batch2/original_candidates.csv',1200), ('batch2/supplement_candidates.csv',600)]:
            source = csv_rows(name)
            if len(source) != count:
                raise ValueError('candidate membership mismatch')
            for index, row in enumerate(source):
                domain = registered_domain(clean_url('https://'+row['domain']+'/'))
                records.append(dict(sample_id='domain-only:'+sha(domain), registered_domain_sha256=sha(domain),
                    exposure_origin='legitimate_collection_attempted_domain', source_revision=SUPPLEMENT_SHA,
                    source_file=name, source_row=index, identity_kind='domain_only_no_observed_url'))
        # Diagnostic failures are historical exposure too, without inventing URLs.
        name = 'prior/data/collection/cloud_diagnostic/collection_failures.csv'
        domains = sorted({r['candidate_domain'] for r in csv_rows(name)})
        for domain in domains:
            normalized = registered_domain(clean_url('https://'+domain+'/'))
            records.append(dict(sample_id='domain-only:'+sha(normalized), registered_domain_sha256=sha(normalized),
                exposure_origin='legitimate_diagnostic_attempted_domain', source_revision=SUPPLEMENT_SHA,
                source_file=name, identity_kind='domain_only_no_observed_url'))
    return records, len(checks)


def connect(rows):
    """Merge equal keys transitively across all provenance rows and sample IDs."""
    parent = {r['sample_id']: r['sample_id'] for r in rows}
    def root(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    indexes = {k: defaultdict(set) for k in KEYS}
    for row in rows:
        for key in KEYS:
            if row.get(key):
                indexes[key][row[key]].add(row['sample_id'])
    for index in indexes.values():
        for ids in index.values():
            ordered = sorted(ids)
            for sid in ordered[1:]:
                a,b = root(ordered[0]),root(sid)
                parent[max(a,b)] = min(a,b)
    groups = defaultdict(list)
    for sid in sorted(parent):
        groups[root(sid)].append(sid)
    components = {sid: 'proxy-v5:'+sha('\n'.join(ids)) for ids in groups.values() for sid in ids}
    matches = [dict(match_type=key, identity_sha256=value, sample_ids=sorted(ids),
                    distinct_sample_ids=len(ids))
               for key,index in indexes.items() for value,ids in sorted(index.items()) if len(ids)>1]
    return components, matches


def run(root, pilot, supplement, output):
    previous = root/'research/robustness_v1/evidence/history_v4/historical_exposure_registry.jsonl.gz'
    rows = read_rows(previous)
    pilot_rows, verification = verify_pilot(pilot, root/'results/assignment03/dom_data_pilot_v1/verification.json',20)
    old_pilot = {r['sample_id']:r for r in rows if r['exposure_origin']=='dom_pilot'}
    if set(old_pilot) != {r['sample_id'] for r in pilot_rows}:
        raise ValueError('pilot/history membership mismatch')
    for p in pilot_rows:
        r = old_pilot[p['sample_id']]
        if r['html_sha256'] != p['html_sha256']:
            raise ValueError('pilot/history HTML mismatch')
        r.update(normalized_url_sha256=sha(p['url_clean']), registered_domain_sha256=sha(p['registered_domain']),
                 campaign_status='unknown_no_independent_campaign_evidence')
        if (p.get('tag_count') or 0)>=20 and p.get('structural_tag_sequence_sha256'):
            r['structural_sha256'] = p['structural_tag_sequence_sha256']
    new, members = collection_rows(supplement)
    rows.extend(new)
    components, matches = connect(rows)
    for row in rows:
        if row.get('suspected_campaign_component_id'):
            row['prior_suspected_campaign_component_id'] = row['suspected_campaign_component_id']
        row['suspected_campaign_component_id'] = components[row['sample_id']]
        row['campaign_status'] = 'proxy_component_not_confirmed_campaign'
    origins = defaultdict(set)
    for row in rows:
        origins[row['sample_id']].add(row['exposure_origin'])
    for match in matches:
        match['exposure_origins'] = sorted(set().union(*(origins[s] for s in match['sample_ids'])))
    coverage = {origin:dict(records=len(rs), unique_sample_ids=len({r['sample_id'] for r in rs}),
                 present={k:sum(bool(r.get(k)) for r in rs) for k in (*KEYS,'campaign_id')})
                for origin in sorted({r['exposure_origin'] for r in rows})
                for rs in [[r for r in rows if r['exposure_origin']==origin]]}
    output.mkdir(parents=True,exist_ok=False)
    registry = output/'historical_exposure_registry.jsonl.gz'
    registry.write_bytes(gzip.compress(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows).encode(),mtime=0))
    write_rows(output/'duplicate_groups.jsonl',matches)
    write_json(output/'coverage.json',coverage)
    summary = dict(status='partial_history_unknown_campaign_not_novelty_certification',
        historical_records=len(rows),unique_sample_ids=len(components),
        dom_pilot_enriched=len(pilot_rows),dom_pilot_verification=verification,
        added_collection_records=len(new), verified_supplement_members=members,
        supplement_sha256=digest(supplement),previous_registry_sha256=digest(previous),registry_sha256=digest(registry),
        duplicate_groups_by_key=dict(Counter(m['match_type'] for m in matches)),
        suspected_components=len(set(components.values())),
        components_with_multiple_ids=sum(n>1 for n in Counter(components.values()).values()),
        confirmed_campaigns=0,completed_human_reviews=0,new_training_samples=0,real_model_fits=0,test_predictions_read=False,
        remaining_gaps=['Assignment01 original 4000 URLs not recovered',
            'Earlier local failed collection identities and inspected PhiUSIIL candidate pool not recovered in this registry',
            'URL-only histories have no archived HTML; template absence is unknown, not negative',
            'Near-template similarity and independent campaign/kit/operator attribution remain unverified'],
        component_interpretation='Equality-based conservative leakage proxy; broad shared templates/domains may overgroup; no campaign attribution')
    write_json(output/'summary.json',summary)
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for n in ('root','pilot','supplement','output'):parser.add_argument('--'+n,type=Path,required=True)
    a=parser.parse_args()
    print(json.dumps(run(a.root,a.pilot,a.supplement,a.output),indent=2))
