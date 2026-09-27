"""Audit and freeze an explicitly historical original-URL benchmark; no live visits."""
from __future__ import annotations
import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from .ingestion import ParsedRow
from .prepare import prepare_dataset
from .randomness import load_seed_plan
from .url_cleaning import clean_url, registered_domain


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n')


def read_originals(root, specification):
    rows=[]
    for source in specification['sources']:
        path=root/source['filename']
        if sha(path)!=source['sha256']:raise ValueError('original source checksum mismatch')
        data=json.loads(path.read_text())
        if not isinstance(data,list) or not all(isinstance(x,str) for x in data):
            raise ValueError('expected original URL string array')
        rows.extend(ParsedRow(source['source'],source['label'],i,url) for i,url in enumerate(data,1))
    return rows


def profile(frame):
    result={}
    for label,part in frame.groupby('label'):
        parsed=part.url_clean.map(urlsplit);groups=part.registered_domain.value_counts()
        result[str(label)]={'rows':len(part),'domains':len(groups),
            'largest_domain_share':float(groups.iloc[0]/len(part)),
            'top10_domain_share':float(groups.iloc[:10].sum()/len(part)),
            'domain_hhi':float(((groups/len(part))**2).sum()),
            'https_rate':float(parsed.map(lambda p:p.scheme=='https').mean()),
            'inner_page_rate':float(parsed.map(lambda p:p.path not in ('','/')).mean()),
            'query_rate':float(parsed.map(lambda p:bool(p.query)).mean())}
        for name,values in [('url',part.url_clean.str.len()),('path',parsed.map(lambda p:len(p.path))),('query',parsed.map(lambda p:len(p.query)))]:
            result[str(label)][name+'_length']=values.quantile([0,.05,.25,.5,.75,.95,.99,1]).to_dict()
    return result


def audit(root, output, specification):
    if output.exists():raise FileExistsError('audit output already exists')
    output.mkdir(parents=True)
    rows=read_originals(root,specification);valid=[];invalid=[]
    for row in rows:
        try:
            u=clean_url(row.url_raw)
            valid.append({'url_raw':row.url_raw,'url_clean':u,'label':row.label,'source':row.source,
                          'source_row':row.row_number,'registered_domain':registered_domain(u)})
        except ValueError as exc:invalid.append({**asdict(row),'reason':str(exc)})
    frame=pd.DataFrame(valid)
    conflicts=frame.groupby('url_clean').label.nunique().loc[lambda s:s>1].index
    conflict_rows=frame[frame.url_clean.isin(conflicts)]
    pool=frame[~frame.url_clean.isin(conflicts)].sort_values(['url_clean','source','url_raw','source_row']).drop_duplicates('url_clean')
    counts=pool.groupby('label').size();domains=pool.groupby('label').registered_domain.nunique()
    checks={'original_url_text':True,'explicit_published_binary_labels':True,
      'enough_rows':all(counts.get(l,0)>=specification['target_per_label'] for l in (0,1)),
      'domain_diversity_heuristic':all(domains.get(l,0)>=specification['min_domains_per_class_heuristic'] for l in (0,1))}
    suitability=all(checks.values())
    result={'dataset_id':specification['dataset_id'],'raw_rows':len(rows),'valid_rows':len(frame),
        'invalid_rows':len(invalid),'invalid_reasons':dict(Counter(r['reason'] for r in invalid)),
        'exact_duplicate_rows':int(frame.duplicated(['url_raw','label']).sum()),
        'normalized_duplicate_rows':int(frame.duplicated(['url_clean','label']).sum()),
        'conflicting_normalized_urls':len(conflicts),'conflicting_rows_removed':len(conflict_rows),
        'mixed_label_domains':int((pool.groupby('registered_domain').label.nunique()>1).sum()),
        'profiles':profile(pool),'checks':checks,
        'decision':'suitable_for_historical_source_label_baseline_only' if suitability else 'unsuitable',
        'suitable_for_2026_or_multimodal_claims':False,'limitations':specification['limitations'],
        'source_config_sha256':hashlib.sha256(json.dumps(specification,sort_keys=True).encode()).hexdigest()}
    pool.to_csv(output/'eligible_urls.csv',index=False)
    pd.DataFrame(invalid).to_csv(output/'invalid_rows.csv',index=False)
    conflict_rows.to_csv(output/'conflicts.csv',index=False)
    frame[frame.duplicated(['url_clean','label'],keep=False)].to_csv(output/'duplicate_rows.csv',index=False)
    pool.groupby(['label','registered_domain']).size().rename('url_count').to_csv(output/'domain_concentration.csv')
    write(output/'audit.json',result)
    write(output/'source_specification.json',specification)
    return result


def freeze(root, audited, output, specification, seed_path):
    if output.exists():raise FileExistsError('frozen dataset already exists')
    audit_result=json.loads((audited/'audit.json').read_text())
    if audit_result['decision']!='suitable_for_historical_source_label_baseline_only':raise ValueError('audit gate not passed')
    if audit_result['source_config_sha256']!=hashlib.sha256(json.dumps(specification,sort_keys=True).encode()).hexdigest():
        raise ValueError('source configuration changed after audit')
    seeds=load_seed_plan(seed_path);rows=read_originals(root,specification)
    prepared=prepare_dataset(rows,specification['target_per_label'],seeds['sampling_seed'])
    replay=prepare_dataset(list(reversed(rows)),specification['target_per_label'],seeds['sampling_seed'])
    if prepared.records!=replay.records:raise ValueError('sampling depends on input order')
    if prepared.sampling_manifest['shortfall']:raise ValueError('class shortfall; no replacements allowed')
    output.mkdir(parents=True)
    frame=pd.DataFrame([r.as_dict() for r in prepared.records]);frame.to_csv(output/'urls.csv',index=False)
    pd.DataFrame([asdict(r) for r in prepared.rejected_records]).to_csv(output/'excluded_or_not_sampled.csv',index=False)
    pd.DataFrame(prepared.source_summary).to_csv(output/'source_summary.csv',index=False)
    pd.DataFrame(prepared.cleaning_summary).to_csv(output/'cleaning_summary.csv',index=False)
    write(output/'seed_plan.json',seeds)
    selected=set(frame.url_clean)
    provenance=pd.read_csv(audited/'eligible_urls.csv',keep_default_na=False)
    provenance[provenance.url_clean.isin(selected)].to_csv(output/'row_provenance.csv',index=False)
    write(output/'frozen_manifest.json',{'dataset_id':specification['dataset_id'],
        'scope':'historical URL-only source-label baseline; not the final prospective Hybrid dataset',
        'label_semantics':specification['label_semantics'],'dataset_sha256':sha(output/'urls.csv'),
        'audit_sha256':sha(audited/'audit.json'),'source_config_sha256':audit_result['source_config_sha256'],
        'seed_plan_sha256':sha(seed_path),'sampling':prepared.sampling_manifest,
        'order_invariance_verified':True,'profiles':profile(frame),
        'source_files':specification['sources'],'limitations':specification['limitations']})


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['audit','freeze'])
    p.add_argument('--raw',type=Path,required=True);p.add_argument('--config',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--audit',type=Path);p.add_argument('--seed-plan',type=Path)
    a=p.parse_args();spec=json.loads(a.config.read_text())
    if a.command=='audit':print(json.dumps(audit(a.raw,a.output,spec),indent=2))
    else:freeze(a.raw,a.audit,a.output,spec,a.seed_plan)


if __name__=='__main__':main()
