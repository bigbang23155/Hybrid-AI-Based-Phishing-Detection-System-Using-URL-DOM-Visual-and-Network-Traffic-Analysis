"""Versioned observation records and gates; source assertions are not training labels."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

from .url_cleaning import clean_url, registered_domain


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data: bytes):
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def label_assertion(candidate_class: int, evidence: dict) -> dict:
    if type(candidate_class) is not int or candidate_class not in (0, 1):
        raise ValueError("candidate_class must be 0 or 1")
    return {"policy_version": "label-policy-v1", "project_label": None,
            "status": "assumed_benign" if candidate_class == 0 else "source_reported_phishing",
            "training_eligible": False, "review_status": "pending",
            "source_verification_time": None, "evidence": evidence}


def artifact(root: Path, path: Path, captured_at: str) -> dict:
    data = path.read_bytes()
    return {"path": str(path.relative_to(root)), "sha256": digest(data),
            "size_bytes": len(data), "captured_at": captured_at}


def validate_record(record: dict, root: Path, schema: dict) -> None:
    from jsonschema import Draft202012Validator, FormatChecker
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(record)
    if clean_url(record["url_raw"]) != record["url_clean"]:
        raise ValueError("raw/normalized URL mismatch")
    if registered_domain(record["url_clean"]) != record["domain_group"]:
        raise ValueError("domain group mismatch")
    if record['candidate_id'] != digest((record['source']+'\n'+record['url_clean']).encode()):
        raise ValueError('candidate identity mismatch')
    start=datetime.fromisoformat(record['started_at']);end=datetime.fromisoformat(record['ended_at'])
    if end < start: raise ValueError("reversed observation times")
    if record['label']['training_eligible'] or record['label']['project_label'] is not None:
        raise ValueError("raw capture must not assign adjudicated training labels")
    if record["status"] == "complete" and set(record["modalities"]) != {"url", "dom", "screenshot", "network"}:
        raise ValueError("complete observation lacks a modality")
    if record['status']=='complete' and not (record['http_status'] is not None and 200 <= record['http_status'] < 300):
        raise ValueError('complete observation requires successful HTTP status')
    for info in record["modalities"].values():
        path = (root / info["path"]).resolve()
        if not path.is_relative_to(root.resolve()): raise ValueError("artifact path escapes root")
        data=path.read_bytes()
        if digest(data) != info["sha256"] or len(data) != info["size_bytes"]:
            raise ValueError("artifact checksum/size mismatch")
        stamp=datetime.fromisoformat(info['captured_at'])
        if not start <= stamp <= end: raise ValueError("artifact timestamp outside observation")
    for name in ('url','network'):
        if name in record['modalities']:
            payload=json.loads((root/record['modalities'][name]['path']).read_text())
            if payload.get('observation_id') != record['observation_id']:
                raise ValueError('modality observation identity mismatch')
    if 'screenshot' in record['modalities']:
        if not (root/record['modalities']['screenshot']['path']).read_bytes().startswith(b'\x89PNG\r\n\x1a\n'):
            raise ValueError('screenshot is not a PNG')


def audit(root: Path, config: dict, schema: dict) -> dict:
    plan=json.loads((root/'plan.json').read_text())
    records=[json.loads(p.read_text()) for p in sorted((root/'observations').glob('*/observation.json'))]
    errors=[];ids=[]
    planned={r['candidate_id']:r for r in plan['candidates']}
    for r in records:
        ids.append(r['candidate_id'])
        try:
            validate_record(r,root,schema)
            original=planned[r['candidate_id']]
            if any(original.get(k)!=r[k] for k in ('url_clean','candidate_class','source')):
                raise ValueError('observation differs from frozen candidate plan')
        except Exception as exc: errors.append({'observation_id':r.get('observation_id'), 'error':str(exc)[:300]})
    complete=Counter(str(r['candidate_class']) for r in records if r['status']=='complete')
    preflight=json.loads((root/'preflight.json').read_text()) if (root/'preflight.json').exists() else {'passed':False}
    planned_ids={r['candidate_id'] for r in plan['candidates']}
    complete_plan=set(ids)==planned_ids and len(ids)==len(planned_ids)==config['technical_gate']['required_observations']
    technical=not errors and complete_plan and preflight.get('passed') is True and all(
        complete[str(c)] >= config['technical_gate']['min_complete_per_stratum'] for c in (0,1))
    # Raw observations are immutable; this pilot has no completed adjudication table.
    decision={'protocol_version':config['protocol_version'], 'technical_pass':technical,
              'label_gate_pass':False, 'expansion_allowed':False,
              'decision':'technical_pass_review_required' if technical else 'pilot_incomplete',
              'planned':len(plan['candidates']), 'recorded':len(records),
              'complete_by_candidate_class':dict(complete), 'schema_errors':errors,
              'status_counts':dict(Counter(r['status'] for r in records)),
              'failure_reasons':dict(Counter(r['reason'] for r in records if r['reason'])),
              'pending_label_reviews':len(records), 'all_planned_rows_present':complete_plan,
              'thresholds':config['technical_gate'], 'model_training_performed':False,
              'note':'Source assertions and HTTP/asset completeness do not adjudicate page labels. No expansion without review.'}
    write_json(root/'pilot_audit.json',decision)
    queue=[{'observation_id':r['observation_id'], 'candidate_id':r['candidate_id'],
            'candidate_class':r['candidate_class'], 'capture_status':r['status'],
            'review_status':'pending', 'reviewer_id':None, 'reviewer_type':None,
            'decision':None, 'reason':None, 'evidence':r['modalities']} for r in records]
    write_json(root/'label_review_queue.json',queue)
    return decision
