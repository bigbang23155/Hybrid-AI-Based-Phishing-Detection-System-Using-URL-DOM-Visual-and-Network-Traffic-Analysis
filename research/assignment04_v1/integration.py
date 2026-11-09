"""Verified checkpoint adapter, aggregate inventory and evidence-only demo.

All operations reject test partitions and preserve training ineligibility.
This is application-level protection, not OS access control.
"""
import argparse
import copy
import hashlib
import html
import json
from pathlib import Path
from research.multimodal_v1.contract import assemble, fusion_view, modality, unavailable_features
from . import visual


def reject_test(record):
    if record.get('partition') not in (None, 'train', 'validation', 'development'):
        raise ValueError('test_or_unknown_partition_forbidden')
    if record.get('scope') not in ('smoke_test', 'historical_development_audit'):
        raise ValueError('nondevelopment_scope_forbidden')


def upgrade(checkpoint, *, as_of, max_age_seconds):
    # Inspect declared scope before opening screenshot / DOM / HTTP artifacts.
    path = Path(checkpoint)
    if path.is_symlink() or path.stat().st_size > 1_000_000:
        raise ValueError('invalid_checkpoint')
    raw = json.loads(path.read_text())
    reject_test(raw)
    from research.multimodal_v1.adapters import from_checkpoint, read_artifact
    record = from_checkpoint(path, as_of=as_of, max_age_seconds=max_age_seconds, run_yara=False)
    old = record['modalities']['visual']
    features = unavailable_features(visual.VERSION, visual.NAMES, 'visual_evidence_unavailable')
    extraction = 'unavailable'
    audit = None
    if old['acquisition_status'] == 'available' and old['extraction_status'] in ('ok', 'partial'):
        try:
            _, data = read_artifact(path.parent, raw['artifacts']['screenshot'])
            features = visual.extract(data)
            audit = features.pop('audit')
            extraction = 'ok'
        except (ValueError, OSError):
            features = unavailable_features(visual.VERSION, visual.NAMES, 'visual_extraction_failed')
            extraction = 'failed'
    record['modalities']['visual'] = modality('visual', features,
        acquisition=old['acquisition_status'], extraction=extraction,
        temporal=old['temporal'], provenance=old['provenance'],
        reasons=old['reasons'], quality_flags=['handcrafted_descriptor_not_semantic_embedding'])
    output = assemble(record['item_id'], record['modalities'], scope=record['scope'])
    output['partition'] = raw.get('partition')
    output['visual_audit'] = audit
    output['checkpoint_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    return output


def validate(record):
    reject_test(record)
    if record.get('eligible_for_training') is not False or record.get('label') is not None:
        raise ValueError('label_adoption_or_training_not_supported')
    checked = assemble(record['item_id'], copy.deepcopy(record['modalities']), scope=record['scope'])
    for name in checked['modalities']:
        if checked['modalities'][name] != record['modalities'][name]:
            raise ValueError('inconsistent_serialized_masks')
    # Same-scan and source provenance for acquired evidence must agree.
    aligned = [m['provenance'] for n,m in checked['modalities'].items()
               if n != 'url' and m['acquisition_status'] == 'available']
    for key in ('checkpoint_sha256', 'scan_uuid'):
        values = [p.get(key) for p in aligned]
        if any(not v for v in values) or len(set(values)) > 1:
            raise ValueError('unaligned_evidence')
    times = [m['temporal']['captured_at'] for n,m in checked['modalities'].items()
             if n != 'url' and m['acquisition_status'] == 'available']
    if len(set(times)) > 1:
        raise ValueError('unaligned_capture_times')
    return checked


def inventory(records):
    seen, buckets, schemas = set(), {}, {}
    for record in records:
        checked = validate(record)
        if checked['item_id'] in seen:
            raise ValueError('duplicate_item_id')
        seen.add(checked['item_id'])
        # Source assertions are optional metadata, NEVER adopted labels.
        label = record.get('source_label')
        if label is not None and (type(label) is not int or label not in (0,1)):
            raise ValueError('invalid_source_assertion')
        bucket = buckets.setdefault(str(label) if label is not None else 'unknown',
            {'attempted': 0, 'all_four_usable': 0, 'modalities': {}})
        bucket['attempted'] += 1
        bucket['all_four_usable'] += int(all(m['modality_usable_mask'] for m in checked['modalities'].values()))
        for name, m in checked['modalities'].items():
            signature = (m['features']['registry_version'], tuple(m['features']['feature_order']))
            if name in schemas and schemas[name] != signature:
                raise ValueError('mixed_feature_schemas')
            schemas[name] = signature
            counts = bucket['modalities'].setdefault(name, {'available':0, 'usable':0, 'states':{}})
            counts['available'] += m['modality_available_mask']
            counts['usable'] += m['modality_usable_mask']
            state = '/'.join([m['acquisition_status'], m['extraction_status'], m['temporal']['status']])
            counts['states'][state] = counts['states'].get(state, 0) + 1
    return {'attempted': len(seen), 'by_source_assertion_not_adjudicated_label': buckets,
            'training_eligible': 0, 'test_evaluated': False,
            'note': 'Usable means at least one usable feature, not complete coverage or label validity.'}


def evidence_demo(record):
    checked = validate(record)
    rows = ''.join('<tr><td>'+html.escape(n)+'</td><td>'+html.escape(m['acquisition_status'])+
        '</td><td>'+html.escape(m['extraction_status'])+'</td><td>'+html.escape(m['temporal']['status'])+
        '</td><td>'+str(sum(m['usable_mask'].values()))+'/'+str(len(m['usable_mask']))+'</td></tr>'
        for n,m in checked['modalities'].items())
    return '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>A04 evidence preview</title><style>body{font:18px system-ui;max-width:900px;margin:50px auto;padding:20px;color:#182b42}td,th{padding:14px;text-align:left;border-bottom:1px solid #ddd}table{border-collapse:collapse}.table-scroll{overflow-x:auto;max-width:100%}@media(max-width:600px){body{margin:16px auto;padding:12px;font-size:16px}td,th{padding:10px}}</style><h1>Multimodal evidence preview</h1><p><b>Prediction unavailable: no approved trained multimodal model.</b></p><p>Engineering preview only. Labels remain pending; test evaluation is disabled.</p><div class="table-scroll"><table><tr><th>Modality</th><th>Acquisition</th><th>Extraction</th><th>Freshness</th><th>Usable fields</th></tr>'+rows+'</table></div>'


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('extract'); p.add_argument('--checkpoint', required=True)
    p.add_argument('--as-of', required=True); p.add_argument('--max-age-seconds', type=float, required=True)
    p.add_argument('--output', required=True)
    for cmd in ('inventory','demo','fusion'):
        p = sub.add_parser(cmd); p.add_argument('--input', required=True); p.add_argument('--output', required=True)
    args = parser.parse_args()
    if args.command == 'extract':
        value = upgrade(args.checkpoint, as_of=args.as_of, max_age_seconds=args.max_age_seconds)
        content = json.dumps(value, indent=2, allow_nan=False)
    else:
        records = [json.loads(line) for line in Path(args.input).read_text().splitlines() if line.strip()] if args.command == 'inventory' else [json.loads(Path(args.input).read_text())]
        if args.command == 'inventory': value = inventory(records)
        elif args.command == 'fusion': value = fusion_view(validate(records[0]))
        else: value = evidence_demo(records[0])
        content = value if isinstance(value,str) else json.dumps(value, indent=2, allow_nan=False)
    with open(args.output, 'x') as stream: stream.write(content+'\n')

if __name__ == '__main__': main()
