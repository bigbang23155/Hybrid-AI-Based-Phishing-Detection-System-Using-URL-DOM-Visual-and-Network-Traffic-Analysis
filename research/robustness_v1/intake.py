"""Offline review intake. Reads saved metadata, never HTML, networks or test scores."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime
import gzip
import hashlib
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_rows(path):
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        return [json.loads(line) for line in stream if line.strip()]


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + '\n')


def write_rows(path, rows):
    path.write_text(''.join(json.dumps(r, sort_keys=True, allow_nan=False) + '\n' for r in rows))


def wilson(errors, total, z=1.959963984540054):
    if not 0 <= errors <= total or total <= 0:
        raise ValueError('invalid binomial counts')
    p = errors / total
    denominator = 1 + z*z/total
    center = (p + z*z/(2*total)) / denominator
    radius = z*math.sqrt(p*(1-p)/total + z*z/(4*total*total))/denominator
    return [max(0.0, center-radius), min(1.0, center+radius)]


def precision_plan():
    # Worst-case normal planning approximation, not a clustered power analysis.
    return {
        'independent_binomial_worst_case_n_for_95pct_plus_minus_5pp': math.ceil(1.959963984540054**2 * .25 / .05**2),
        'zero_error_n_for_one_sided_95pct_upper_fpr_1pct': math.ceil(math.log(.05)/math.log(.99)),
        'zero_error_n_for_one_sided_95pct_upper_fpr_0_1pct': math.ceil(math.log(.05)/math.log(.999)),
        'unit': 'independent evaluation units, not duplicate URLs or synthetic rows',
        'limits': 'planning only; each relevant class/subgroup needs its own denominator; correlated pages require group bootstrap/design-effect or cluster simulation; nonzero errors require exact interval calculation',
        'learning_curve_fractions': [.125, .25, .5, .75, 1.0],
        'stop_rule': 'predeclared acquisition waves/budget, never stop when a desired score appears',
    }


def historical_audit(root, output):
    """Prepare development review only and a full historic exposure denylist."""
    manifest_path = root / 'results/assignment03/holdout_v1/partition_manifest.jsonl.gz'
    ledger_path = root / 'results/assignment03/review_v1/error_ledger.jsonl.gz'
    changes_path = root / 'results/assignment03/review_v1/paired_changes.jsonl.gz'
    manifest, ledger, changes = [read_rows(p) for p in (manifest_path, ledger_path, changes_path)]
    index = {r['sample_id']: r for r in manifest}
    if len(index) != len(manifest):
        raise ValueError('duplicate manifest ID')
    # Verify the immutable benchmark bytes without executing its evaluation API.
    lock_path = root / 'config/assignment03_final_evaluation_v1.json'
    lock = json.loads(lock_path.read_text())
    for relative, expected in lock['file_sha256'].items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root.resolve()) or digest(path) != expected:
            raise ValueError('frozen baseline changed: ' + relative)
    rf = {r['sample_id']: r for r in ledger if r['condition'] == 'random_forest/url_dom/baseline'}
    expected = {r['sample_id'] for r in manifest if r['partition'] == 'validation'}
    if set(rf) != expected or len([r for r in ledger if r['condition'] == 'random_forest/url_dom/baseline']) != len(expected):
        raise ValueError('development reference mismatch')
    for r in ledger:
        reference = index[r['sample_id']]
        if reference['partition'] != 'validation' or r['label'] != reference['label'] or r['final_group'] != reference['final_group']:
            raise ValueError('non-development/inconsistent ledger')
    breaks = {r['sample_id'] for r in changes if r['model'] == 'random_forest' and r['comparator'] == 'url_only' and r['kind'] == 'breaks'}
    if not breaks <= expected:
        raise ValueError('non-development change record')
    reasons = defaultdict(set)
    controls = defaultdict(list)
    seed = json.loads((HERE/'protocol.json').read_text())['seed']
    for sid, row in rf.items():
        if row['outcome'] in ('fp', 'fn'):
            reasons[sid].add('hybrid_error')
        if sid in breaks:
            reasons[sid].add('fusion_introduced_error')
        if row['label'] == 0 and row['complexity_bin'] == 0:
            reasons[sid].add('simple_benign')
        if row['label'] == 1 and row['complexity_bin'] == 3:
            reasons[sid].add('complex_phishing')
        if row['label'] == 0 and row['password_present']:
            reasons[sid].add('benign_password_proxy')
        if row['outcome'] in ('tp', 'tn'):
            cell = (row['label'], row['complexity_bin'], row['password_present'], row['source_shard'], row['month'], row['language_group'])
            controls[cell].append(sid)
    cap = json.loads((HERE/'protocol.json').read_text())['sample_design']['correct_control_cap_per_historical_cell']
    for members in controls.values():
        ranked = sorted(members, key=lambda sid: hashlib.sha256(f'{seed}:{sid}'.encode()).hexdigest())
        for sid in ranked[:cap]:
            reasons[sid].add('stratified_correct_control')
    queue, key = [], []
    for sid in sorted(reasons):
        ref, row = index[sid], rf[sid]
        review_id = hashlib.sha256(('review-v1:'+sid).encode()).hexdigest()[:24]
        # Reviewer packet intentionally omits source label, score and selection reason.
        queue.append(dict(review_id=review_id, sample_id=sid, html_sha256=ref['html_sha256'],
                          source_file=ref['source_file'], source_row=ref['source_row'],
                          scope='historical_development_audit', content_status='requires_snapshot_materialization',
                          pass_a=None, pass_b=None, adjudication=None))
        key.append(dict(review_id=review_id, sample_id=sid, source_label=row['label'],
                        reasons=sorted(reasons[sid]), original_partition='validation',
                        final_group=ref['final_group'], complexity_bin=row['complexity_bin'],
                        password_present=row['password_present'], source_shard=row['source_shard'],
                        month=row['month'], language_group=row['language_group']))
    coverage = []
    for label in (0, 1):
        for complexity in range(4):
            for password in (False, True):
                rows = [r for r in rf.values() if r['label'] == label and r['complexity_bin'] == complexity and r['password_present'] == password]
                count = len(rows)
                errors = sum(r['outcome'] in ('fp', 'fn') for r in rows)
                coverage.append(dict(label=label, complexity_bin=complexity, password_present=password,
                                     n=count, groups=len({r['final_group'] for r in rows}), errors=errors,
                                     error_rate=errors/count if count else None,
                                     illustrative_independent_wilson_interval=wilson(errors, count) if count else None,
                                     interval_limitation='not cluster-adjusted, descriptive only'))
    output.mkdir(parents=True, exist_ok=False)
    write_rows(output/'review_queue_blinded.jsonl', queue)
    write_rows(output/'coordinator_key.jsonl', key)
    write_rows(output/'historical_exposure_denylist.jsonl', [{k:r.get(k) for k in ('sample_id','final_group','registered_domain_sha256','html_sha256','source_file','source_row','partition')} for r in manifest])
    write_json(output/'coverage.json', coverage)
    write_json(output/'sample_size_plan.json', precision_plan())
    summary = dict(status='review_prepared_not_adjudicated', historical_partitions=dict(Counter(r['partition'] for r in manifest)),
                   historical_exposure_rows=len(manifest), development_validation_rows=len(rf),
                   review_queue_rows=len(queue), review_reason_counts=dict(Counter(reason for rs in reasons.values() for reason in rs)),
                   frozen_files_verified=len(lock['file_sha256']), reviewed_labels=0, new_samples_acquired=0,
                   model_fits=0, test_predictions_read=0, adversarial_training_executed=False,
                   input_sha256={str(p.relative_to(root)):digest(p) for p in (manifest_path,ledger_path,changes_path,lock_path)},
                   blockers=['Original snapshots are not included in the repository; materialize for content review.',
                             'Two independent human reviews with time-aligned evidence are not available.',
                             'New development/reference samples and untouched external holdout are not acquired.',
                             'Historical denylist lacks pilot-only IDs and URL/template/campaign keys; expand it before certifying novel cohorts.'])
    write_json(output/'intake_summary.json', summary)
    return summary


def _timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timestamp must include timezone')
    return result


def adjudicate(packet):
    """Validate recorded human evidence. This is not an automated truth oracle."""
    evidence = packet.get('evidence', [])
    rounds = packet.get('reviews', [])
    snapshot = packet['html_sha256']
    if len(snapshot) != 64 or any(c not in '0123456789abcdef' for c in snapshot):
        raise ValueError('invalid snapshot SHA-256')
    capture_time = _timestamp(packet['captured_at'])
    ev = {r['id']:r for r in evidence}
    if len(ev) != len(evidence):
        raise ValueError('duplicate evidence ID')
    for r in evidence:
        _timestamp(r['observed_at'])
        valid_from, valid_to = _timestamp(r['valid_from']), _timestamp(r['valid_to'])
        if valid_to < valid_from:
            raise ValueError('invalid evidence validity interval')
        if not r.get('origin_family') or not r.get('reference') or not r.get('rationale'):
            raise ValueError('evidence requires provenance and rationale')
        if r['verdict'] not in (0, 1, 'uncertain'):
            raise ValueError('invalid evidence verdict')
    if len(rounds) < 2:
        return dict(status='pending', label=None, reason='two independent reviews required')
    for r in rounds:
        if r['label'] not in (0, 1, 'uncertain') or r['html_sha256'] != snapshot:
            raise ValueError('review label or snapshot mismatch')
        if not r.get('rationale') or not r.get('reviewer_id') or r.get('reviewer_type') != 'human':
            raise ValueError('human review identity and rationale required; no fabricated AI-as-human votes')
        if _timestamp(r['reviewed_at']) < capture_time:
            raise ValueError('review predates snapshot')
        if any(i not in ev for i in r['evidence_ids']):
            raise ValueError('unresolved evidence reference')
    a, b = rounds[:2]
    if a['reviewer_id'] == b['reviewer_id'] or not all(r.get('blind_to_model_and_other_review') is True for r in (a,b)):
        raise ValueError('first two passes must be independent and blinded')
    evidence_dispute = any(e['verdict'] in (0,1) and e['verdict'] != a['label']
                           and e['html_sha256'] == snapshot
                           and _timestamp(e['valid_from']) <= capture_time <= _timestamp(e['valid_to'])
                           for e in evidence)
    disputed = a['label'] != b['label'] or a['label'] == 'uncertain' or evidence_dispute
    selected = rounds[:2]
    if disputed:
        if len(rounds) != 3:
            return dict(status='quarantine', label=None, reason='disagreement or uncertainty requires third adjudication')
        third = rounds[2]
        if third['reviewer_id'] in {a['reviewer_id'], b['reviewer_id']} or third.get('role') != 'adjudicator':
            raise ValueError('third adjudicator must be distinct')
        selected, label = [third], third['label']
    else:
        if len(rounds) != 2:
            raise ValueError('extra review rounds require a versioned disagreement record')
        label = a['label']
    if label == 'uncertain':
        return dict(status='quarantine', label=None, reason='uncertain final label')
    def supportive(item):
        return (item['verdict'] == label and item['html_sha256'] == snapshot
                and item.get('evidence_type') in ('historical_source_assertion','snapshot_content_review','official_identity_verification','incident_confirmation')
                and _timestamp(item['valid_from']) <= capture_time <= _timestamp(item['valid_to']))
    for review in selected:
        families = {ev[i]['origin_family'] for i in review['evidence_ids'] if supportive(ev[i])}
        if len(families) < 2:
            return dict(status='quarantine', label=None, reason='insufficient independent, snapshot/time-aligned support')
    conflicting = [e for e in evidence if e['verdict'] in (0,1) and e['verdict'] != label
                   and e['html_sha256'] == snapshot and _timestamp(e['valid_from']) <= capture_time <= _timestamp(e['valid_to'])]
    if conflicting and not (disputed and set(e['id'] for e in conflicting) <= set(rounds[2].get('resolved_conflict_ids', []))):
        return dict(status='quarantine', label=None, reason='conflicting evidence needs explicit adjudication')
    return dict(status='accepted_recorded_review', label=label, independently_verified_by_software=False,
                original_label=packet.get('source_label'), changed=packet.get('source_label') != label,
                note='Trusts recorded reviewer identity, source independence and rationale; no claim that software independently established truth.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    a = sub.add_parser('audit'); a.add_argument('--root',type=Path,default=Path('.'));a.add_argument('--output',type=Path,required=True)
    r = sub.add_parser('review');r.add_argument('--input',type=Path,required=True);r.add_argument('--output',type=Path,required=True)
    args = p.parse_args()
    if args.command == 'audit':
        result = historical_audit(args.root, args.output)
    else:
        packets = read_rows(args.input)
        if len({r['sample_id'] for r in packets}) != len(packets):
            raise ValueError('duplicate review packet ID')
        result = [{'sample_id':r['sample_id'], **adjudicate(r)} for r in packets]
        if args.output.exists():raise ValueError('refuse to overwrite adjudication history')
        write_rows(args.output, result)
    print(json.dumps(result,indent=2))


if __name__ == '__main__':main()
