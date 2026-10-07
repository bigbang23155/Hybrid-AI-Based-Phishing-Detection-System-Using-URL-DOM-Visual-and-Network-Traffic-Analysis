"""Freeze auditable internal partitions after content/source research decisions.

No training, feature selection, relabeling, backfill or live webpage access.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import platform

import numpy as np

from .formal_candidates import file_sha, json_bytes, sha
from .formal_html import frozen_candidates, inspect_html
from .paired_quality import read_jsonl, _safe_path


def keys(row, min_tags=20):
    result = [('domain', row['registered_domain']), ('url', row['url_clean'])]
    if row.get('html_sha256'):
        result.append(('html', row['html_sha256']))
    if (row.get('tag_count') or 0) >= min_tags and row.get('structural_tag_sequence_sha256'):
        result.append(('structure', row['structural_tag_sequence_sha256']))
    return result


def connected_groups(rows, min_tags=20):
    parent = {r['sample_id']: r['sample_id'] for r in rows}
    if len(parent) != len(rows):
        raise ValueError('duplicate sample IDs')
    def root(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    first = {}
    for r in sorted(rows, key=lambda r: r['sample_id']):
        for key in keys(r, min_tags):
            if key in first:
                a, b = root(r['sample_id']), root(first[key])
                if a != b:
                    parent[max(a, b)] = min(a, b)
            else:
                first[key] = r['sample_id']
    return {s: root(s) for s in sorted(parent)}


def verify_pilot(root, verification_path, min_tags):
    rows = read_jsonl(root / 'paired_manifest.jsonl')
    verification = json.loads(verification_path.read_text())
    # These three fields were added by the documented pilot metadata enrichment.
    # Reconstruct the original complete manifest bytes, not merely its IDs.
    original = ''.join(json.dumps({k: v for k, v in r.items() if k not in ('target', 'lang', 'lang_score')},
                                 sort_keys=True, allow_nan=False) + '\n' for r in rows).encode()
    if sha(original) != verification['paired_manifest_sha256']:
        raise ValueError('original pilot manifest projection mismatch')
    if file_sha(root / 'public/replay_index.csv') != verification['artifact_replay_index_sha256']:
        raise ValueError('original pilot replay mismatch')
    if len(rows) != verification['selected_candidates'] or len({r['sample_id'] for r in rows}) != len(rows):
        raise ValueError('pilot candidate accounting mismatch')
    for r in rows:
        if r.get('html_path'):
            raw = _safe_path(root, r['html_path']).read_bytes()
            if sha(raw) != r['html_sha256']:
                raise ValueError('pilot HTML integrity mismatch')
            value = inspect_html(raw.decode('utf-8'), r['url_clean'], 2097152)
            if value['parse_status'] != 'parsed_markup':
                raise ValueError('pilot structural probe changed')
            r['structural_tag_sequence_sha256'] = value['structural_tag_sequence_sha256']
            r['tag_count'] = value['tag_count']
        else:
            r['structural_tag_sequence_sha256'] = None
    return rows, {'original_manifest_projection_sha256': sha(original),
                  'original_replay_sha256': file_sha(root / 'public/replay_index.csv'),
                  'enriched_manifest_sha256': file_sha(root / 'paired_manifest.jsonl'),
                  'candidate_count': len(rows), 'all_candidates_including_oversize_treated_as_exposed': True,
                  'structural_signatures_available': sum(any(k == 'structure' for k, _ in keys(r, min_tags)) for r in rows)}


def exposure(rows, pilot, groups, min_tags=20):
    pilot_keys = defaultdict(set)
    for r in pilot:
        for key in keys(r, min_tags) + [('sample', r['sample_id'])]:
            pilot_keys[key].add(r['sample_id'])
    direct, group_hits = {}, defaultdict(set)
    for r in rows:
        matches = defaultdict(set)
        for key in keys(r, min_tags) + [('sample', r['sample_id'])]:
            if key in pilot_keys:
                matches[key[0]].update(pilot_keys[key])
        direct[r['sample_id']] = {k: sorted(v) for k, v in sorted(matches.items())}
        if matches:
            group_hits[groups[r['sample_id']]].update(matches)
    return direct, {k: sorted(v) for k, v in group_hits.items()}


def choose_groups(rows, target_per_label, seed, attempts):
    if not rows:
        raise ValueError('no unexposed groups left')
    counts = defaultdict(lambda: [0, 0])
    for r in rows:
        counts[r['final_group']][r['label']] += 1
    names = sorted(counts)
    values = np.asarray([counts[name] for name in names], dtype=int)
    target = np.asarray(target_per_label, dtype=float)
    if any(values.sum(axis=0) < target):
        raise ValueError('insufficient unexposed class capacity')
    rng, best = np.random.default_rng(seed), None
    for _ in range(attempts):
        order = rng.permutation(len(names))
        cumulative = values[order].cumsum(axis=0)
        stop = min(int(np.searchsorted(cumulative.sum(axis=1), target.sum())), len(names)-1)
        chosen = order[:stop+1]
        score = float(np.sum(np.abs(cumulative[stop] - target) / target))
        if best is None or score < best[0]:
            best = score, {names[i] for i in chosen}
    return best[1]


def allocate(rows, exposed_groups, policy):
    total = Counter(r['label'] for r in rows)
    part = policy['partition']
    if set(total) != {0, 1}:
        raise ValueError('both labels required')
    eligible = [r for r in rows if r['final_group'] not in exposed_groups]
    test = choose_groups(eligible, [total[y]*part['test_fraction'] for y in (0, 1)],
                         part['test_seed'], part['permutation_candidates'])
    remaining = [r for r in eligible if r['final_group'] not in test]
    validation = choose_groups(remaining, [total[y]*part['validation_fraction'] for y in (0, 1)],
                               part['development_seed'], part['permutation_candidates'])
    result = {r['sample_id']: 'test' if r['final_group'] in test else 'validation'
              if r['final_group'] in validation else 'train' for r in rows}
    return result


def validate_partition(rows, assignment, exposed_groups, policy):
    if set(assignment) != {r['sample_id'] for r in rows}:
        raise ValueError('partition membership mismatch')
    by_key, by_group = defaultdict(set), defaultdict(set)
    counts = {name: Counter() for name in ('train', 'validation', 'test')}
    n = len(rows)
    total = Counter(r['label'] for r in rows)
    for r in rows:
        p = assignment[r['sample_id']]
        if p not in counts:
            raise ValueError('unknown partition')
        if r['final_group'] in exposed_groups and p != 'train':
            raise ValueError('pilot-exposed component outside training')
        by_group[r['final_group']].add(p)
        for key in keys(r, policy['grouping']['structural_min_tags']):
            by_key[key].add(p)
        counts[p][r['label']] += 1
    if any(len(v) > 1 for v in by_group.values()) or any(len(v) > 1 for v in by_key.values()):
        raise ValueError('group/domain/content/structure overlap across partitions')
    tol = policy['partition']['maximum_fraction_error_overall_and_per_label']
    for p, c in counts.items():
        target = policy['partition'][p + '_fraction']
        if set(c) != {0, 1} or abs(sum(c.values())/n - target) > tol or any(abs(c[y]/total[y]-target) > tol for y in (0, 1)):
            raise ValueError('partition class/size tolerance failed; no reselection')
    return {p: {'total': sum(c.values()), 'benign': c[0], 'phishing': c[1],
                'fraction': sum(c.values())/n,
                'groups': len({r['final_group'] for r in rows if assignment[r['sample_id']] == p})}
            for p, c in counts.items()}


def freeze_rows(formal, pilot, policy, output):
    if output.exists():
        raise FileExistsError('immutable freeze output exists')
    if len(formal) != policy['eligibility']['expected_candidates']:
        raise ValueError('candidate count changed')
    usable = [dict(r) for r in formal if r['usable_pair']]
    if len(usable) != policy['eligibility']['expected_usable']:
        raise ValueError('eligible count changed')
    min_tags = policy['grouping']['structural_min_tags']
    groups = connected_groups(usable, min_tags)
    sizes = Counter(groups.values())
    if max(sizes.values())/len(usable) > policy['grouping']['maximum_component_fraction']:
        raise ValueError('component exceeds preregistered cap; stop without reselection')
    for r in usable:
        r['final_group'] = groups[r['sample_id']]
    direct, exposed = exposure(usable, pilot, groups, min_tags)
    assigned = allocate(usable, exposed, policy)
    counts = validate_partition(usable, assigned, exposed, policy)
    public_rows = []
    for r in sorted(formal, key=lambda r: r['sample_id']):
        sid = r['sample_id']
        group = groups.get(sid)
        public_rows.append({'sample_id': sid, 'source_file': r['source_file'], 'source_row': r['source_row'],
                           'label': r['label'], 'registered_domain_sha256': sha(r['registered_domain'].encode()),
                           'html_sha256': r['html_sha256'], 'parse_status': r['parse_status'],
                           'eligible': r['usable_pair'], 'exclusion_reasons': r['exclusion_reasons'],
                           'final_group': group, 'partition': assigned.get(sid, 'excluded'),
                           'direct_pilot_matches': direct.get(sid, {}),
                           'component_pilot_exposed': group in exposed,
                           'component_exposure_reasons': exposed.get(group, [])})
    all_direct, _ = exposure(formal, pilot, {r['sample_id']: r['sample_id'] for r in formal}, min_tags)
    def match_counts(mapping):
        return {kind: sum(kind in v for v in mapping.values()) for kind in ('sample', 'url', 'domain', 'html', 'structure')}
    overlap = {'pilot_candidates': len(pilot), 'formal_all_candidates_direct_matches': match_counts(all_direct),
               'formal_usable_direct_matches': match_counts(direct),
               'usable_directly_matched_rows': sum(bool(v) for v in direct.values()),
               'exposed_formal_components': len(exposed),
               'train_only_due_to_pilot_rows': sum(groups[r['sample_id']] in exposed for r in usable),
               'transitive_additional_train_only_rows': sum(groups[r['sample_id']] in exposed and not direct[r['sample_id']] for r in usable),
               'pilot_exposed_validation_rows': 0, 'pilot_exposed_test_rows': 0}
    summary = {'schema_version': 'assignment03-frozen-holdout-v1', 'eligible_pairs': len(usable),
               'excluded_pairs': len(formal)-len(usable), 'final_group_count': len(sizes),
               'largest_group': max(sizes.values()), 'group_size_histogram': dict(sorted(Counter(sizes.values()).items())),
               'partition_counts': counts, 'overlap': overlap,
               'cross_partition_domain_overlap': 0, 'cross_partition_exact_html_overlap': 0,
               'cross_partition_structural_signature_overlap': 0, 'cross_partition_group_overlap': 0,
               'final_partition_created': True, 'eligible_membership_frozen': True,
               'training_approved': False, 'model_training_performed': False, 'test_evaluated': False,
               'holdout_scope': policy['purpose'], 'policy_sha256': sha(json_bytes(policy)),
               'python_version': platform.python_version(), 'numpy_version': np.__version__}
    output.mkdir(parents=True)
    raw = ''.join(json.dumps(r, sort_keys=True, allow_nan=False)+'\n' for r in public_rows).encode()
    (output/'partition_manifest.jsonl').write_bytes(raw)
    summary['partition_manifest_sha256'] = sha(raw)
    # Private URLs and DOM feature values are intentionally absent from the freeze.
    (output/'holdout_summary.json').write_bytes(json_bytes(summary))
    (output/'holdout_policy.json').write_bytes(json_bytes(policy))
    return summary


def run(args):
    if args.output.exists():
        raise FileExistsError('freeze output already exists')
    policy = json.loads(args.holdout_policy.read_text())
    checkpoint = json.loads(args.html_checkpoint.read_text())
    audit_path = args.audit_public / 'sample_audit.jsonl'
    if file_sha(audit_path) != checkpoint['sample_audit_sha256']:
        raise ValueError('locked formal sample audit mismatch')
    chosen, _, _, _, replay = frozen_candidates(args.source_root, args.frame, args.paired_policy, args.candidate_freeze)
    if sha(replay) != checkpoint['candidate_replay_sha256']:
        raise ValueError('candidate replay differs from selected-HTML checkpoint')
    audit = read_jsonl(audit_path)
    by_id = {r['sample_id']: r for r in audit}
    if len(by_id) != len(audit) or set(by_id) != {r['sample_id'] for r in chosen}:
        raise ValueError('formal audit membership mismatch')
    formal = []
    for r in chosen:
        a = by_id[r['sample_id']]
        if any(a[k] != r[k] for k in ('source_file', 'source_file_sha256', 'source_row', 'label')):
            raise ValueError('formal metadata/audit alignment mismatch')
        formal.append({**r, **a})
    pilot, evidence = verify_pilot(args.pilot_root, args.pilot_verification, policy['grouping']['structural_min_tags'])
    summary = freeze_rows(formal, pilot, policy, args.output)
    summary['provenance'] = {'formal_sample_audit_sha256': file_sha(audit_path),
                             'formal_paired_manifest_sha256': checkpoint['paired_manifest_sha256'],
                             'candidate_replay_sha256': sha(replay), 'pilot': evidence,
                             'implementation_sha256': file_sha(Path(__file__)),
                             'source_frame_sha256': file_sha(args.frame),
                             'paired_policy_sha256': file_sha(args.paired_policy),
                             'source_ledger_sha256': file_sha(args.source_ledger)}
    (args.output/'holdout_summary.json').write_bytes(json_bytes(summary))
    (args.output/'source_ledger.json').write_bytes(args.source_ledger.read_bytes())
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'audit-public', 'pilot-root', 'pilot-verification', 'frame', 'paired-policy',
                 'candidate-freeze', 'html-checkpoint', 'holdout-policy', 'source-ledger', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    print(json.dumps(run(p.parse_args()), indent=2))


if __name__ == '__main__':
    main()
