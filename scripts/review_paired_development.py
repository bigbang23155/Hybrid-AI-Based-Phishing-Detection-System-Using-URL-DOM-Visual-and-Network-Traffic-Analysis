"""Descriptive review of sanitized, verified development artifacts; no fitting."""
import argparse
from collections import defaultdict
import csv
import json
from pathlib import Path


def review(public, repository):
    protocol = json.loads((repository/'config/assignment03_modeling_protocol_v1.json').read_text())
    seed = protocol['primary_model_seed']
    metrics = list(csv.DictReader((public/'models/metrics.csv').open()))
    variants = [('url_only','baseline'),('dom_only','baseline'),('url_dom','baseline')]
    variants += [(m,s) for s in protocol['sensitivity_url_sets'] for m in ('url_only','url_dom')]
    expected = {(f'{model}/{modality}/{variant}',s) for model in protocol['models']
                for modality,variant in variants for s in protocol['model_seeds']}
    evidence = json.loads((public/'models/model_evidence.json').read_text())
    assert len(evidence) == len(expected) == 70
    assert {(r['condition'],r['seed']) for r in evidence} == expected
    for r in evidence:
        params = protocol['models'][r['condition'].split('/')[0]]
        assert all(r['parameters'][k] == v for k,v in params.items())
        assert r['parameters']['random_state'] == r['seed']
        assert r['validation_batch_size'] == protocol['sample_counts']['validation']
    assert len(metrics) == 140
    assert {(r['condition'],int(r['seed']),r['partition']) for r in metrics} == {
        (c,s,p) for c,s in expected for p in ('train','validation')}
    assert all(int(r['n']) == protocol['sample_counts'][r['partition']] for r in metrics)
    cells = {(r['condition'], r['partition']): r for r in metrics if int(r['seed']) == seed}
    predictions = defaultdict(dict)
    for line in (public/'models/validation_predictions.jsonl').read_text().splitlines():
        r = json.loads(line)
        if r['seed'] == seed and r['condition'].endswith('/baseline'):
            predictions[r['condition']][r['sample_id']] = r
    paired = []
    for model in protocol['models']:
        hybrid = predictions[f'{model}/url_dom/baseline']
        for other in ('url_only', 'dom_only'):
            baseline = predictions[f'{model}/{other}/baseline']
            assert set(hybrid) == set(baseline)
            counts = dict(both_correct=0, both_wrong=0, hybrid_fixes=0, hybrid_breaks=0)
            for sid, h in hybrid.items():
                b = baseline[sid]
                assert h['label'] == b['label']
                hc, bc = h['predicted'] == h['label'], b['predicted'] == b['label']
                name = ('both_correct' if hc else 'hybrid_breaks') if bc else ('hybrid_fixes' if hc else 'both_wrong')
                counts[name] += 1
            paired.append(dict(model=model, comparator=other, n=len(hybrid), **counts))
    sensitivity = []
    for model in protocol['models']:
        for modality in ('url_only', 'url_dom'):
            base = cells[f'{model}/{modality}/baseline', 'validation']
            for variant in protocol['sensitivity_url_sets']:
                row = cells[f'{model}/{modality}/{variant}', 'validation']
                sensitivity.append(dict(model=model, modality=modality, variant=variant,
                    delta_f1=float(row['f1'])-float(base['f1']),
                    delta_fpr=float(row['fpr'])-float(base['fpr']),
                    f1=float(row['f1']), fpr=float(row['fpr'])))
    strata = json.loads((public/'models/validation_strata.json').read_text())
    for r in strata:
        r['positive_n'], r['negative_n'] = int(r['tp']+r['fn']), int(r['tn']+r['fp'])
        # Execution metrics follow zero-division conventions. Display absent-class
        # rates as undefined so a pure-positive subgroup never appears to have 0 FPR.
        if not r['negative_n']: r['fpr'] = None
        if not r['positive_n']: r['recall'] = None
        r['small_slice_under_30'] = r['n'] < 30
    profile = json.loads((public/'feature_profiles.json').read_text())
    class_gaps, constant = [], []
    for partition, labels in profile.items():
        for name in labels['0']['numeric']:
            b, p = labels['0']['numeric'][name], labels['1']['numeric'][name]
            scale = ((b['std_population']**2 + p['std_population']**2)/2)**.5
            class_gaps.append(dict(partition=partition, feature=name,
                benign_mean=b['mean'], phishing_mean=p['mean'],
                descriptive_standardized_mean_difference=(p['mean']-b['mean'])/scale if scale else None,
                zero_rate_benign=b['zero_count']/b['n'], zero_rate_phishing=p['zero_count']/p['n']))
            if b['min'] == b['max'] == p['min'] == p['max']:
                constant.append(dict(partition=partition, feature=name, value=b['min']))
    return dict(primary_seed=seed, condition_grid_verified=True, model_parameters_verified=True,
                paired_errors=paired, sensitivity=sensitivity,
                validation_strata_with_denominators=strata, class_feature_gaps=class_gaps,
                constant_features=constant,
                interpretation='Descriptive development diagnostics only; no feature selection, thresholds, parameters or split changes. Small and single-class slices are not performance guarantees.')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public',type=Path,required=True)
    parser.add_argument('--repository',type=Path,default=Path('.'))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    args.output.write_text(json.dumps(review(args.public,args.repository),indent=2,sort_keys=True,allow_nan=False)+'\n')
