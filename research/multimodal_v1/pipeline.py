"""Offline batch extraction from an existing decrypted Collector run."""
from __future__ import annotations

import argparse
from collections import Counter
import importlib.metadata
import json
from pathlib import Path
import platform

from . import VERSION
from .adapters import from_checkpoint
from .contract import MODALITIES, encoded, fusion_view, freshness, sha
from .network_http import REGISTRY_SHA256, registry
from .forensics import RULE_PATH
from .quality import Coverage

ROOT = Path(__file__).resolve().parents[2]


def implementation_manifest():
    sources = list(Path(__file__).parent.glob('*.py')) + [RULE_PATH]
    sources += [ROOT/'src/phishing_url'/n for n in ('features.py','url_cleaning.py','dom_features.py')]
    sources += [ROOT/'research/urlscan_v1/similarity.py']
    deps = {}
    for name in ('tldextract', 'yara-python', 'Pillow', 'numpy', 'scipy'):
        try:
            deps[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            deps[name] = None
    return {'version': VERSION, 'python': platform.python_version(), 'dependencies': deps,
            'source_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sorted(sources)},
            'network_registry_sha256': REGISTRY_SHA256, 'yara_rules_sha256': sha(RULE_PATH.read_bytes())}


def build(run, output, *, as_of, max_age_seconds, run_yara=True):
    run, output = Path(run).resolve(), Path(output).resolve()
    if output.is_relative_to(ROOT) or output.is_relative_to(run) or run.is_relative_to(output):
        raise ValueError('output_must_be_outside_repository_and_input')
    freshness(None, as_of=as_of, max_age_seconds=max_age_seconds)
    checkpoints = sorted((run/'private').glob('*/record.json'))
    if not checkpoints:
        raise ValueError('no_collector_checkpoints')
    if len(checkpoints) > 5000:
        raise ValueError('batch_limit_exceeded')
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    private, public = output/'private', output/'public'
    private.mkdir(mode=0o700); public.mkdir()
    counts, temporal_counts, extraction_counts, yara_counts = Counter(), Counter(), Counter(), Counter()
    manifest = implementation_manifest()
    manifest.update(as_of=as_of, max_age_seconds=max_age_seconds, run_yara=run_yara,
                    freshness_policy='explicit_provisional_cutoff_not_calibrated', complete=False)
    (output/'run.json').write_bytes(encoded(manifest)+b'\n')
    seen = set()
    coverage = Coverage()
    with (private/'features.jsonl').open('xb') as stream, (private/'fusion_inputs.jsonl').open('xb') as fusion:
        for checkpoint in checkpoints:
            if checkpoint.parent.is_symlink() or not checkpoint.resolve().is_relative_to(run):
                raise ValueError('checkpoint_path_escape')
            row = from_checkpoint(checkpoint, as_of=as_of, max_age_seconds=max_age_seconds, run_yara=run_yara)
            if row['item_id'] in seen:
                raise ValueError('duplicate_item')
            seen.add(row['item_id'])
            coverage.add(row)
            if coverage.pairing['failed']:
                raise ValueError('cross_modality_alignment_failed')
            stream.write(encoded(row)+b'\n')
            fusion.write(encoded({'item_id': row['item_id'], **fusion_view(row)})+b'\n')
            for name in MODALITIES:
                m = row['modalities'][name]
                counts[name+':'+m['acquisition_status']] += 1
                temporal_counts[name+':'+m['temporal']['status']] += 1
                extraction_counts[name+':'+m['extraction_status']] += 1
            yara_counts[row['sidecars'].get('content_forensics', {}).get('yara', {}).get('status', 'content_unavailable')] += 1
    summary = {'version': VERSION, 'records': len(seen), 'acquisition_counts': dict(counts),
               'temporal_counts': dict(temporal_counts), 'extraction_counts': dict(extraction_counts),
               'yara_status_counts': dict(yara_counts), 'new_scans': 0, 'network_requests': 0,
               'labels_added': 0, 'training_eligible_added': 0, 'model_fits': 0,
               'historical_equivalence_asserted': False}
    (public/'summary.json').write_bytes(encoded(summary)+b'\n')
    (public/'network_http_registry.json').write_bytes(encoded(registry())+b'\n')
    (public/'feature_quality.json').write_bytes(encoded(coverage.report())+b'\n')
    manifest.update(complete=True, output_sha256={p.name:sha(p.read_bytes()) for p in sorted(private.iterdir())})
    manifest['public_output_sha256'] = {p.name:sha(p.read_bytes()) for p in sorted(public.iterdir())}
    (output/'run.json').write_bytes(encoded(manifest)+b'\n')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True, help='Existing decrypted Collector run')
    parser.add_argument('--output', type=Path, required=True, help='New private directory outside checkout and input')
    parser.add_argument('--as-of', required=True, help='Fixed timezone-aware reference time')
    parser.add_argument('--max-age-seconds', type=float, required=True, help='Explicit provisional age cutoff')
    parser.add_argument('--skip-yara', action='store_true')
    args = parser.parse_args()
    try:
        print(encoded(build(args.run, args.output, as_of=args.as_of,
            max_age_seconds=args.max_age_seconds, run_yara=not args.skip_yara)).decode())
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('multimodal_input_or_output_validation_failed') from None


if __name__ == '__main__':
    main()
