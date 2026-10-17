"""Existing public example.com scan -> features -> quality -> encrypted evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

from research.urlscan_v1.client import Client
from research.urlscan_v1.collector import collect, write_json
from research.urlscan_v1.secure_store import public_key, seal_directory

from .contract import encoded
from .pipeline import ROOT, build

MAX_AGE_SECONDS = 7 * 86400  # Public positive-control recency, not a model threshold.
REQUEST_LIMIT = 15
INTERVAL_SECONDS = 12
CANDIDATE = {'review_id': 'example-com-smoke', 'url': 'https://example.com/', 'scope': 'smoke_test'}
CORE_HTTP = ('request_record_count', 'http_request_count', 'main_status')


def readiness(quality):
    """A smoke pass permits documented optional gaps, never a label or training."""
    core = all(quality['features']['network_http__'+n]['usable_records'] == 1 for n in CORE_HTTP)
    core = core and all(quality['features']['network_http__'+n]['observed_zero_records'] == 0
                        for n in ('request_record_count', 'http_request_count'))
    aligned = quality['records'] == 1 and quality['alignment_counts'].get('aligned') == 1
    usable = quality['all_modalities_usable_records'] == 1
    yara_ok = quality['yara_status_counts'].get('ok') == 1
    gaps = [name for name, c in quality['features'].items() if c['usable_records'] != 1]
    success = core and aligned and usable and yara_ok
    return {'status': 'PASS_WITH_GAPS' if success and gaps else 'PASS' if success else 'FAIL',
            'contract_check_passed': success, 'core_http_fields_usable': core,
            'four_modalities_aligned': aligned, 'four_modalities_usable': usable,
            'yara_executed': yara_ok, 'registered_columns': quality['column_count'],
            'observed_columns': sum(c['observed_records'] == 1 for c in quality['features'].values()),
            'usable_columns': sum(c['usable_records'] == 1 for c in quality['features'].values()),
            'unusable_columns': gaps,
            'missing_reasons': {n:c['missing_reasons'] for n,c in quality['features'].items() if c['missing_reasons']},
            'quality_flag_counts': quality['quality_flag_counts'],
            'alignment_reason_counts': quality['alignment_reason_counts']}


def run(work, publish, recipient, client, *, as_of=None):
    work, publish, recipient = Path(work).resolve(), Path(publish).resolve(), Path(recipient)
    if (work == publish or work.is_relative_to(publish) or publish.is_relative_to(work)
            or work.is_relative_to(ROOT) or publish.is_relative_to(ROOT)):
        raise ValueError('smoke_paths_must_be_separate_and_outside_checkout')
    if work.exists() or publish.exists():
        raise ValueError('smoke_output_already_exists')
    # Fail before any request when the encryption recipient is invalid.
    public_key(recipient.read_bytes())
    work.mkdir(parents=True, mode=0o700)
    report = {'version': 'multimodal-public-smoke-v1', 'status': 'FAIL',
              'control': 'existing_public_example_com_scan', 'new_scans_submitted': 0,
              'historical_candidates_searched': 0, 'labels_added': 0, 'model_fits': 0,
              'training_eligible_added': 0, 'max_age_seconds': MAX_AGE_SECONDS,
              'age_policy': 'public_control_recency_not_calibrated_model_cutoff',
              'request_limit': client.limit, 'stage': 'capture'}
    try:
        collect([dict(CANDIDATE)], work/'capture', client, smoke=True, search_diagnostics=True)
        reference = as_of or datetime.now(timezone.utc).isoformat()
        report.update(as_of=reference, stage='feature_extraction')
        build(work/'capture', work/'features', as_of=reference, max_age_seconds=MAX_AGE_SECONDS)
        quality = json.loads((work/'features/public/feature_quality.json').read_bytes())
        report.update(readiness(quality), stage='completed')
    except Exception:
        # Exact provider details/paths remain in private checkpoints, never logs.
        report.update(status='FAIL', failure_code='capture_or_feature_validation_failed')
    finally:
        report['requests'] = client.requests
        write_json(work/'readiness.json', report)
        publish.mkdir(parents=True, mode=0o700)
        receipt = seal_directory(work, publish/'evidence.enc', recipient)
        write_json(publish/'encryption_receipt.json', receipt)
        write_json(publish/'readiness.json', report)
        quality_file = work/'features/public/feature_quality.json'
        if quality_file.is_file():
            write_json(publish/'feature_quality.json', json.loads(quality_file.read_bytes()))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--publish', type=Path, required=True)
    parser.add_argument('--public-key', type=Path,
                        default=ROOT/'research/urlscan_v1/config/evidence-recipient.pem')
    args = parser.parse_args()
    try:
        client = Client(os.environ.pop('URLSCAN_API_KEY', ''), request_limit=REQUEST_LIMIT,
                        interval=INTERVAL_SECONDS)
        report = run(args.work, args.publish, args.public_key, client)
        provenance = {}
        for env, name, pattern in (('GITHUB_SHA','workflow_checkout_sha',r'[0-9a-f]{40}'),
                ('SOURCE_HEAD_SHA','source_head_sha',r'[0-9a-f]{40}'),
                ('GITHUB_RUN_ID','run_id',r'[0-9]+'), ('GITHUB_RUN_ATTEMPT','run_attempt',r'[0-9]+')):
            value = os.environ.get(env, '')
            if re.fullmatch(pattern, value):
                provenance[name] = value
        write_json(args.publish/'execution.json', provenance)
        print(encoded(report).decode())
        if not report.get('contract_check_passed'):
            raise SystemExit(2)
    except (ValueError, OSError) as exc:
        raise SystemExit('public_smoke_configuration_or_storage_failed') from None


if __name__ == '__main__':
    main()
