"""Bounded cloud capture with private Secret input and encryption-before-upload output."""
import argparse
import json
import os
from pathlib import Path
import shutil

from .client import Client, CaptureError, decode_body
from .collector import collect, encoded, sha, validate_candidates, write_json
from .secure_store import (fingerprint, public_key, seal_directory, unb64, write_new)
from .similarity import acquired_records, build

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT/'research/urlscan_v1/config'


def prepare_candidates(config, secret):
    if config.get('version') != 1 or config.get('enabled') is not True:
        raise ValueError('batch disabled or invalid config')
    if not secret or len(secret) > 48*1024:
        raise ValueError('candidate secret missing or too large')
    blob = unb64(secret)
    if sha(blob) != config['compressed_input_sha256']:
        raise ValueError('compressed input binding mismatch')
    if not blob.startswith(b'\x1f\x8b'):
        raise ValueError('gzip input required')
    raw, _ = decode_body(blob, {}, 2_000_000)
    if sha(raw) != config['plaintext_input_sha256']:
        raise ValueError('plaintext input binding mismatch')
    candidates = [json.loads(line) for line in raw.splitlines() if line.strip()]
    validate_candidates(candidates)
    offset, limit, budget = config['offset'], config['limit'], config['request_limit']
    if any(type(v) is not int for v in (offset, limit, budget)) or not 0 <= offset < len(candidates) or not 1 <= limit <= 20 or not 1 <= budget <= 100:
        raise ValueError('batch bounds invalid')
    selected = candidates[offset:offset+limit]
    if len(selected) != limit:
        raise ValueError('batch extends beyond input')
    return selected


def run(work, publish, recipient, client, *, candidates, smoke=False, provenance=None):
    if work.exists() or publish.exists():
        raise ValueError('output already exists')
    # Validate encryption configuration before the first API request.
    public_key(recipient.read_bytes())
    work.mkdir(parents=True, mode=0o700)
    write_new(work/'input.jsonl', b''.join(encoded(c)+b'\n' for c in candidates))
    write_json(work/'execution.json', provenance or {})
    summary = None
    try:
        summary = collect(candidates, work/'capture', client, smoke=smoke)
        similarity = build(list(acquired_records(work/'capture')), work/'similarity')
    finally:
        # A partial run is also encrypted. No uploader ever targets work/.
        publish.mkdir(parents=True, mode=0o700)
        receipt = seal_directory(work, publish/'evidence.enc', recipient)
        write_json(publish/'encryption_receipt.json', receipt)
    if summary is not None:
        write_json(publish/'dataset_attrition_report.json', summary)
        write_json(publish/'similarity_summary.json', similarity)
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--publish', type=Path, required=True)
    p.add_argument('--public-key', type=Path, default=CONFIG/'evidence-recipient.pem')
    p.add_argument('--config', type=Path, default=CONFIG/'cloud_batch.json')
    p.add_argument('--smoke', action='store_true')
    a = p.parse_args()
    if a.smoke:
        candidates = [{'review_id': 'example-com-smoke', 'url': 'https://example.com/', 'scope': 'smoke_test'}]
        budget, interval = 15, 12
        provenance = {'mode': 'encrypted_smoke'}
    else:
        config = json.loads(a.config.read_text())
        secret = os.environ.pop('URLSCAN_CANDIDATES_GZIP_B64', '')
        if not secret:
            raise CaptureError('missing_private_candidates_secret')
        candidates = prepare_candidates(config, secret)
        del secret
        if fingerprint(public_key(a.public_key.read_bytes())) != config['recipient_sha256']:
            raise ValueError('recipient binding mismatch')
        budget, interval = config['request_limit'], max(12, config['interval_seconds'])
        provenance = {'mode': 'historical_development_audit', 'config': config}
    provenance.update(git_sha=os.environ.get('GITHUB_SHA'), run_id=os.environ.get('GITHUB_RUN_ID'),
        run_attempt=os.environ.get('GITHUB_RUN_ATTEMPT'))
    client = Client(os.environ.pop('URLSCAN_API_KEY', ''), request_limit=budget, interval=interval)
    result = run(a.work, a.publish, a.public_key, client, candidates=candidates, smoke=a.smoke, provenance=provenance)
    print(encoded(result).decode())
    if result['run_status'] == 'STOPPED':
        raise SystemExit(3)
    if a.smoke and result['completeness_counts'].get('COMPLETE') != 1:
        raise SystemExit(2)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(encoded({'status': 'failed', 'code': getattr(exc, 'code', 'batch_validation_or_storage_failed')}).decode())
        raise SystemExit(1) from None
