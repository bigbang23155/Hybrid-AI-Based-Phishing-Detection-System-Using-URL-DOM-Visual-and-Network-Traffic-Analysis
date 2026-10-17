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
SECRET_PART_BYTES = 32_000  # Conservative headroom below GitHub's 48 KB limit.
MAX_SECRET_PARTS = 8


def split_candidate_secret(secret):
    """Split ASCII Base64 without changing its bytes; never truncate the pool."""
    if not isinstance(secret, str) or not secret or not secret.isascii():
        raise ValueError('invalid candidate secret encoding')
    if len(secret) > SECRET_PART_BYTES * MAX_SECRET_PARTS:
        raise ValueError('candidate secret exceeds supported input size')
    return [secret[i:i+SECRET_PART_BYTES] for i in range(0, len(secret), SECRET_PART_BYTES)]


def read_candidate_secret(config, environ):
    """Consume only the configured input scheme, before creating an API client."""
    if config.get('version') == 1:
        secret = environ.pop('URLSCAN_CANDIDATES_GZIP_B64', '').strip()
        if not secret:
            raise CaptureError('missing_private_candidates_secret')
        if not secret.isascii() or len(secret) > SECRET_PART_BYTES:
            raise CaptureError('candidate_secret_requires_chunked_setup')
        return secret
    count = config.get('input_secret_parts')
    size = config.get('input_encoded_bytes')
    if (config.get('version') != 2 or type(count) is not int or not 1 <= count <= MAX_SECRET_PARTS
            or type(size) is not int or not 1 <= size <= count * SECRET_PART_BYTES):
        raise ValueError('invalid chunked input config')
    parts = []
    for index in range(1, count + 1):
        part = environ.pop(f'URLSCAN_CANDIDATES_GZIP_B64_{index:02d}', '').strip()
        if not part:
            raise CaptureError('missing_private_candidates_secret_part')
        if not part.isascii() or len(part) > SECRET_PART_BYTES:
            raise CaptureError('invalid_private_candidates_secret_part')
        parts.append(part)
    secret = ''.join(parts)
    if len(secret) != size or parts != split_candidate_secret(secret):
        raise CaptureError('private_candidates_secret_parts_size_mismatch')
    return secret


def prepare_candidates(config, secret):
    if config.get('version') not in (1, 2) or config.get('enabled') is not True:
        raise ValueError('batch disabled or invalid config')
    max_size = SECRET_PART_BYTES if config['version'] == 1 else SECRET_PART_BYTES * MAX_SECRET_PARTS
    if not secret or not secret.isascii() or len(secret) > max_size:
        raise ValueError('candidate secret missing or too large')
    if config['version'] == 2 and len(secret) != config.get('input_encoded_bytes'):
        raise ValueError('candidate secret size mismatch')
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


def run(work, publish, recipient, client, *, candidates, smoke=False, provenance=None, search_diagnostics=False):
    if work.exists() or publish.exists():
        raise ValueError('output already exists')
    # Validate encryption configuration before the first API request.
    public_key(recipient.read_bytes())
    work.mkdir(parents=True, mode=0o700)
    write_new(work/'input.jsonl', b''.join(encoded(c)+b'\n' for c in candidates))
    write_json(work/'execution.json', provenance or {})
    summary = None
    try:
        summary = collect(candidates, work/'capture', client, smoke=smoke, search_diagnostics=search_diagnostics)
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
        secret = read_candidate_secret(config, os.environ)
        candidates = prepare_candidates(config, secret)
        del secret
        if fingerprint(public_key(a.public_key.read_bytes())) != config['recipient_sha256']:
            raise ValueError('recipient binding mismatch')
        budget, interval = config['request_limit'], max(12, config['interval_seconds'])
        provenance = {'mode': 'historical_development_audit', 'config': config}
    provenance.update(git_sha=os.environ.get('GITHUB_SHA'), run_id=os.environ.get('GITHUB_RUN_ID'),
        run_attempt=os.environ.get('GITHUB_RUN_ATTEMPT'))
    client = Client(os.environ.pop('URLSCAN_API_KEY', ''), request_limit=budget, interval=interval)
    result = run(a.work, a.publish, a.public_key, client, candidates=candidates, smoke=a.smoke, provenance=provenance,
        search_diagnostics=False if a.smoke else config.get('search_diagnostics', False))
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
