"""Read-only historical evidence collector and safe public-example smoke test."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import struct
from urllib.parse import urlsplit, urlunsplit
import zlib

from . import VERSION
from .client import CaptureError, Client, json_object, scan_id

ROOT = Path(__file__).resolve().parents[2]
QUEUE = ROOT / 'research/robustness_v1/evidence/intake/review_queue_blinded.jsonl'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()


def write_json(path, obj):
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_bytes(encoded(obj) + b'\n')
    temp.replace(path)


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines() if line.strip()]


def utc():
    return datetime.now(timezone.utc).isoformat()


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.utcoffset() is None:
            raise ValueError()
        return parsed
    except (ValueError, AttributeError, TypeError):
        raise CaptureError('missing_or_invalid_scan_time') from None


def normalized_url(value):
    try:
        if not isinstance(value, str) or any(ord(c) < 33 for c in value):
            raise ValueError()
        p = urlsplit(value)
        if p.scheme not in ('https', 'http') or not p.hostname or p.username or p.password:
            raise ValueError()
        port = p.port
        host = p.hostname.lower()
        if ':' in host:
            host = '[' + host + ']'
        if port is not None and (p.scheme, port) not in (('http', 80), ('https', 443)):
            host += ':' + str(port)
        # Preserve query, case-sensitive path and SPA fragment. No tracking removal.
        return urlunsplit((p.scheme.lower(), host, p.path or '/', p.query, p.fragment))
    except (ValueError, TypeError):
        raise CaptureError('invalid_candidate_url') from None


def validate_candidates(candidates, queue_path=QUEUE, *, smoke=False):
    if not candidates:
        raise ValueError('empty candidate list')
    known = {r['review_id']: r for r in rows(queue_path)} if not smoke else {}
    seen = set()
    for c in candidates:
        rid = c.get('review_id')
        if not isinstance(rid, str) or rid in seen:
            raise ValueError('missing or duplicate review ID')
        seen.add(rid)
        normalized_url(c.get('url'))
        if smoke:
            if c != {'review_id': 'example-com-smoke', 'url': 'https://example.com/', 'scope': 'smoke_test'}:
                raise ValueError('smoke input must be the fixed public example')
        else:
            q = known.get(rid)
            if not q or c.get('scope') != 'historical_development_audit':
                raise ValueError('only queued historical development packets supported in v1')
            if any(c.get(k) != q[k] for k in ('sample_id', 'html_sha256')):
                raise ValueError('historical identity binding mismatch')
            if c.get('scan_uuid'):
                scan_id(c['scan_uuid'])


class Tags(HTMLParser):
    def __init__(self):
        super().__init__(); self.count = 0
    def handle_starttag(self, tag, attrs):
        self.count += 1


def validate_png(data):
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        raise CaptureError('invalid_png')
    offset, kinds, dimensions = 8, [], None
    while offset + 12 <= len(data):
        size = struct.unpack('>I', data[offset:offset+4])[0]
        kind = data[offset+4:offset+8]
        end = offset + 12 + size
        if end > len(data):
            raise CaptureError('invalid_png')
        chunk = data[offset+4:offset+8+size]
        if zlib.crc32(chunk) & 0xffffffff != struct.unpack('>I', data[end-4:end])[0]:
            raise CaptureError('invalid_png')
        if not kinds:
            if kind != b'IHDR' or size != 13:
                raise CaptureError('invalid_png')
            dimensions = struct.unpack('>II', data[offset+8:offset+16])
            if not all(0 < v <= 100000 for v in dimensions):
                raise CaptureError('invalid_png')
        kinds.append(kind); offset = end
        if kind == b'IEND':
            if size or offset != len(data) or b'IDAT' not in kinds:
                raise CaptureError('invalid_png')
            return dimensions
    raise CaptureError('invalid_png')


def find_scan(client, url, record, *, diagnostics=False):
    """Bounded discovery; broader hits never relax the task-URL evidence gate."""
    strategies = [('submitted_exact', 'task.url.keyword', url)]
    if diagnostics:
        canonical = normalized_url(url)
        if canonical != url:
            strategies.append(('normalized_exact', 'task.url.keyword', canonical))
        strategies.extend([('final_url_exact', 'page.url.keyword', canonical),
                           ('submitted_host_context', 'task.domain.keyword', urlsplit(url).hostname)])
    record['search_diagnostics'] = []
    record['search_window'] = 'latest_10_per_query_no_exhaustive_history_claim'
    for strategy, field, value in strategies:
        search = client.search(value, field=field, public_only=diagnostics)
        matches, rejected = [], Counter()
        for hit in search['results']:
            try:
                if not isinstance(hit, dict) or not isinstance(hit.get('task'), dict):
                    rejected['invalid_hit'] += 1
                    continue
                task = hit['task']
                if task.get('visibility') != 'public':
                    rejected['non_public'] += 1
                    continue
                if normalized_url(task.get('url')) != normalized_url(url):
                    rejected['different_submitted_url'] += 1
                    continue
                matches.append((timestamp(task.get('time')), scan_id(hit.get('_id'))))
            except (CaptureError, AttributeError):
                rejected['invalid_identity_or_time'] += 1
        diagnostic = {'strategy': strategy, 'returned': len(search['results']),
            'exact_public_matches': len(matches), 'rejected': dict(rejected),
            'has_more': search.get('has_more') if isinstance(search.get('has_more'), bool) else None}
        record['search_diagnostics'].append(diagnostic)
        record['search_candidates_returned'] = sum(d['returned'] for d in record['search_diagnostics'])
        record['search_exact_public_matches'] = len(matches)
        if matches:
            record['selected_search_strategy'] = strategy
            return max(matches)[1]
    raise CaptureError('no_exact_public_scan_in_search_window')


def capture(client, candidate, folder, *, search_diagnostics=False):
    record = {'candidate_sha256': sha(encoded(candidate)), 'review_id': candidate['review_id'],
        'scope': candidate['scope'], 'requested_url': candidate['url'], 'retrieved_at': utc(),
        'provider': 'urlscan.io', 'collector_version': VERSION,
        'artifacts': {}, 'errors': {}, 'quality_flags': [],
        'human_review_status': 'pending', 'eligible_for_training': False,
        'network_representation': 'HTTP_METADATA_NOT_HAR_OR_PCAP',
        'original_snapshot_sha256': candidate.get('html_sha256'),
        'original_captured_at': candidate.get('captured_at'),
        'publisher_date': candidate.get('publisher_date'),
        'historical_equivalence': 'unverified'}

    def save(kind, data, filename, transfer=None):
        path = folder / filename
        path.write_bytes(data)
        record['artifacts'][kind] = {'file': filename, 'sha256': sha(data), 'bytes': len(data), 'transport': transfer}

    try:
        uuid = candidate.get('scan_uuid')
        if not uuid:
            uuid = find_scan(client, candidate['url'], record, diagnostics=search_diagnostics)
        record['scan_uuid'] = scan_id(uuid)
        response = client.result(uuid)
        obj = json_object(response)
        task, page = obj.get('task'), obj.get('page')
        if not isinstance(task, dict) or not isinstance(page, dict):
            raise CaptureError('invalid_result_shape')
        if task.get('uuid') != uuid or normalized_url(task.get('url')) != normalized_url(candidate['url']):
            raise CaptureError('scan_identity_mismatch')
        if task.get('visibility') != 'public':
            raise CaptureError('non_public_scan_not_supported')
        scan_time = timestamp(task.get('time'))
        record.update(scan_time=scan_time.isoformat(), submitted_url=task['url'],
            final_url=page.get('url'), page_status=page.get('status'),
            provider_source=task.get('source'), scan_visibility='public')
        if normalized_url(page.get('url')) != normalized_url(candidate['url']):
            record['quality_flags'].append('redirected')
        if candidate.get('captured_at'):
            record['capture_time_delta_seconds'] = (scan_time - timestamp(candidate['captured_at'])).total_seconds()
        else:
            record['capture_time_delta_seconds'] = None
            record['quality_flags'].append('original_capture_time_unknown')
        if str(page.get('status')) in ('401', '403', '429'):
            record['quality_flags'].append('access_blocked')
        elif page.get('status') is None:
            record['quality_flags'].append('page_status_unknown')
        elif str(page.get('status')).startswith(('4', '5')):
            record['quality_flags'].append('page_http_error')
        data = obj.get('data')
        requests = data.get('requests') if isinstance(data, dict) else None
        record['http_requests_available'] = isinstance(requests, list) and bool(requests)
        record['http_request_count'] = len(requests) if isinstance(requests, list) else None
        if not record['http_requests_available']:
            record['quality_flags'].append('http_metadata_missing_or_empty')
        save('result', response.body, 'result.json', response.transfer)
        for kind, fetch, filename in (('dom', client.dom, 'dom.html.txt'),
                                      ('screenshot', client.screenshot, 'screenshot.png')):
            try:
                attachment = fetch(uuid)
                if kind == 'dom':
                    text = attachment.body.decode('utf-8-sig')
                    parser = Tags(); parser.feed(text)
                    if not parser.count:
                        raise CaptureError('dom_has_no_markup')
                    record['dom_tag_count'] = parser.count
                    if parser.count < 20:
                        record['quality_flags'].append('low_dom_content')
                    if sha(attachment.body) == candidate.get('html_sha256'):
                        record['historical_equivalence'] = 'exact_dom_bytes_only_time_and_label_unverified'
                else:
                    record['screenshot_dimensions'] = validate_png(attachment.body)
                save(kind, attachment.body, filename, attachment.transfer)
            except (CaptureError, UnicodeError) as exc:
                record['errors'][kind] = {'code': getattr(exc, 'code', 'invalid_utf8'),
                    'http_status': getattr(exc, 'status', None)}
                if getattr(exc, 'code', '') in ('authentication_or_access_denied', 'rate_limited',
                        'retry_deferred', 'request_budget_exhausted'):
                    raise
    except CaptureError as exc:
        record['errors']['capture'] = {'code': exc.code, 'http_status': exc.status}
    have = record['artifacts']
    record['completeness'] = 'COMPLETE' if len(have) == 3 and record.get('http_requests_available') else 'PARTIAL' if have else 'NONE'
    record['evidence_status'] = 'REVIEW_REQUIRED' if have else 'UNAVAILABLE'
    return record


def verify_checkpoint(record, candidate, folder):
    if record.get('candidate_sha256') != sha(encoded(candidate)):
        raise ValueError('checkpoint candidate changed')
    for artifact in record['artifacts'].values():
        path = (folder / artifact['file']).resolve()
        if not path.is_relative_to(folder.resolve()) or not path.is_file() or sha(path.read_bytes()) != artifact['sha256']:
            raise ValueError('checkpoint artifact integrity failure')


def collect(candidates, output, client, *, resume=False, retry_incomplete=False, smoke=False, search_diagnostics=False):
    validate_candidates(candidates, smoke=smoke)
    identity = {'version': VERSION, 'input_sha256': sha(encoded(candidates)),
        'candidates': len(candidates), 'search_size': 10, 'policy': 'exact_public_get_only',
        'search_diagnostics': search_diagnostics}
    if resume:
        if json.loads((output/'run.json').read_text()) != identity:
            raise ValueError('resume identity mismatch')
    else:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        write_json(output/'run.json', identity)
    private, public = output/'private', output/'public'
    private.mkdir(exist_ok=True, mode=0o700); public.mkdir(exist_ok=True)
    records, stopped = [], False
    for candidate in candidates:
        folder = private / sha(encoded(candidate))
        folder.mkdir(exist_ok=True, mode=0o700)
        checkpoint = folder/'record.json'
        record = json.loads(checkpoint.read_text()) if checkpoint.exists() else None
        if record:
            verify_checkpoint(record, candidate, folder)
        if not record or (retry_incomplete and record['completeness'] != 'COMPLETE'):
            if stopped:
                continue  # Explicitly counted as unattempted below.
            record = capture(client, candidate, folder, search_diagnostics=search_diagnostics)
            write_json(checkpoint, record)
            stopped = any(e['code'] in ('authentication_or_access_denied', 'rate_limited',
                'retry_deferred', 'request_budget_exhausted') for e in record['errors'].values())
        records.append(record)
    summary = {'collector_version': VERSION, 'candidates': len(candidates),
        'recorded_candidates': len(records), 'unattempted_candidates': len(candidates)-len(records),
        'requests_this_invocation': client.requests, 'request_limit': client.limit,
        'completeness_counts': dict(Counter(r['completeness'] for r in records)),
        'quality_flag_counts': dict(Counter(f for r in records for f in r['quality_flags'])),
        'error_counts': dict(Counter(e['code'] for r in records for e in r['errors'].values())),
        'available_artifact_counts': dict(Counter(k for r in records for k in r['artifacts'])),
        'search_strategy_counts': dict(Counter(d['strategy'] for r in records for d in r.get('search_diagnostics', []))),
        'search_returned_hit_counts': dict(sum((Counter({d['strategy']: d['returned']}) for r in records for d in r.get('search_diagnostics', [])), Counter())),
        'search_rejection_counts': dict(sum((Counter(d['rejected']) for r in records for d in r.get('search_diagnostics', [])), Counter())),
        'new_scans_submitted': 0, 'human_reviews_added': 0, 'training_eligible_added': 0,
        'original_dataset_writes': 0, 'model_fits': 0,
        'input_sha256': identity['input_sha256'], 'smoke_test': smoke,
        'complete_means': 'files and HTTP requests present; not correctness or historical equivalence',
        'run_status': 'STOPPED' if stopped else 'FINISHED'}
    write_json(public/'dataset_attrition_report.json', summary)
    manifest = [{'candidate_sha256': r['candidate_sha256'], 'completeness': r['completeness'],
        'artifacts': {k: {'sha256': v['sha256'], 'bytes': v['bytes']} for k, v in r['artifacts'].items()}}
        for r in records]
    write_json(public/'artifact_hashes.json', manifest)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--smoke', action='store_true')
    source.add_argument('--input', type=Path, help='private original historical development packets JSONL')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-limit', type=int, default=30)
    parser.add_argument('--limit', type=int, default=5)
    parser.add_argument('--interval', type=float, default=12)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--retry-incomplete', action='store_true')
    args = parser.parse_args()
    if args.limit < 1 or args.retry_incomplete and not args.resume:
        parser.error('positive limit required; retry-incomplete requires resume')
    candidates = [{'review_id': 'example-com-smoke', 'url': 'https://example.com/', 'scope': 'smoke_test'}] if args.smoke else rows(args.input)
    # Validate the full input before slicing, so invalid trailing packets cannot hide.
    validate_candidates(candidates, smoke=args.smoke)
    client = Client(os.environ.get('URLSCAN_API_KEY'), request_limit=args.request_limit, interval=args.interval)
    result = collect(candidates[:args.limit], args.output, client, resume=args.resume,
        retry_incomplete=args.retry_incomplete, smoke=args.smoke)
    print(json.dumps(result, sort_keys=True))
    if args.smoke and result['completeness_counts'].get('COMPLETE') != 1:
        raise SystemExit(2)
    if result['run_status'] == 'STOPPED':
        raise SystemExit(3)


if __name__ == '__main__':
    try:
        main()
    except (CaptureError, ValueError, OSError) as exc:
        # Private paths, provider response bodies and input URLs are never printed.
        print(json.dumps({'status': 'failed', 'code': getattr(exc, 'code', 'local_validation_or_io_error')}))
        raise SystemExit(1) from None
