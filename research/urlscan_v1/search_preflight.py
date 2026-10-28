"""Account-specific search horizon and fixed public positive controls; GET only."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from .client import Client, CaptureError, json_object, scan_id, search_metadata
from .collector import normalized_url, timestamp, write_json

URL = 'https://example.com/'
STRATEGIES = [('submitted_exact', 'task.url.keyword', URL),
              ('final_url_exact', 'page.url.keyword', URL),
              ('submitted_host_context', 'task.domain.keyword', 'example.com')]


def check(client, *, now=None):
    now = now or datetime.now(timezone.utc)
    report = {'checked_at': now.isoformat(), 'control_url': URL,
              'scope': 'fixed_public_example_only', 'queries': [],
              'result_identity_check': 'NOT_RUN', 'positive_controls': 'INCOMPLETE',
              'historical_candidates_searched': 0, 'new_scans_submitted': 0,
              'history_limit_status': 'UNKNOWN', 'account_search_date_limit_days': None,
              'errors': []}
    reference = None
    try:
        for strategy, field, value in STRATEGIES:
            obj = client.search(value, field=field, public_only=True)
            metadata = search_metadata(obj)
            eligible = []
            for hit in obj['results']:
                try:
                    task = hit['task']
                    if task.get('visibility') != 'public':
                        continue
                    submitted = normalized_url(task.get('url'))
                    if field == 'task.url.keyword' and submitted != URL:
                        continue
                    if field == 'page.url.keyword' and normalized_url(hit['page'].get('url')) != URL:
                        continue
                    if field == 'task.domain.keyword' and urlsplit(submitted).hostname != 'example.com':
                        continue
                    when = timestamp(task.get('time'))
                    # A known recent positive control, not an arbitrary old example.
                    age = (now - when).total_seconds()
                    if not -300 <= age <= 7 * 86400:
                        continue
                    eligible.append((when, scan_id(hit.get('_id'))))
                except (CaptureError, KeyError, TypeError, AttributeError):
                    continue
            report['queries'].append({'strategy': strategy, 'field': field,
                'returned': len(obj['results']), 'valid_recent_public_hits': len(eligible),
                'control_status': 'PASS' if eligible else 'FAIL', **metadata})
            if strategy == 'submitted_exact' and eligible:
                reference = max(eligible)
        if reference:
            when, uuid = reference
            obj = json_object(client.result(uuid))
            task = obj.get('task')
            if (not isinstance(task, dict) or task.get('uuid') != uuid
                    or task.get('visibility') != 'public'
                    or normalized_url(task.get('url')) != URL
                    or timestamp(task.get('time')) != when):
                raise CaptureError('positive_control_result_identity_mismatch')
            report.update(result_identity_check='PASS', reference_scan_uuid=uuid,
                          reference_scan_time=when.isoformat())
    except CaptureError as exc:
        report['errors'].append({'code': exc.code, 'http_status': exc.status})
    queries = report['queries']
    reported = [q['search_date_limit_days'] for q in queries if q['search_date_limit_days_state'] == 'reported']
    if len(reported) == 3 and len(set(reported)) == 1:
        days = reported[0]
        report.update(history_limit_status='PROVIDER_REPORTED_CONSISTENT',
                      account_search_date_limit_days=days,
                      approximate_search_cutoff_utc=(now-timedelta(days=days)).isoformat())
    elif reported:
        report['history_limit_status'] = 'PARTIAL_OR_INCONSISTENT'
    if len(queries) == 3 and all(q['control_status'] == 'PASS' for q in queries) and report['result_identity_check'] == 'PASS':
        report['positive_controls'] = 'PASS'
    else:
        report['positive_controls'] = 'FAIL'
    report['requests'] = client.requests
    report['request_limit'] = client.limit
    report['history_interpretation'] = 'provider_search_visibility_window_not_retention_or_result_endpoint_limit'
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    client = Client(os.environ.pop('URLSCAN_API_KEY', ''), request_limit=12, interval=12)
    report = check(client)
    args.output.mkdir(parents=True, exist_ok=False)
    report.update(git_sha=os.environ.get('GITHUB_SHA'), run_id=os.environ.get('GITHUB_RUN_ID'))
    write_json(args.output/'search_preflight.json', report)
    print(json.dumps(report, sort_keys=True))
    if report['positive_controls'] != 'PASS':
        raise SystemExit(2)


if __name__ == '__main__':
    try:
        main()
    except (CaptureError, ValueError, OSError) as exc:
        print(json.dumps({'status': 'failed', 'code': getattr(exc, 'code', 'search_preflight_validation_failed')}))
        raise SystemExit(1) from None
