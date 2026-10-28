"""Search coverage must be provider-reported, never inferred from no hits."""
from datetime import datetime, timezone
import json
import unittest

from research.urlscan_v1.client import search_metadata
from research.urlscan_v1.search_preflight import check, URL
from research.urlscan_v1.test_urlscan import Fake, TASK, UUID, response

NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)


def fixture(limit=30):
    hit = {'_id': UUID, 'task': TASK, 'page': {'url': URL},
           'untrusted_extra': 'do-not-publish-raw-response'}
    search = {'results': [hit], 'total': 12, 'has_more': False, 'took': 2}
    if limit is not None:
        search['search_date_limit_days'] = limit
    return [response(search) for _ in range(3)] + [response({'task': TASK})]


class SearchPreflightTests(unittest.TestCase):
    def test_account_limit_and_three_independent_positive_controls(self):
        f = Fake(fixture())
        r = check(f.client, now=NOW)
        self.assertEqual(r['positive_controls'], 'PASS')
        self.assertEqual(r['account_search_date_limit_days'], 30)
        self.assertEqual(r['history_limit_status'], 'PROVIDER_REPORTED_CONSISTENT')
        self.assertEqual(r['approximate_search_cutoff_utc'], '2026-09-17T00:00:00+00:00')
        self.assertEqual(f.client.requests, 4)
        for value in ('do-not-publish-raw-response', 'secret-test-value'):
            self.assertNotIn(value, json.dumps(r))

    def test_missing_limit_is_unknown_not_unlimited(self):
        r = check(Fake(fixture(None)).client, now=NOW)
        self.assertEqual(r['positive_controls'], 'PASS')
        self.assertEqual(r['history_limit_status'], 'UNKNOWN')
        self.assertIsNone(r['account_search_date_limit_days'])
        self.assertNotIn('approximate_search_cutoff_utc', r)

    def test_malformed_limits_and_total_are_not_coerced(self):
        for value in (True, -1, '30', None, 10**20):
            r = search_metadata({'search_date_limit_days': value})
            self.assertEqual(r['search_date_limit_days_state'], 'invalid')
            self.assertIsNone(r['search_date_limit_days'])
        r = search_metadata({'total': 12, 'has_more': False})
        self.assertEqual(r['total'], 12)
        self.assertIn('not_page_exhaustion', r['has_more_semantics'])

    def test_inconsistent_limits_cannot_be_reported_as_confirmed(self):
        data = fixture()
        obj = json.loads(data[1].body); obj['search_date_limit_days'] = 7
        data[1] = response(obj)
        r = check(Fake(data).client, now=NOW)
        self.assertEqual(r['history_limit_status'], 'PARTIAL_OR_INCONSISTENT')
        self.assertIsNone(r['account_search_date_limit_days'])

    def test_all_zero_is_control_failure_even_with_known_limit(self):
        f = Fake([response({'results': [], 'total': 0, 'search_date_limit_days': 30}) for _ in range(3)])
        r = check(f.client, now=NOW)
        self.assertEqual(r['positive_controls'], 'FAIL')
        self.assertEqual(r['account_search_date_limit_days'], 30)
        self.assertEqual(r['result_identity_check'], 'NOT_RUN')
        self.assertEqual(f.client.requests, 3)

    def test_result_mismatch_and_budget_fail_without_raw_error(self):
        data = fixture(); data[-1] = response({'task': dict(TASK, url='https://other.example/')})
        r = check(Fake(data).client, now=NOW)
        self.assertEqual(r['positive_controls'], 'FAIL')
        self.assertEqual(r['errors'][0]['code'], 'positive_control_result_identity_mismatch')
        r = check(Fake(fixture(), budget=1).client, now=NOW)
        self.assertEqual(r['positive_controls'], 'FAIL')
        self.assertEqual(r['requests'], 1)
        self.assertEqual(r['history_limit_status'], 'PARTIAL_OR_INCONSISTENT')

    def test_old_hit_cannot_pass_recent_control(self):
        data = fixture()
        for i in range(3):
            obj = json.loads(data[i].body)
            obj['results'][0]['task']['time'] = '2020-01-01T00:00:00Z'
            data[i] = response(obj)
        r = check(Fake(data).client, now=NOW)
        self.assertEqual(r['positive_controls'], 'FAIL')
        self.assertEqual(r['result_identity_check'], 'NOT_RUN')
