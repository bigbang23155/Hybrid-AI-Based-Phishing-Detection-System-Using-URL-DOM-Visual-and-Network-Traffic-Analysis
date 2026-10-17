"""Allowlisted urlscan HTTP aggregates; no PCAP, verdicts, tags or reputation."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from .contract import encoded, feature_set, sha, unavailable_features

VERSION = 'urlscan-network-http-v1'
MAX_REQUESTS = 100000


@dataclass(frozen=True)
class Definition:
    name: str
    unit: str
    source: str
    definition: str


# This tuple fixes the column order. Missing inputs invalidate the affected
# aggregate, instead of silently changing its denominator to successful rows.
DEFINITIONS = (
    Definition('request_record_count', 'count', 'data.requests', 'Length of supplied list, including malformed records; not unique requests or redirect hops.'),
    Definition('http_request_count', 'count', 'data.requests[].request.request.url', 'Count of HTTP(S) URLs; null if any URL is missing/invalid.'),
    Definition('unique_http_host_count', 'count', 'data.requests[].request.request.url', 'Distinct lowercase HTTP hostnames; no DNS lookup, no eTLD+1 grouping.'),
    Definition('https_request_ratio', 'ratio', 'data.requests[].request.request.url', 'HTTPS / HTTP(S) requests; excludes valid non-HTTP schemes.'),
    Definition('cross_host_request_ratio', 'ratio', 'data.requests[].request.request.url; page.url', 'HTTP(S) requests whose hostname differs from final page hostname / HTTP(S) requests; not third-party ownership.'),
    Definition('post_request_ratio', 'ratio', 'data.requests[].request.request.method', 'Case-normalized POST / all request records.'),
    Definition('xhr_fetch_request_ratio', 'ratio', 'data.requests[].request.type', 'Types XHR or Fetch / all request records.'),
    Definition('response_3xx_ratio', 'ratio', 'data.requests[].response.response.status', 'Statuses 300..399 / all request records; not a redirect-chain length.'),
    Definition('response_4xx_ratio', 'ratio', 'data.requests[].response.response.status', 'Statuses 400..499 / all request records.'),
    Definition('response_5xx_ratio', 'ratio', 'data.requests[].response.response.status', 'Statuses 500..599 / all request records.'),
    Definition('unique_mime_count', 'count', 'data.requests[].response.response.mimeType', 'Distinct lowercase MIME types before semicolon; empty strings are unknown.'),
    Definition('javascript_response_ratio', 'ratio', 'data.requests[].response.response.mimeType', 'MIME in text/javascript, application/javascript, application/x-javascript / all records.'),
    Definition('encoded_bytes_total', 'bytes', 'data.requests[].response.encodedDataLength', 'Sum of reported nonnegative integer encoded lengths; no fallback to decoded bytes, not packet traffic.'),
    Definition('decoded_bytes_total', 'bytes', 'data.requests[].response.dataLength', 'Sum of reported nonnegative integer decoded lengths.'),
    Definition('cookie_count', 'count', 'data.cookies', 'Number of supplied cookie objects; null for malformed elements.'),
    Definition('secure_cookie_ratio', 'ratio', 'data.cookies[].secure', 'True secure flags / supplied cookies; missing flag is unknown, not false.'),
    Definition('httponly_cookie_ratio', 'ratio', 'data.cookies[].httpOnly', 'True httpOnly flags / supplied cookies; missing flag is unknown, not false.'),
    Definition('main_status', 'status_code', 'page.status', 'Final page integer HTTP status 100..599, accepting decimal strings.'),
    Definition('main_uses_https', 'binary', 'page.url', 'Final HTTP(S) page uses HTTPS.'),
    Definition('main_host_changed', 'binary', 'task.url; page.url', 'Submitted and final HTTP(S) hostnames differ; not redirect count.'),
)
NAMES = tuple(d.name for d in DEFINITIONS)


def registry():
    return {'version': VERSION, 'representation': 'HTTP_METADATA_NOT_HAR_OR_PCAP',
            'features': [asdict(d) for d in DEFINITIONS],
            'missing_policy': 'null plus reason; all required rows must be observed; empty count=0; empty ratio=null',
            'max_request_records': MAX_REQUESTS,
            'excluded': ['verdicts', 'labels', 'tags', 'meta', 'reputation', 'response bodies', 'cookie values', 'request bodies']}


def get(obj, *keys):
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def url(value):
    if not text(value) or any(ord(c) < 33 for c in value):
        return None
    try:
        p = urlsplit(value)
        if not p.scheme:
            return None
        if p.scheme.lower() in ('http', 'https'):
            if not p.hostname:
                return None
            p.port  # reject malformed ports
        return p
    except ValueError:
        return None


def status(value):
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        value = int(value)
    return value if type(value) is int and 100 <= value <= 599 else None


def byte_count(value):
    # Avoid pathological integers and preserve exact downstream float conversion.
    return value if type(value) is int and 0 <= value <= 2**53 - 1 else None


def extract(result):
    if not isinstance(result, dict):
        return unavailable_features(VERSION, NAMES, 'invalid_result_object')
    values, reasons, support = {}, {}, {}

    def put(name, data, fn, *, ratio=False, context=True):
        valid = sum(x is not None for x in data) if data is not None else 0
        support[name] = {'observed': valid, 'expected': len(data) if data is not None else None}
        reason = ('missing_or_invalid_field' if data is None else
                  'incomplete_field_coverage' if valid != len(data) else
                  'missing_context' if not context else
                  'empty_denominator' if ratio and not data else None)
        values[name] = None if reason else fn(data)
        if reason:
            reasons[name] = reason

    requests = get(result, 'data', 'requests')
    if not isinstance(requests, list):
        requests = None
    if requests is not None and len(requests) > MAX_REQUESTS:
        return unavailable_features(VERSION, NAMES, 'request_limit_exceeded')
    put('request_record_count', requests, len)
    # A malformed element still contributes to the raw list length.
    if requests is not None:
        values['request_record_count'] = len(requests)
        reasons.pop('request_record_count', None)
        support['request_record_count']['observed'] = len(requests)

    def column(*path, convert=lambda x: x):
        return [convert(get(r, *path)) for r in requests] if requests is not None else None

    urls = column('request', 'request', 'url', convert=url)
    http_urls = None if urls is None or any(x is None for x in urls) else [p for p in urls if p.scheme.lower() in ('http', 'https')]
    page = url(get(result, 'page', 'url'))
    task = url(get(result, 'task', 'url'))
    page_ok = page is not None and page.scheme.lower() in ('http', 'https')
    task_ok = task is not None and task.scheme.lower() in ('http', 'https')
    put('http_request_count', urls, lambda ps: sum(p.scheme.lower() in ('http', 'https') for p in ps))
    put('unique_http_host_count', urls, lambda ps: len({p.hostname for p in ps if p.scheme.lower() in ('http', 'https')}))
    put('https_request_ratio', http_urls, lambda ps: sum(p.scheme.lower() == 'https' for p in ps)/len(ps), ratio=True)
    put('cross_host_request_ratio', http_urls, lambda ps: sum(p.hostname != page.hostname for p in ps)/len(ps), ratio=True, context=page_ok)
    methods = column('request', 'request', 'method', convert=text)
    kinds = column('request', 'type', convert=text)
    put('post_request_ratio', methods, lambda xs: sum(x.upper() == 'POST' for x in xs)/len(xs), ratio=True)
    put('xhr_fetch_request_ratio', kinds, lambda xs: sum(x.lower() in ('xhr','fetch') for x in xs)/len(xs), ratio=True)
    statuses = column('response', 'response', 'status', convert=status)
    for digit in (3, 4, 5):
        put(f'response_{digit}xx_ratio', statuses, lambda xs, d=digit: sum(x//100 == d for x in xs)/len(xs), ratio=True)
    mimes = column('response', 'response', 'mimeType', convert=lambda x: text(x.split(';')[0].lower()) if isinstance(x, str) else None)
    put('unique_mime_count', mimes, lambda xs: len(set(xs)))
    put('javascript_response_ratio', mimes, lambda xs: sum(x in ('text/javascript', 'application/javascript', 'application/x-javascript') for x in xs)/len(xs), ratio=True)
    for field, name in (('encodedDataLength','encoded_bytes_total'), ('dataLength','decoded_bytes_total')):
        put(name, column('response', field, convert=byte_count), sum)
    cookies = get(result, 'data', 'cookies')
    if not isinstance(cookies, list):
        cookies = None
    put('cookie_count', [c if isinstance(c,dict) else None for c in cookies] if cookies is not None else None, len)
    for field, name in (('secure','secure_cookie_ratio'), ('httpOnly','httponly_cookie_ratio')):
        flags = [get(c, field) if type(get(c, field)) is bool else None for c in cookies] if cookies is not None else None
        put(name, flags, lambda xs: sum(xs)/len(xs), ratio=True)
    put('main_status', [status(get(result, 'page', 'status'))], lambda xs: xs[0])
    put('main_uses_https', [page if page_ok else None], lambda xs: int(xs[0].scheme.lower() == 'https'))
    put('main_host_changed', [task if task_ok else None, page if page_ok else None], lambda xs: int(xs[0].hostname != xs[1].hostname))
    return feature_set(VERSION, {n: values[n] for n in NAMES}, reasons=reasons, support=support)


REGISTRY_SHA256 = sha(encoded(registry()))
