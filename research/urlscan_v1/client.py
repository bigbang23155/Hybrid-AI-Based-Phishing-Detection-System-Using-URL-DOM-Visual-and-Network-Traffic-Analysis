"""Bounded authenticated GETs to urlscan.io only. No submission API."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import http.client
import math
import re
import time
import zlib
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener

BASE = 'https://urlscan.io'
UUID = re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}')


class CaptureError(Exception):
    """Only a fixed error code and HTTP status may reach logs."""
    def __init__(self, code, status=None):
        self.code, self.status = code, status
        super().__init__(code)


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes
    transfer: dict | None = None


def decode_body(data, headers, max_bytes):
    """urllib does not decode HTTP compression; urlscan DOM can be a gzip object."""
    headers = {k.lower(): v for k, v in headers.items()}
    encoding = headers.get('content-encoding', '').strip().lower()
    gzip_magic = data.startswith(b'\x1f\x8b')
    info = {'wire_sha256': hashlib.sha256(data).hexdigest(), 'wire_bytes': len(data),
            'content_encoding': encoding or 'identity', 'gzip_magic': gzip_magic}
    if encoding in ('gzip', 'x-gzip') or gzip_magic:
        mode = 16 + zlib.MAX_WBITS
    elif encoding == 'deflate':
        mode = zlib.MAX_WBITS
    elif encoding in ('', 'identity'):
        return data, info
    else:
        raise CaptureError('unsupported_content_encoding')
    try:
        decoder = zlib.decompressobj(mode)
        decoded = decoder.decompress(data, max_bytes + 1)
        if len(decoded) > max_bytes or decoder.unconsumed_tail:
            raise CaptureError('decoded_response_too_large')
        if not decoder.eof or decoder.unused_data:
            raise CaptureError('invalid_compressed_response')
    except zlib.error:
        raise CaptureError('invalid_compressed_response') from None
    info['decoded_from'] = 'gzip' if mode != zlib.MAX_WBITS else 'deflate'
    return decoded, info


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def transport(url, headers, timeout, max_bytes):
    req = Request(url, headers=headers, method='GET')
    try:
        response = build_opener(NoRedirect).open(req, timeout=timeout)
    except HTTPError as exc:
        # Never read provider error bodies: they may echo the query or credential.
        result = Response(exc.code, dict(exc.headers), b'')
        exc.close()
        return result
    except (URLError, TimeoutError, OSError):
        raise CaptureError('transport_error') from None
    try:
        with response:
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise CaptureError('response_too_large')
            body, info = decode_body(data, dict(response.headers), max_bytes)
            return Response(response.status, dict(response.headers), body, info)
    except (OSError, http.client.HTTPException):
        raise CaptureError('transport_error') from None


def scan_id(value):
    if not isinstance(value, str) or not UUID.fullmatch(value):
        raise CaptureError('invalid_scan_uuid')
    return value


def json_object(response):
    try:
        obj = json.loads(response.body)
    except (ValueError, UnicodeError):
        raise CaptureError('invalid_json') from None
    if not isinstance(obj, dict):
        raise CaptureError('invalid_json_shape')
    return obj


class Client:
    def __init__(self, key, *, request_limit=30, interval=12, attempts=3,
                 timeout=25, max_bytes=20_000_000, send=transport,
                 sleep=time.sleep, clock=time.monotonic):
        if not key or '\n' in key or '\r' in key:
            raise CaptureError('missing_or_invalid_api_key')
        if not 1 <= request_limit <= 1000 or not 1 <= attempts <= 5:
            raise ValueError('invalid request budget')
        if not math.isfinite(interval) or interval < 0:
            raise ValueError('invalid interval')
        self.key, self.limit, self.interval = key, request_limit, interval
        self.attempts, self.timeout, self.max_bytes = attempts, timeout, max_bytes
        self.send, self.sleep, self.clock = send, sleep, clock
        self.requests, self.last = 0, None
        self.cooldowns = {}

    @staticmethod
    def allowed(url):
        p = urlsplit(url)
        if p.scheme != 'https' or p.netloc != 'urlscan.io' or p.fragment:
            raise CaptureError('redirect_or_endpoint_rejected')
        if p.path in ('/api/v1/search/', '/api/v1/quotas/'):
            return
        if re.fullmatch(r'/api/v1/result/([0-9a-f-]{36})/', p.path):
            scan_id(p.path.split('/')[-2]); return
        if re.fullmatch(r'/dom/([0-9a-f-]{36})/', p.path):
            scan_id(p.path.split('/')[-2]); return
        if re.fullmatch(r'/screenshots/([0-9a-f-]{36})\.png', p.path):
            scan_id(p.path.split('/')[-1][:-4]); return
        raise CaptureError('redirect_or_endpoint_rejected')

    def get(self, path, *, pending=False):
        url = BASE + path
        redirects = 0
        for attempt in range(self.attempts):
            while True:
                self.allowed(url)
                endpoint = urlsplit(url).path
                family = 'search' if endpoint.startswith('/api/v1/search/') else 'result' if endpoint.startswith('/api/v1/result/') else 'dom' if endpoint.startswith('/dom/') else 'screenshot'
                remaining = self.cooldowns.get(family, 0) - self.clock()
                if remaining > 60:
                    raise CaptureError('retry_deferred', 429)
                if remaining > 0:
                    self.sleep(remaining)
                if self.requests >= self.limit:
                    raise CaptureError('request_budget_exhausted')
                if self.last is not None:
                    self.sleep(max(0, self.interval - (self.clock() - self.last)))
                self.requests += 1
                self.last = self.clock()
                try:
                    response = self.send(url, {'api-key': self.key,
                        'Accept-Encoding': 'gzip, deflate',
                        'User-Agent': 'hybrid-phishing-research/1.0.0'}, self.timeout, self.max_bytes)
                except CaptureError as exc:
                    if exc.code != 'transport_error' or attempt + 1 == self.attempts:
                        raise
                    response = Response(599, {}, b'')
                if response.status not in (301, 302, 303, 307, 308):
                    break
                headers = {k.lower(): v for k, v in response.headers.items()}
                target = headers.get('location')
                if not target or redirects >= 3:
                    raise CaptureError('redirect_limit')
                url = urljoin(url, target)
                self.allowed(url)  # Key is never forwarded to another host.
                redirects += 1
            status = response.status
            headers = {k.lower(): v for k, v in response.headers.items()}
            reset_after = headers.get('x-rate-limit-reset-after')
            if headers.get('x-rate-limit-remaining') == '0' and reset_after:
                try:
                    delay = float(reset_after)
                    if not math.isfinite(delay) or delay < 0:
                        raise ValueError()
                    self.cooldowns[family] = self.clock() + delay
                except ValueError:
                    raise CaptureError('invalid_rate_limit_header', status) from None
            if status == 200:
                return response
            if status in (401, 403):
                raise CaptureError('authentication_or_access_denied', status)
            retry = status == 429 or status >= 500 or (status == 404 and pending)
            if not retry or attempt + 1 == self.attempts:
                code = {404: 'result_pending_or_unavailable' if pending else 'attachment_missing',
                        410: 'scan_deleted', 429: 'rate_limited'}.get(status, 'http_error')
                raise CaptureError(code, status)
            headers = {k.lower(): v for k, v in response.headers.items()}
            delay = max(2, 2 ** attempt)
            value = headers.get('retry-after') or reset_after
            if value:
                try:
                    try:
                        retry_after = float(value)
                    except ValueError:
                        retry_after = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
                    if not math.isfinite(retry_after):
                        raise ValueError()
                    delay = max(delay, retry_after)
                except (ValueError, TypeError, OverflowError):
                    raise CaptureError('invalid_retry_after', status) from None
            if delay > 60:
                raise CaptureError('retry_deferred', status)
            self.sleep(delay)
        raise CaptureError('retry_exhausted')

    def search(self, url, size=10, *, field="task.url.keyword", public_only=False):
        if field not in ("task.url.keyword", "page.url.keyword", "task.domain.keyword"):
            raise ValueError("unsupported search field")
        # Escape Elasticsearch special characters, then transport-encode the query.
        escaped = re.sub(r'([+\-=!(){}\[\]^"~*?:\\/<>|&])', r'\\\1', url)
        query = f'{field}:"{escaped}"'
        if public_only:
            query += " AND task.visibility:public"
        obj = json_object(self.get('/api/v1/search/?' + urlencode({'q': query, 'size': size})))
        if not isinstance(obj.get('results'), list):
            raise CaptureError('invalid_search_shape')
        return obj

    def result(self, uuid):
        return self.get(f'/api/v1/result/{scan_id(uuid)}/', pending=True)

    def dom(self, uuid):
        return self.get(f'/dom/{scan_id(uuid)}/')

    def screenshot(self, uuid):
        return self.get(f'/screenshots/{scan_id(uuid)}.png')
