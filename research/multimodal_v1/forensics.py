"""Bounded passive byte inspection. Never decode/execute embedded payloads."""
from __future__ import annotations

from collections import Counter
import math
from pathlib import Path
import re

from .contract import feature_set, sha, unavailable_features

VERSION = 'static-content-forensics-v1'
MAX_BYTES = 2 * 1024 * 1024
MAX_OFFSETS = 32
RULE_PATH = Path(__file__).with_name('rules') / 'content_v1.yar'
PATTERNS = {
    'percent_escape_count': rb'%[0-9a-fA-F]{2}',
    'js_hex_escape_count': rb'\\x[0-9a-fA-F]{2}',
    'js_unicode_escape_count': rb'\\u[0-9a-fA-F]{4}',
    'html_numeric_entity_count': rb'&#(?:[0-9]{1,7}|[xX][0-9a-fA-F]{1,6});',
    'eval_call_count': rb'\beval\s*\(',
    'atob_call_count': rb'\batob\s*\(',
    'fromcharcode_call_count': rb'\bString\s*\.\s*fromCharCode\s*\(',
    'unescape_call_count': rb'\bunescape\s*\(',
    'document_write_call_count': rb'\bdocument\s*\.\s*write\s*\(',
    'base64_like_run_count': rb'[A-Za-z0-9+/]{80,}={0,2}',
}
NAMES = ('byte_length', 'byte_entropy', *PATTERNS, 'base64_like_byte_ratio')


def inspect(data, *, run_yara=True):
    if not isinstance(data, bytes):
        raise TypeError('bytes_required')
    result = {'version': VERSION, 'source_sha256': sha(data), 'source_bytes': len(data),
              'label': None, 'label_assignment': False, 'execution_performed': False,
              'signals': {}, 'yara': {'status': 'not_requested', 'matches': None,
                                     'rules_sha256': sha(RULE_PATH.read_bytes()), 'engine_version': None}}
    if not data or len(data) > MAX_BYTES:
        reason = 'empty_content' if not data else 'content_limit_exceeded'
        result['features'] = unavailable_features(VERSION, NAMES, reason)
        result['yara']['status'] = 'input_unavailable'
        return result
    counts = Counter(data)
    values = {'byte_length': len(data),
              'byte_entropy': -sum((n/len(data))*math.log2(n/len(data)) for n in counts.values())}
    base64_bytes = 0
    for name, pattern in PATTERNS.items():
        count, offsets = 0, []
        for match in re.finditer(pattern, data):
            count += 1
            if len(offsets) < MAX_OFFSETS:
                offsets.append({'offset': match.start(), 'length': match.end()-match.start()})
            if name == 'base64_like_run_count':
                base64_bytes += match.end()-match.start()
        values[name] = count
        result['signals'][name] = {'count': count, 'byte_spans': offsets,
                                   'spans_truncated': count > len(offsets)}
    values['base64_like_byte_ratio'] = base64_bytes / len(data)
    result['features'] = feature_set(VERSION, values)
    if run_yara:
        result['yara'] = yara_scan(data)
    return result


def yara_scan(data):
    rules_bytes = RULE_PATH.read_bytes()
    out = {'status': 'dependency_missing', 'matches': None,
           'rules_sha256': sha(rules_bytes), 'engine_version': None}
    try:
        import yara
    except ImportError:
        return out
    out['engine_version'] = yara.__version__
    try:
        rules = yara.compile(source=rules_bytes.decode('utf-8'), includes=False, error_on_warning=True)
        matches = rules.match(data=data, timeout=5)
        hits = []
        for match in sorted(matches, key=lambda m: m.rule):
            spans, total = [], 0
            for string in match.strings:
                for instance in string.instances:
                    total += 1
                    if len(spans) < MAX_OFFSETS:
                        spans.append({'string_id': string.identifier, 'offset': instance.offset,
                                      'length': instance.matched_length})
            hits.append({'rule_id': match.rule, 'namespace': match.namespace,
                         'tags': sorted(match.tags), 'rule_version': match.meta.get('version'),
                         'byte_spans': spans, 'spans_truncated': total > len(spans)})
        out.update(status='ok', matches=hits)
    except yara.TimeoutError:
        out['status'] = 'timeout'
    except yara.Error:
        out['status'] = 'engine_error'
    return out
