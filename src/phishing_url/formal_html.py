"""Replay frozen candidates and audit publisher HTML offline; never train or browse."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from html.parser import HTMLParser
import json
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import numpy as np

from .dom_dataset import leakage_groups
from .formal_candidates import file_sha, json_bytes, read_metadata, select, sha, validate_frame
from .paired_quality import audit_paired_dataset, _month
from .url_cleaning import registered_domain

COUNTS = ('tag_count', 'form_count', 'password_input_count', 'input_count',
          'script_count', 'iframe_count', 'link_count', 'http_link_count',
          'external_link_count', 'unresolved_link_count', 'resource_count',
          'http_resource_count', 'external_resource_count', 'unresolved_resource_count',
          'external_script_count', 'hidden_attribute_count', 'hidden_input_count',
          'inline_hidden_style_count', 'meta_refresh_count', 'external_form_action_count',
          'unresolved_form_action_count', 'static_text_chars')
MARKERS = {
    'challenge_marker': ('verify you are human', 'checking your browser', 'just a moment', 'attention required'),
    'access_error_marker': ('access denied', '403 forbidden', '404 not found', 'page not found', '502 bad gateway', '503 service unavailable'),
    'parking_marker': ('domain is for sale', 'buy this domain', 'domain has expired'),
}


class ContentProbe(HTMLParser):
    """Static lexical tag audit. No rendered-DOM, CSS, or JavaScript claims."""
    def __init__(self, page_url):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.counts = Counter()
        self.tags = []
        self.references = []
        self.base_href = None
        self.inert_depth = Counter()
        self.title_depth = 0
        self.title_parts = []
        self.text_parts = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.tags.append(tag)
        self.counts['tag_count'] += 1
        if tag in ('form', 'input', 'script', 'iframe'):
            self.counts[tag + '_count'] += 1
        kind = str(a.get('type') or '').strip().lower()
        self.counts['password_input_count'] += tag == 'input' and kind == 'password'
        self.counts['hidden_input_count'] += tag == 'input' and kind == 'hidden'
        self.counts['hidden_attribute_count'] += 'hidden' in a
        style = ''.join(str(a.get('style') or '').lower().split())
        self.counts['inline_hidden_style_count'] += 'display:none' in style or 'visibility:hidden' in style
        self.counts['meta_refresh_count'] += tag == 'meta' and str(a.get('http-equiv') or '').strip().lower() == 'refresh'
        if tag == 'base' and self.base_href is None and 'href' in a:
            self.base_href = a['href'] or ''
        if tag == 'a' and 'href' in a:
            self.counts['link_count'] += 1
            self.references.append(('link', a['href'] or '', tag))
        resource_attr = 'href' if tag == 'link' else 'src'
        if tag in ('script', 'img', 'iframe', 'link', 'source', 'audio', 'video', 'embed', 'input') and resource_attr in a:
            self.counts['resource_count'] += 1
            self.references.append(('resource', a[resource_attr] or '', tag))
        if tag == 'form' and 'action' in a:
            self.references.append(('form_action', a['action'] or '', tag))
        if tag in ('script', 'style', 'noscript', 'template'):
            self.inert_depth[tag] += 1
        if tag == 'title':
            self.title_depth += 1

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag in self.inert_depth:
            self.inert_depth[tag] = max(0, self.inert_depth[tag] - 1)
        if tag == 'title':
            self.title_depth = max(0, self.title_depth - 1)

    def handle_data(self, data):
        if self.title_depth:
            self.title_parts.append(data)
        elif not any(self.inert_depth.values()):
            self.text_parts.append(data)

    def result(self):
        # First static base element applies to every relative reference.
        base = urljoin(self.page_url, self.base_href) if self.base_href is not None else self.page_url
        domain = registered_domain(self.page_url)
        for kind, value, tag in self.references:
            try:
                resolved = urljoin(base, value.strip())
                parts = urlsplit(resolved)
                if parts.scheme not in ('http', 'https'):
                    continue
                if not parts.hostname:
                    raise ValueError('missing hostname')
                self.counts['http_' + kind + '_count'] += 1
                external = registered_domain(resolved) != domain
                self.counts['external_' + kind + '_count'] += external
                if kind == 'resource' and tag == 'script':
                    self.counts['external_script_count'] += external
            except (ValueError, TypeError):
                self.counts['unresolved_' + kind + '_count'] += 1
        visible = ' '.join(' '.join(self.text_parts).split())
        title = ' '.join(' '.join(self.title_parts).split())
        self.counts['static_text_chars'] = len(visible)
        # Bounded visible/title text, excluding script/style source. Review flags only.
        text = (title + ' ' + visible[:2000]).casefold()
        result = {k: int(self.counts[k]) for k in COUNTS}
        result.update({k: any(s in text for s in terms) for k, terms in MARKERS.items()})
        result['low_static_content_flag'] = len(visible) < 100
        result['has_html_tag'] = 'html' in self.tags
        result['has_body_tag'] = 'body' in self.tags
        result['structural_tag_sequence_sha256'] = sha(' '.join(self.tags).encode()) if self.tags else None
        for kind in ('link', 'resource'):
            den = self.counts['http_' + kind + '_count']
            result['external_' + kind + '_ratio'] = self.counts['external_' + kind + '_count'] / den if den else None
        return result


def inspect_html(value, page_url, max_bytes):
    empty = {k: None for k in COUNTS}
    if not isinstance(value, str):
        return {**empty, 'parse_status': 'missing_html' if value is None else 'non_string_html', 'html_sha256': None, 'html_bytes': None}
    try:
        raw = value.encode('utf-8')
    except UnicodeError:
        return {**empty, 'parse_status': 'encoding_error', 'html_sha256': None, 'html_bytes': None}
    base = {**empty, 'html_sha256': sha(raw), 'html_bytes': len(raw)}
    if not value.strip():
        return {**base, 'parse_status': 'empty_html'}
    if len(raw) > max_bytes:
        return {**base, 'parse_status': 'oversize_html'}
    try:
        parser = ContentProbe(page_url)
        parser.feed(value)
        parser.close()
        result = parser.result()
    except (ValueError, AssertionError, RecursionError):
        return {**base, 'parse_status': 'parse_error'}
    return {**base, **result, 'parse_status': 'parsed_markup' if result['tag_count'] else 'no_markup'}


def frozen_candidates(source_root, frame_path, policy_path, freeze_path):
    frame = json.loads(frame_path.read_text())
    policy = json.loads(policy_path.read_text())
    freeze = json.loads(freeze_path.read_text())
    validate_frame(frame, policy)
    if file_sha(frame_path) != freeze['source_frame_sha256'] or file_sha(policy_path) != freeze['policy_sha256']:
        raise ValueError('frozen policy/frame hash mismatch')
    metadata, inventory = read_metadata(source_root, frame)
    chosen, _ = select(metadata, policy)
    manifest = ''.join(json.dumps(r, sort_keys=True, allow_nan=False) + '\n' for r in chosen).encode()
    fields = ('sample_id', 'source_file', 'source_file_sha256', 'source_row', 'label')
    replay = ''.join(json.dumps({k: r[k] for k in fields}, sort_keys=True) + '\n' for r in chosen).encode()
    if (len(chosen) != freeze['candidate_count'] or sha(manifest) != freeze['candidate_manifest_sha256'] or
            sha(replay) != freeze['candidate_replay_sha256'] or
            {str(y): sum(r['label'] == y for r in chosen) for y in (0, 1)} != freeze['selected_per_label']):
        raise ValueError('frozen membership mismatch: stop before reading HTML')
    return chosen, frame, policy, inventory, replay


def materialize(chosen, html_items, output, policy, frame):
    output.mkdir(parents=True, exist_ok=False)
    (output / 'html').mkdir()
    by_id = {r['sample_id']: r for r in chosen}
    if len(by_id) != len(chosen):
        raise ValueError('duplicate candidates')
    rows, seen = [], set()
    for sample_id, value in html_items:
        if sample_id not in by_id or sample_id in seen:
            raise ValueError('unexpected or duplicate materialized sample')
        seen.add(sample_id)
        selected = by_id[sample_id]
        result = inspect_html(value, selected['url_clean'], policy['content']['max_html_bytes'])
        parsed = result['parse_status'] == 'parsed_markup'
        row = {**selected, **result, 'source_revision': frame['revision'],
               'usable_pair': parsed, 'html_path': None, 'exclusion_reasons': [] if parsed else [result['parse_status']],
               'final_url': None, 'redirect_chain': None, 'http_status': None,
               'source_verification_time': None, 'training_approved': False,
               'label_basis': 'published_source_label_not_independently_adjudicated'}
        # Preserve bounded HTML even for no-markup/parse errors, never oversized payloads.
        if result['html_sha256'] and result['html_bytes'] <= policy['content']['max_html_bytes']:
            row['html_path'] = 'html/' + result['html_sha256'] + '.html.txt'
            (output / row['html_path']).write_bytes(value.encode('utf-8'))
        rows.append(row)
    if seen != set(by_id):
        raise ValueError('selected source rows missing: incomplete run, no replacement')
    rows.sort(key=lambda r: r['sample_id'])
    hashes = defaultdict(list)
    for row in rows:
        if row['html_sha256']:
            hashes[row['html_sha256']].append(row)
    conflicts = []
    for h, group in hashes.items():
        if len({r['label'] for r in group}) > 1:
            conflicts.append({'html_sha256': h, 'sample_ids': [r['sample_id'] for r in group],
                              'labels': dict(Counter(str(r['label']) for r in group))})
            for row in group:
                row['usable_pair'] = False
                row['exclusion_reasons'].append('cross_label_exact_html_conflict')
    usable = [r for r in rows if r['usable_pair']]
    groups = leakage_groups(usable)
    for row in rows:
        row['leakage_group'] = groups.get(row['sample_id'])
    raw = ''.join(json.dumps(r, sort_keys=True, allow_nan=False) + '\n' for r in rows).encode()
    (output / 'paired_manifest.jsonl').write_bytes(raw)
    return rows, conflicts


def selected_html(source_root, frame, chosen):
    import pyarrow as pa
    import pyarrow.parquet as pq
    by_file = defaultdict(dict)
    for row in chosen:
        by_file[row['source_file']][row['source_row']] = row['sample_id']
    for item in frame['sampling_frame']['fixed_shards']:
        wanted = by_file[item['path']]
        source = pq.ParquetFile(source_root / item['path'])
        offset = 0
        for batch in source.iter_batches(batch_size=8, columns=['html']):
            local = [i for i in range(batch.num_rows) if offset + i in wanted]
            # Parquet page decoding includes neighboring rows; only selected values
            # are converted to Python, inspected, or persisted.
            if local:
                values = batch.take(pa.array(local)).column(0).to_pylist()
                for index, value in zip(local, values, strict=True):
                    yield wanted[offset + index], value
            offset += batch.num_rows


def numeric(values):
    present = [v for v in values if v is not None]
    if not present:
        return {'n': 0, 'missing': len(values)}
    a = np.asarray(present, dtype=float)
    if not np.isfinite(a).all():
        raise ValueError('nonfinite audit value')
    return {'n': len(present), 'missing': len(values), 'zero_count': sum(v == 0 for v in present),
            'mean': float(a.mean()), 'std_population': float(a.std()),
            **dict(zip(('min', 'p25', 'median', 'p75', 'p90', 'p95', 'p99', 'max'),
                       map(float, np.quantile(a, [0, .25, .5, .75, .9, .95, .99, 1])), strict=True))}


def profile(rows):
    n = len(rows)
    rates = {}
    for name, values in {
        'https': [urlsplit(r['url_clean']).scheme == 'https' for r in rows],
        'root_path': [urlsplit(r['url_clean']).path in ('', '/') for r in rows],
        'query_present': [bool(urlsplit(r['url_clean']).query) for r in rows],
        'password_input': [r['password_input_count'] > 0 if r['password_input_count'] is not None else None for r in rows],
        **{k: [r.get(k) for r in rows] for k in (*MARKERS, 'low_static_content_flag', 'has_html_tag', 'has_body_tag')},
    }.items():
        valid = [v for v in values if v is not None]
        rates[name] = {'count': sum(valid), 'denominator': len(valid), 'missing': n - len(valid),
                       'rate': sum(valid) / len(valid) if valid else None}
    domains = Counter(r['registered_domain'] for r in rows)
    return {'n': n, 'registered_domains': len(domains), 'rates': rates,
            'numeric': {k: numeric([r.get(k) for r in rows]) for k in ('html_bytes', *COUNTS, 'external_link_ratio', 'external_resource_ratio')},
            'month_counts': dict(sorted(Counter(_month(r['capture_date']) or 'missing' for r in rows).items())),
            'language_counts': dict(Counter(str(r['lang']) if r['lang'] not in (None, '') else 'missing' for r in rows).most_common()),
            'target_counts': dict(Counter(str(r['target']) if r.get('target') not in (None, '') else 'missing' for r in rows).most_common()),
            'shard_counts': dict(sorted(Counter(r['source_file'] for r in rows).items())),
            'largest_domain_count': max(domains.values(), default=0),
            'largest_domain_share': max(domains.values(), default=0)/n if n else None}


def duplicate_summary(rows, key):
    groups = defaultdict(list)
    for r in rows:
        if r.get(key):
            groups[r[key]].append(r)
    repeated = [g for g in groups.values() if len(g) > 1]
    return {'distinct_values': len(groups), 'repeated_groups': len(repeated),
            'rows_in_repeated_groups': sum(map(len, repeated)),
            'excess_rows': sum(len(g)-1 for g in repeated),
            'largest_group': max(map(len, groups.values()), default=0),
            'cross_label_groups': sum(len({r['label'] for r in g}) > 1 for g in repeated),
            'cross_domain_groups': sum(len({r['registered_domain'] for r in g}) > 1 for g in repeated)}


def diagnostics(rows, conflicts):
    cohorts = {'selected': rows, 'parsed': [r for r in rows if r['parse_status'] == 'parsed_markup'],
               'usable': [r for r in rows if r['usable_pair']]}
    profiles = {name: {str(y): profile([r for r in part if r['label'] == y]) for y in (0, 1)} for name, part in cohorts.items()}
    gaps = {}
    for name, ps in profiles.items():
        gaps[name] = {}
        for metric in ps['0']['rates']:
            a, b = ps['0']['rates'][metric]['rate'], ps['1']['rates'][metric]['rate']
            gaps[name][metric] = b-a if a is not None and b is not None else None
    # Cohort counts make selective loss by month/language/shard/root-path visible.
    strata = {}
    for field, getter in {'month': lambda r: _month(r['capture_date']) or 'missing',
                          'language': lambda r: str(r['lang']) if r['lang'] not in (None, '') else 'missing',
                          'shard': lambda r: r['source_file'],
                          'root_path': lambda r: str(urlsplit(r['url_clean']).path in ('', '/'))}.items():
        groups = defaultdict(list)
        for r in rows:
            groups[(r['label'], getter(r))].append(r)
        strata[field] = [{'label': y, 'stratum': v, 'selected': len(g), 'usable': sum(r['usable_pair'] for r in g),
                          'loss_count': sum(not r['usable_pair'] for r in g),
                          'loss_rate': sum(not r['usable_pair'] for r in g)/len(g)} for (y, v), g in sorted(groups.items())]
    return {'cohorts': profiles, 'rate_difference_phishing_minus_benign': gaps,
            'status_counts_by_label': {str(y): dict(Counter(r['parse_status'] for r in rows if r['label'] == y)) for y in (0, 1)},
            'exclusion_reason_counts_by_label': {str(y): dict(Counter(reason for r in rows if r['label'] == y for reason in r['exclusion_reasons'])) for y in (0, 1)},
            'cross_label_exact_html_conflicts': conflicts,
            'exact_html_selected': duplicate_summary(rows, 'html_sha256'),
            'exact_html_usable': duplicate_summary(cohorts['usable'], 'html_sha256'),
            'hard_leakage_components': duplicate_summary(cohorts['usable'], 'leakage_group'),
            'coarse_structural_template_candidates': duplicate_summary([r for r in cohorts['parsed'] if r['tag_count'] >= 20], 'structural_tag_sequence_sha256'),
            'attrition_strata': strata,
            'bias_review_required': True, 'training_approved': False,
            'limitations': ['Source labels are not independently adjudicated.',
                'Static tolerant parsing is not browser rendering, full HTML validation or proof of complete content.',
                'Publisher UTF-8 string hashes are not asserted equal to source sample IDs or original HTTP bytes.',
                'Markers are exploratory review flags, not confirmed error pages or exclusion rules.',
                'Structural tag sequence matches ignore attributes/text; they are coarse template candidates, not confirmed near duplicates and do not merge groups.',
                'Rates use explicitly reported nonmissing denominators; no confidence/p-values assume independent URLs.',
                'Full-cohort audit is exploratory before holdout creation; test-specific feature selection is prohibited.',
                'No official source test, final partition, model training, automatic approval, replacement or live requests.']}


def run(source_root, output, frame_path, policy_path, freeze_path):
    if output.exists():
        raise FileExistsError('preserve audit output; use a new directory')
    chosen, frame, policy, inventory, replay = frozen_candidates(source_root, frame_path, policy_path, freeze_path)
    rows, conflicts = materialize(chosen, selected_html(source_root, frame, chosen), output, policy, frame)
    public = output / 'public'
    public.mkdir()
    (public / 'candidate_replay.jsonl').write_bytes(replay)
    quality = audit_paired_dataset(output / 'paired_manifest.jsonl', output, policy_path)
    report = diagnostics(rows, conflicts)
    # Enforce mandatory distribution review even if numeric gap triggers happen to pass.
    quality['bias_review_required'] = True
    quality['formal_data_ready_for_research_review'] = False
    for finding in quality['findings']:
        if finding['code'] == 'bias_review':
            finding['passed'] = False
            finding['note'] = 'Preregistered date/language/HTML-size review is mandatory; no automatic approval.'
    fields = ('sample_id', 'source_file', 'source_file_sha256', 'source_row', 'label', 'parse_status',
              'html_sha256', 'html_bytes', 'usable_pair', 'exclusion_reasons', 'leakage_group',
              *COUNTS, *MARKERS, 'low_static_content_flag', 'has_html_tag', 'has_body_tag',
              'external_link_ratio', 'external_resource_ratio', 'structural_tag_sequence_sha256')
    audit_bytes = ''.join(json.dumps({k: r.get(k) for k in fields}, sort_keys=True, allow_nan=False) + '\n' for r in rows).encode()
    (public / 'sample_audit.jsonl').write_bytes(audit_bytes)
    summary = {'schema_version': 'formal-selected-html-audit-v1', 'candidate_count': len(rows),
               'usable_pairs': sum(r['usable_pair'] for r in rows), 'technical_gate_pass': quality['technical_gate_pass'],
               'candidate_replay_sha256': sha(replay), 'paired_manifest_sha256': file_sha(output / 'paired_manifest.jsonl'),
               'sample_audit_sha256': sha(audit_bytes), 'implementation_sha256': file_sha(Path(__file__)),
               'freeze_sha256': file_sha(freeze_path), 'source_inventory': inventory,
               'html_files_saved': len(list((output / 'html').iterdir())),
               'failed_candidate_replacement': False, 'membership_verified_before_html': True,
               'training_approved': False, 'final_partition_created': False, 'model_training_performed': False,
               'test_evaluated': False, 'final_dom_dataset_frozen': False, 'bias_review_required': True}
    for name, value in [('materialization_summary.json', summary), ('quality_report.json', quality), ('content_diagnostics.json', report)]:
        (public / name).write_bytes(json_bytes(value))
    for path in (frame_path, policy_path, freeze_path):
        (public / path.name).write_bytes(path.read_bytes())
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'output', 'frame', 'policy', 'freeze'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    result = run(a.source_root, a.output, a.frame, a.policy, a.freeze)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
