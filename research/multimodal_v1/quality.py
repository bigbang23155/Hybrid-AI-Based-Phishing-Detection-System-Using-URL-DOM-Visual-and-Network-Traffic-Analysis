"""Label-independent coverage and pairing checks with public aggregate output."""
from __future__ import annotations

from collections import Counter
import re

from . import VERSION
from .adapters import SPEC
from .contract import MODALITIES, assemble, parse_time
from .network_http import REGISTRY_SHA256

QUALITY_VERSION = 'multimodal-coverage-alignment-v1'
HASH = re.compile(r'[0-9a-f]{64}')
PUBLIC_REASONS = frozenset((
    'missing_or_invalid_field', 'incomplete_field_coverage', 'missing_context',
    'empty_denominator', 'request_limit_exceeded', 'invalid_result_object',
    'artifact_integrity_or_access_failed', 'result_identity_mismatch',
    'invalid_result_or_identity', 'result_identity_unverified',
    'extraction_failed_or_resource_limit', 'extractor_dependency_missing',
    'invalid_requested_url', 'result_not_supplied', 'dom_not_supplied',
    'screenshot_not_supplied', 'no_exact_public_scan_in_search_window',
    'http_error', 'network_error', 'rate_limited', 'retry_deferred',
    'request_budget_exhausted', 'authentication_or_access_denied',
    'invalid_png', 'invalid_utf8', 'dom_has_no_markup', 'timeout'))
PUBLIC_FLAGS = frozenset((
    'redirected', 'original_capture_time_unknown', 'access_blocked',
    'page_status_unknown', 'page_http_error', 'http_metadata_missing_or_empty',
    'low_dom_content', 'flat_image', 'quality_features_only_no_semantic_visual_embedding'))
YARA_STATES = frozenset(('ok', 'not_requested', 'input_unavailable', 'dependency_missing',
                         'timeout', 'engine_error', 'content_unavailable'))


def safe_reason(value):
    return value if value in PUBLIC_REASONS else 'other_reason'


def alignment(row):
    """Return fixed diagnostic codes, never raw identifiers or timestamps."""
    mods = row['modalities']
    present = [mods[n] for n in MODALITIES if mods[n]['acquisition_status'] == 'available']
    source_hash = row.get('source_record_sha256')
    problems = []
    if not isinstance(source_hash, str) or not HASH.fullmatch(source_hash):
        problems.append('missing_checkpoint_binding')
    if any(m['provenance'].get('checkpoint_sha256') != source_hash for m in present):
        problems.append('checkpoint_mismatch')
    if any(not HASH.fullmatch(str(m['provenance'].get('source_sha256', ''))) for m in present):
        problems.append('missing_source_hash')
    observations = [mods[n] for n in ('dom', 'visual', 'network_http')
                    if mods[n]['acquisition_status'] == 'available']
    if observations:
        ids = [m['provenance'].get('scan_uuid') for m in observations]
        if any(not isinstance(x, str) or not x for x in ids):
            problems.append('missing_scan_identity')
        elif len(set(ids)) != 1:
            problems.append('scan_identity_mismatch')
        try:
            times = {parse_time(m['temporal']['captured_at']) for m in observations}
            if len(times) != 1:
                problems.append('capture_time_mismatch')
        except (ValueError, TypeError):
            problems.append('capture_time_unknown')
        for field in ('submitted_url_sha256', 'final_url_sha256'):
            hashes = [m['provenance'].get(field) for m in observations]
            if any(not isinstance(h, str) or not HASH.fullmatch(h) for h in hashes):
                problems.append('missing_' + field)
            elif len(set(hashes)) != 1:
                problems.append(field + '_mismatch')
        if mods['url']['acquisition_status'] == 'available' and (
                mods['url']['provenance'].get('source_sha256') !=
                observations[0]['provenance'].get('submitted_url_sha256')):
            problems.append('url_input_mismatch')
    network = mods['network_http']
    if network['acquisition_status'] == 'available' and (
            network['provenance'].get('registry_sha256') != REGISTRY_SHA256 or
            network['provenance'].get('representation') != 'HTTP_METADATA_NOT_HAR_OR_PCAP'):
        problems.append('network_registry_or_representation_mismatch')
    if problems:
        return 'failed', sorted(set(problems))
    if len(present) != 4:
        return 'incomplete', ['missing_acquired_modality']
    return 'aligned', []


class Coverage:
    """Streaming counts over all attempted rows, including unavailable records."""
    def __init__(self):
        self.records = 0
        self.seen = set()
        self.acquisition, self.extraction, self.temporal = Counter(), Counter(), Counter()
        self.flags, self.pairing, self.pairing_reasons, self.yara = Counter(), Counter(), Counter(), Counter()
        self.all_usable = 0
        self.columns = {}
        for modality, (version, names) in SPEC.items():
            for name in names:
                self.columns[modality + '__' + name] = {
                    'registry_version': version, 'observed_records': 0, 'usable_records': 0,
                    'observed_zero_records': 0, 'missing_reasons': Counter(),
                    'support_observed_total': 0, 'support_expected_total': 0,
                    'support_known_records': 0}

    def add(self, row):
        if (row.get('schema_version') != VERSION or row.get('eligible_for_training') is not False
                or row.get('label') is not None or row.get('human_review_status') != 'pending'):
            raise ValueError('quality_audit_requires_unlabelled_research_record')
        if row['item_id'] in self.seen:
            raise ValueError('duplicate_quality_item')
        mods = assemble(row['item_id'], dict(row['modalities']), scope=row['scope'])['modalities']
        for name in MODALITIES:
            f = mods[name]['features']
            version, names = SPEC[name]
            if f['registry_version'] != version or f['feature_order'] != list(names):
                raise ValueError('quality_registry_contract_mismatch')
            # The stored masks must match recomputation before any consumer uses them.
            for key in ('observed_mask', 'usable_mask', 'modality_available_mask', 'modality_usable_mask'):
                if row['modalities'][name][key] != mods[name][key]:
                    raise ValueError('quality_stored_mask_mismatch')
        state, reasons = alignment(dict(row, modalities=mods))
        self.seen.add(row['item_id']); self.records += 1
        self.pairing[state] += 1; self.pairing_reasons.update(reasons)
        self.all_usable += state == 'aligned' and all(m['modality_usable_mask'] for m in mods.values())
        for name in MODALITIES:
            m = mods[name]
            self.acquisition[name + ':' + m['acquisition_status']] += 1
            self.extraction[name + ':' + m['extraction_status']] += 1
            self.temporal[name + ':' + m['temporal']['status']] += 1
            self.flags.update(name + ':' + (f if f in PUBLIC_FLAGS else 'other_quality_flag')
                              for f in set(m['quality_flags']))
            f = m['features']
            for feature in f['feature_order']:
                out = self.columns[name + '__' + feature]
                value = f['values'][feature]
                out['observed_records'] += m['observed_mask'][feature]
                out['usable_records'] += m['usable_mask'][feature]
                out['observed_zero_records'] += value is not None and value == 0
                if value is None:
                    out['missing_reasons'][safe_reason(f['missing_reasons'][feature])] += 1
                support = f['support'].get(feature)
                if support is not None:
                    observed, expected = support.get('observed'), support.get('expected')
                    if type(observed) is not int or observed < 0 or (expected is not None and
                            (type(expected) is not int or expected < observed)):
                        raise ValueError('invalid_feature_support')
                    if expected is not None:
                        out['support_known_records'] += 1
                        out['support_observed_total'] += observed
                        out['support_expected_total'] += expected
        yara = row.get('sidecars', {}).get('content_forensics', {}).get('yara', {})
        status = yara.get('status', 'content_unavailable')
        self.yara[status if status in YARA_STATES else 'other_status'] += 1

    def report(self):
        columns = {}
        for key, counts in self.columns.items():
            columns[key] = dict(counts, missing_reasons=dict(counts['missing_reasons']),
                missing_records=self.records-counts['observed_records'],
                observed_fraction=counts['observed_records']/self.records if self.records else None,
                usable_fraction=counts['usable_records']/self.records if self.records else None)
        return {'version': QUALITY_VERSION, 'records': self.records, 'column_count': len(columns),
                'denominator': 'all_attempted_records_including_missing_modalities',
                'acquisition_counts': dict(self.acquisition), 'extraction_counts': dict(self.extraction),
                'temporal_counts': dict(self.temporal), 'quality_flag_counts': dict(self.flags),
                'alignment_counts': dict(self.pairing), 'alignment_reason_counts': dict(self.pairing_reasons),
                'all_modalities_usable_records': self.all_usable, 'yara_status_counts': dict(self.yara),
                'features': columns, 'labels_added': 0, 'training_eligible_added': 0,
                'model_fits': 0, 'calibrated_reliability': False,
                'interpretation': 'coverage_and_same_scan_binding_not_ground_truth_or_historical_equivalence'}
