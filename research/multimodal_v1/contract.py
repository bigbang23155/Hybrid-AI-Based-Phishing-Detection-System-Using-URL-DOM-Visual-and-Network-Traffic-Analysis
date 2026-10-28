"""Missingness, time and numeric values are separate, versioned contracts."""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import math

from . import VERSION

MODALITIES = ('url', 'dom', 'visual', 'network_http')
ACQUISITION = frozenset(('available', 'not_supplied', 'not_found', 'download_failed',
                         'not_attempted', 'invalid_artifact', 'integrity_failed'))
EXTRACTION = frozenset(('ok', 'partial', 'unavailable', 'failed', 'dependency_missing'))


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode('utf-8')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError('timestamp_required')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.utcoffset() is None:
        raise ValueError('timezone_required')
    return result


def freshness(captured_at, *, as_of, max_age_seconds, applicable=True):
    reference = parse_time(as_of)
    if (type(max_age_seconds) not in (int, float) or not math.isfinite(max_age_seconds)
            or max_age_seconds < 0):
        raise ValueError('invalid_max_age')
    out = {'as_of': as_of, 'max_age_seconds': max_age_seconds,
           'captured_at': captured_at, 'age_seconds': None, 'status': 'unknown'}
    if not applicable:
        out['status'] = 'not_applicable'
        return out
    try:
        age = (reference - parse_time(captured_at)).total_seconds()
    except (TypeError, ValueError, OverflowError):
        return out
    out.update(age_seconds=age, status='future' if age < 0 else
               'stale' if age > max_age_seconds else 'fresh')
    return out


def feature_set(version, values, *, reasons=None, support=None):
    """None has a mandatory reason; zero must be an observed finite number."""
    reasons = dict(reasons or {})
    if set(reasons) - set(values):
        raise ValueError('unknown_feature_reason')
    for name, value in values.items():
        if value is None:
            if not reasons.get(name):
                raise ValueError('missing_value_requires_reason')
        elif (type(value) not in (int, float) or not math.isfinite(value)
              or name in reasons):
            raise ValueError('invalid_feature_value_or_reason')
    return {'registry_version': version, 'values': dict(values),
            'feature_order': list(values), 'missing_reasons': reasons, 'support': dict(support or {})}


def unavailable_features(version, names, reason):
    return feature_set(version, dict.fromkeys(names), reasons=dict.fromkeys(names, reason))


def modality(name, features, *, acquisition, extraction, temporal, provenance,
             reasons=(), quality_flags=()):
    if name not in MODALITIES or acquisition not in ACQUISITION or extraction not in EXTRACTION:
        raise ValueError('unknown_contract_state')
    if (len(features['feature_order']) != len(set(features['feature_order'])) or
            set(features['feature_order']) != set(features['values'])):
        raise ValueError('invalid_feature_order')
    feature_set(features['registry_version'], features['values'],
                reasons=features['missing_reasons'], support=features['support'])
    expected_temporal = freshness(temporal['captured_at'], as_of=temporal['as_of'],
        max_age_seconds=temporal['max_age_seconds'], applicable=name != 'url')
    if temporal != expected_temporal:
        raise ValueError('inconsistent_temporal_metadata')
    observed = {k: int(v is not None) for k, v in features['values'].items()}
    if (acquisition != 'available' or extraction in ('unavailable', 'failed', 'dependency_missing')) and any(observed.values()):
        raise ValueError('unavailable_modality_has_values')
    if extraction == 'ok' and not all(observed.values()):
        raise ValueError('ok_modality_has_missing_values')
    allowed = acquisition == 'available' and extraction in ('ok', 'partial') and temporal['status'] in ('fresh', 'not_applicable')
    usable = {k: int(allowed and v) for k, v in observed.items()}
    return {'modality': name, 'acquisition_status': acquisition, 'extraction_status': extraction,
            'reasons': sorted(set(reasons)), 'quality_flags': sorted(set(quality_flags)),
            'temporal': temporal, 'provenance': provenance, 'features': features,
            'observed_mask': observed, 'usable_mask': usable,
            'modality_available_mask': int(any(observed.values())),
            'modality_usable_mask': int(any(usable.values())),
            'observed_fraction': sum(observed.values()) / len(observed) if observed else 0.0}


def assemble(item_id, modalities, *, scope):
    if scope not in ('smoke_test', 'historical_development_audit'):
        raise ValueError('research_scope_only')
    if set(modalities) != set(MODALITIES):
        raise ValueError('exactly_four_modalities_required')
    for name, m in modalities.items():
        if m['modality'] != name:
            raise ValueError('modality_key_mismatch')
        # Revalidate and recompute masks; never trust serialized caller masks.
        modalities[name] = modality(name, m['features'], acquisition=m['acquisition_status'],
            extraction=m['extraction_status'], temporal=m['temporal'], provenance=m['provenance'],
            reasons=m['reasons'], quality_flags=m['quality_flags'])
    return {'schema_version': VERSION, 'item_id': item_id, 'scope': scope,
            'modalities': modalities, 'eligible_for_training': False,
            'human_review_status': 'pending', 'label': None}


def fusion_view(record):
    """Unfitted handoff only: stale/unknown evidence is null, never zero-imputed."""
    ordered = assemble(record['item_id'], dict(record['modalities']), scope=record['scope'])
    columns, values, masks = [], [], []
    for name in MODALITIES:
        m = ordered['modalities'][name]
        for key in m['features']['feature_order']:
            value = m['features']['values'][key]
            columns.append(name + '__' + key)
            masks.append(m['usable_mask'][key])
            values.append(value if masks[-1] else None)
    return {'columns': columns, 'values': values, 'feature_mask': masks,
            'modality_order': list(MODALITIES),
            'modality_mask': [ordered['modalities'][n]['modality_usable_mask'] for n in MODALITIES],
            'all_missing': not any(masks), 'imputation': 'none',
            'attention_weights': None, 'eligible_for_training': False}
