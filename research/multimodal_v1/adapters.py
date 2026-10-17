"""Read verified Collector checkpoints into four modalities, without network I/O."""
from __future__ import annotations

import json
from pathlib import Path

from phishing_url.dom_features import DOM_FEATURE_NAMES, REGISTRY_VERSION, extract_dom_features
from phishing_url.features import FEATURE_NAMES, extract_features
from research.urlscan_v1.collector import normalized_url
from research.urlscan_v1.client import CaptureError

from .contract import (assemble, encoded, feature_set, freshness, modality, sha,
                       parse_time, unavailable_features)
from . import forensics, network_http

URL_VERSION = 'frozen-url-lexical18-adapter-v1'
VISUAL_NAMES = ('width', 'height', 'grayscale_stddev')
VISUAL_VERSION = 'dom-tags-shingle5-minhash64-phash64-dhash64-v1'
SPEC = {'url': (URL_VERSION, FEATURE_NAMES), 'dom': (REGISTRY_VERSION, DOM_FEATURE_NAMES),
        'visual': (VISUAL_VERSION + '-quality-adapter-v1', VISUAL_NAMES),
        'network_http': (network_http.VERSION, network_http.NAMES)}
MAX_ARTIFACT_BYTES = 20_000_000


def read_artifact(folder, spec):
    """Never substitute an unverified file for a checkpoint artifact."""
    if not isinstance(spec, dict) or not isinstance(spec.get('file'), str):
        raise ValueError('invalid_artifact_spec')
    path = folder / spec['file']
    if path.is_symlink() or not path.resolve().is_relative_to(folder.resolve()):
        raise ValueError('artifact_path_escape')
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError('artifact_byte_limit')
    data = path.read_bytes()
    if sha(data) != spec.get('sha256') or len(data) != spec.get('bytes'):
        raise ValueError('artifact_integrity_failed')
    return path, data


def absent(record, kind):
    error = record.get('errors', {}).get(kind)
    if error:
        code = error.get('code', 'unknown_error')
        if error.get('http_status') in (404, 410):
            return 'not_found', code
        if code.startswith('invalid_') or code == 'dom_has_no_markup':
            return 'invalid_artifact', code
        return 'download_failed', code
    capture_error = record.get('errors', {}).get('capture', {})
    code = capture_error.get('code')
    if code == 'no_exact_public_scan_in_search_window':
        return 'not_found', code
    if kind == 'result' and code:
        return 'download_failed', code
    if code:
        return 'not_attempted', code
    return 'not_supplied', kind + '_not_supplied'


def from_checkpoint(checkpoint, *, as_of, max_age_seconds, run_yara=True):
    checkpoint = Path(checkpoint)
    if checkpoint.is_symlink() or checkpoint.stat().st_size > 1_000_000:
        raise ValueError('invalid_checkpoint')
    record_raw = checkpoint.read_bytes()
    record = json.loads(record_raw)
    scope = record.get('scope')
    if scope not in ('smoke_test', 'historical_development_audit'):
        raise ValueError('research_scope_only')
    # Also validates caller-specified freshness policy before touching artifacts.
    temporal = freshness(record.get('scan_time'), as_of=as_of, max_age_seconds=max_age_seconds)
    artifacts = record.get('artifacts', {})
    if not isinstance(artifacts, dict):
        raise ValueError('invalid_checkpoint_artifacts')
    loaded, failed = {}, {}
    for kind in ('result', 'dom', 'screenshot'):
        if kind not in artifacts:
            continue
        try:
            loaded[kind] = read_artifact(checkpoint.parent, artifacts[kind])
        except (OSError, ValueError):
            failed[kind] = 'artifact_integrity_or_access_failed'
    result, identity_ok = None, False
    if 'result' in loaded:
        try:
            result = json.loads(loaded['result'][1])
            task = result['task']
            identity_ok = (task['uuid'] == record['scan_uuid'] and
                normalized_url(task['url']) == normalized_url(record['requested_url']) and
                task['visibility'] == 'public' and
                parse_time(task['time']) == parse_time(record['scan_time']))
            if not identity_ok:
                failed['result'] = 'result_identity_mismatch'
        except (ValueError, TypeError, KeyError, CaptureError):
            failed['result'] = 'invalid_result_or_identity'
    # Prevent unbound DOM/screenshots from being silently paired with another scan.
    if not identity_ok:
        for kind in ('dom', 'screenshot'):
            if kind in loaded:
                failed[kind] = 'result_identity_unverified'

    common = {'checkpoint_sha256': sha(record_raw), 'provider': record.get('provider'),
              'scan_uuid': record.get('scan_uuid'), 'retrieved_at': record.get('retrieved_at')}
    modalities, sidecars = {}, {}
    for name, kind in (('url', None), ('dom','dom'), ('visual','screenshot'), ('network_http','result')):
        version, names = SPEC[name]
        flags = list(record.get('quality_flags', []))
        provenance = dict(common)
        t = temporal
        reasons = []
        if name == 'url':
            # Lexical URL is the submitted string, not a newly observed web page.
            t = freshness(None, as_of=as_of, max_age_seconds=max_age_seconds, applicable=False)
            try:
                value = record['requested_url']
                normalized_url(value)
                features = feature_set(version, extract_features(value))
                acquisition, extraction = 'available', 'ok'
                provenance.update(source_sha256=sha(value.encode()), basis='requested_url_string')
            except (KeyError, TypeError, ValueError, CaptureError):
                acquisition, extraction = 'invalid_artifact', 'unavailable'
                reasons = ['invalid_requested_url']
                features = unavailable_features(version, names, reasons[0])
        elif kind in failed:
            acquisition, extraction = 'integrity_failed', 'unavailable'
            reasons = [failed[kind]]
            features = unavailable_features(version, names, reasons[0])
        elif kind not in loaded:
            acquisition, reason = absent(record, kind)
            extraction, reasons = 'unavailable', [reason]
            features = unavailable_features(version, names, reason)
        else:
            path, data = loaded[kind]
            acquisition = 'available'
            provenance['source_sha256'] = sha(data)
            try:
                if name == 'network_http':
                    features = network_http.extract(result)
                    provenance['registry_sha256'] = network_http.REGISTRY_SHA256
                    provenance['representation'] = 'HTTP_METADATA_NOT_HAR_OR_PCAP'
                elif name == 'dom':
                    features = feature_set(version, extract_dom_features(data.decode('utf-8-sig'), result['page']['url']))
                else:
                    from research.urlscan_v1.similarity import visual_signature
                    from PIL import Image
                    try:
                        signature = visual_signature(path)
                    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
                        raise ValueError('image_pixel_limit') from None
                    features = feature_set(version, {'width': signature['dimensions'][0],
                        'height': signature['dimensions'][1], 'grayscale_stddev': signature['grayscale_stddev']})
                    sidecars['visual_signature'] = signature
                    flags.append('quality_features_only_no_semantic_visual_embedding')
                    if signature['flat_image']:
                        flags.append('flat_image')
                extraction = 'partial' if features['missing_reasons'] else 'ok'
            except ImportError:
                extraction = 'dependency_missing'
                reasons = ['extractor_dependency_missing']
                features = unavailable_features(version, names, reasons[0])
            except (ValueError, UnicodeError, OSError, KeyError, TypeError):
                extraction = 'failed'
                reasons = ['extraction_failed_or_resource_limit']
                features = unavailable_features(version, names, reasons[0])
            if name == 'dom':
                sidecars['content_forensics'] = forensics.inspect(data, run_yara=run_yara)
        modalities[name] = modality(name, features, acquisition=acquisition, extraction=extraction,
            temporal=t, provenance=provenance, reasons=reasons, quality_flags=flags)
    output = assemble(record['candidate_sha256'], modalities, scope=scope)
    output['sidecars'] = sidecars
    output['source_record_sha256'] = sha(record_raw)
    return output
