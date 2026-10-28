"""Versioned DOM/visual candidate retrieval, never label transfer or clustering.

Top-k is a review workload control, not a calibrated same-template threshold.
All rows remain historical development audit records, ineligible for training.
"""
import argparse
from collections import Counter
from html.parser import HTMLParser
import json
from pathlib import Path
import warnings

import numpy as np
from PIL import Image, ImageOps
from scipy.fft import dctn

from .batch_plan import bound_packets
from .collector import encoded, rows, sha, write_json

VERSION = 'dom-tags-shingle5-minhash64-phash64-dhash64-v1'
MAX_TOKENS = 100000
Image.MAX_IMAGE_PIXELS = 25_000_000


class Structure(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tokens = []
    def add(self, value):
        if len(self.tokens) >= MAX_TOKENS:
            raise ValueError('dom_token_limit')
        self.tokens.append(value)
    def handle_starttag(self, tag, attrs):
        self.add('<' + tag + '>')
    def handle_startendtag(self, tag, attrs):
        self.add('<' + tag + '/>')
    def handle_endtag(self, tag):
        self.add('</' + tag + '>')


def dom_signature(data):
    if len(data) > 20_000_000:
        raise ValueError('dom_byte_limit')
    parser = Structure(); parser.feed(data.decode('utf-8-sig')); parser.close()
    tokens = parser.tokens
    if not tokens:
        raise ValueError('dom_has_no_markup')
    canonical = '\n'.join(tokens).encode()
    shingles = sorted({sha('\n'.join(tokens[i:i+5]).encode()) for i in range(len(tokens)-4)})
    result = {'raw_sha256': sha(data), 'canonical_sha256': sha(canonical),
        'token_count': len(tokens), 'unique_shingles': len(shingles),
        'minhash64': None, 'tlsh': None, 'tlsh_status': 'optional_dependency_not_installed'}
    if shingles:
        # Fixed seeded universal hash family over a 32-bit prime field.
        prime = np.uint64(4294967291)
        rng = np.random.default_rng(20261017)
        a = rng.integers(1, int(prime), size=64, dtype=np.uint64)
        b = rng.integers(0, int(prime), size=64, dtype=np.uint64)
        minimum = np.full(64, prime, dtype=np.uint64)
        for offset in range(0, len(shingles), 4096):
            x = np.array([int(s[:8], 16) for s in shingles[offset:offset+4096]], dtype=np.uint64) % prime
            values = (a[:,None] * x[None,:] + b[:,None]) % prime
            minimum = np.minimum(minimum, values.min(axis=1))
        result['minhash64'] = [int(v) for v in minimum]
    try:
        import tlsh
        value = tlsh.hash(canonical)
        result['tlsh'] = value if value and value != 'TNULL' else None
        result['tlsh_status'] = 'available' if result['tlsh'] else 'insufficient_length_or_variation'
    except ImportError:
        pass
    return result


def bithex(bits):
    return f'{int("".join("1" if b else "0" for b in bits), 2):016x}'


def visual_signature(path):
    if path.stat().st_size > 20_000_000:
        raise ValueError('image_byte_limit')
    with warnings.catch_warnings():
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        with Image.open(path) as im:
            if im.format != 'PNG':
                raise ValueError('not_png')
            im.load()
            dimensions = list(im.size)
            # White alpha composite and aspect-preserving letterbox, not a stretch.
            rgba = im.convert('RGBA')
            white = Image.new('RGBA', rgba.size, 'white')
            white.alpha_composite(rgba)
            gray = ImageOps.pad(white.convert('L'), (256, 256), method=Image.Resampling.LANCZOS, color=255)
            small = np.asarray(gray.resize((32, 32), Image.Resampling.LANCZOS), dtype=np.float64)
            coefficients = dctn(small, type=2, norm='ortho')[:8,:8].flatten()
            phash = coefficients > np.median(coefficients[1:])
            phash[0] = False  # Explicit DC exclusion, 63 effective bits in a 64-bit representation.
            dh = np.asarray(gray.resize((9, 8), Image.Resampling.LANCZOS))
            contrast = float(np.std(np.asarray(gray, dtype=np.float64)))
    return {'raw_sha256': sha(path.read_bytes()), 'dimensions': dimensions,
        'phash64': bithex(phash), 'dhash64': bithex((dh[:,1:] > dh[:,:-1]).flatten()),
        'grayscale_stddev': contrast, 'flat_image': contrast < 1.0,
        'preprocess': 'white_alpha_letterbox256_lanczos_gray_DC_zero'}


def historical_records(packet_path):
    for packet in bound_packets(packet_path):
        yield {'item_id': 'historical:' + packet['review_id'], 'review_id': packet['review_id'],
            'scope': packet['scope'], 'original_snapshot_sha256': packet['html_sha256'],
            'dom_path': packet_path.parent / packet['snapshot_path'], 'screenshot_path': None,
            'quality_flags': ['historical_static_snapshot', 'screenshot_not_supplied'], 'scan_time': None}


def acquired_records(run):
    for checkpoint in sorted((run/'private').glob('*/record.json')):
        record = json.loads(checkpoint.read_text())
        artifacts = {}
        for kind, spec in record['artifacts'].items():
            path = checkpoint.parent / spec['file']
            if path.is_symlink() or not path.resolve().is_relative_to(checkpoint.parent.resolve()) or sha(path.read_bytes()) != spec['sha256']:
                raise ValueError('acquired artifact integrity failure')
            artifacts[kind] = path
        yield {'item_id': 'urlscan:' + record['candidate_sha256'], 'review_id': record['review_id'],
            'scope': record['scope'], 'original_snapshot_sha256': record.get('original_snapshot_sha256'),
            'dom_path': artifacts.get('dom'), 'screenshot_path': artifacts.get('screenshot'),
            'quality_flags': record['quality_flags'], 'scan_time': record.get('scan_time')}


def candidates(index, top_k=5):
    if not 1 <= top_k <= 20:
        raise ValueError('top_k must be 1..20')
    if len(index) > 5000:
        raise ValueError('pairwise candidate cap exceeded; shard or add ANN')
    pairs = {}
    def propose(left, right, reason):
        key = tuple(sorted((left['item_id'], right['item_id'])))
        if key not in pairs:
            pairs[key] = {'left': key[0], 'right': key[1], 'retrieval_reasons': [],
                'human_pair_review': 'pending', 'same_template': None, 'same_campaign': None,
                'label_transfer': False, 'split_group_assignment': None}
        if reason not in pairs[key]['retrieval_reasons']:
            pairs[key]['retrieval_reasons'].append(reason)
        return pairs[key]
    for left in index:
        for modality in ('dom', 'visual'):
            if not left.get(modality):
                continue
            ranked = []
            for right in index:
                if left is right or not right.get(modality):
                    continue
                if modality == 'dom':
                    a, b = left['dom'], right['dom']
                    if not a.get('minhash64') or not b.get('minhash64'):
                        continue
                    score = sum(x == y for x,y in zip(a['minhash64'], b['minhash64'])) / 64
                    ranked.append((-score, right['item_id'], right))
                else:
                    a, b = left['visual'], right['visual']
                    if a['flat_image'] or b['flat_image']:
                        continue
                    distance = (int(a['phash64'],16) ^ int(b['phash64'],16)).bit_count()
                    ranked.append((distance, right['item_id'], right))
            for score, _, right in sorted(ranked, key=lambda r: (r[0],r[1]))[:top_k]:
                pair = propose(left, right, modality + '_top_k_uncalibrated')
                if modality == 'dom':
                    pair['minhash_estimated_jaccard'] = -score
                    pair['canonical_exact_match'] = left['dom']['canonical_sha256'] == right['dom']['canonical_sha256']
                    pair['raw_dom_exact_match'] = left['dom']['raw_sha256'] == right['dom']['raw_sha256']
                else:
                    pair['phash_hamming'] = score
                    pair['dhash_hamming'] = (int(left['visual']['dhash64'],16)^int(right['visual']['dhash64'],16)).bit_count()
                pair['same_review_id'] = left['review_id'] == right['review_id']
    return [pairs[k] for k in sorted(pairs)]


def build(records, output, *, top_k=5):
    index, seen = [], set()
    for source in records:
        if source['item_id'] in seen:
            raise ValueError('duplicate evidence item')
        seen.add(source['item_id'])
        row = {k:v for k,v in source.items() if not k.endswith('_path')}
        row.update(version=VERSION, eligible_for_training=False, human_review_status='pending', dom=None, visual=None, errors={})
        for modality, field, compute in [('dom', 'dom_path', lambda p: dom_signature(p.read_bytes())), ('visual', 'screenshot_path', visual_signature)]:
            path = source.get(field)
            if path:
                try:
                    row[modality] = compute(path)
                except (ValueError, UnicodeError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning):
                    row['errors'][modality] = 'unusable_or_resource_limit'
        index.append(row)
    pairs = candidates(index, top_k)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    private, public = output/'private', output/'public'
    private.mkdir(mode=0o700); public.mkdir()
    for filename, data in [('index.jsonl', index), ('candidate_pairs.jsonl', pairs)]:
        (private/filename).write_bytes(b''.join(encoded(r)+b'\n' for r in data))
    exact = Counter(r['dom']['canonical_sha256'] for r in index if r['dom'])
    summary = {'version': VERSION, 'evidence_items': len(index), 'dom_available': sum(bool(r['dom']) for r in index),
        'visual_available': sum(bool(r['visual']) for r in index), 'candidate_pairs': len(pairs), 'top_k_per_modality': top_k,
        'canonical_exact_groups_ge2': sum(n>1 for n in exact.values()),
        'canonical_exact_members_ge2': sum(n for n in exact.values() if n>1),
        'flat_images_excluded_from_visual_retrieval': sum(bool(r['visual'] and r['visual']['flat_image']) for r in index),
        'tlsh_status_counts': dict(Counter(r['dom']['tlsh_status'] for r in index if r['dom'])),
        'error_counts': dict(Counter(k for r in index for k in r['errors'])),
        'index_sha256': sha((private/'index.jsonl').read_bytes()),
        'pairs_sha256': sha((private/'candidate_pairs.jsonl').read_bytes()),
        'thresholds_calibrated': False, 'human_reviews_added': 0, 'accepted_labels_added': 0,
        'clusters_automatically_merged': 0, 'training_eligible_added': 0,
        'limits': 'tags-only structure omits attributes/text; top-k may include unrelated pairs; no campaign inference; missing visuals not imputed'}
    write_json(public/'similarity_summary.json', summary)
    return summary


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--packets', type=Path)
    p.add_argument('--run', type=Path)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--top-k', type=int, default=5)
    a = p.parse_args()
    if not a.packets and not a.run:
        p.error('packets or run required')
    try:
        records = list(historical_records(a.packets)) if a.packets else []
        if a.run:
            records.extend(acquired_records(a.run))
        print(encoded(build(records, a.output, top_k=a.top_k)).decode())
    except (ValueError, OSError, KeyError):
        raise SystemExit('similarity_input_validation_failed') from None
