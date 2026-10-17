"""Bind private packets to annotations and plan reproducible uncertain batches."""
import argparse
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from .collector import QUEUE, encoded, rows, sha, normalized_url, write_json
from .client import CaptureError


def bound_packets(packet_path, queue_path=QUEUE):
    packets = rows(packet_path)
    known = {r['review_id']: r for r in rows(queue_path)}
    seen = set()
    for packet in packets:
        rid = packet['review_id']
        if rid in seen or rid not in known or packet.get('scope') != 'historical_development_audit':
            raise ValueError('packet membership or scope mismatch')
        seen.add(rid)
        if any(packet.get(k) != known[rid][k] for k in ('sample_id', 'html_sha256')):
            raise ValueError('packet identity mismatch')
        if packet.get('snapshot_path') != f'snapshots/{rid}.html.txt':
            raise ValueError('snapshot path binding mismatch')
        path = packet_path.parent / packet['snapshot_path']
        if path.is_symlink() or not path.resolve().is_relative_to(packet_path.parent.resolve()):
            raise ValueError('unsafe snapshot path')
        if sha(path.read_bytes()) != packet['html_sha256']:
            raise ValueError('snapshot bytes binding mismatch')
    return packets


def plan(packet_path, annotation_path, output, *, batch_size=5, seed='urlscan-uncertain-v1', queue_path=QUEUE):
    if not 1 <= batch_size <= 20:
        raise ValueError('batch size must be 1..20')
    packets = bound_packets(packet_path, queue_path)
    lookup = {p['review_id']: p for p in packets}
    annotations = rows(annotation_path)
    seen, candidates, blocked = set(), [], []
    for annotation in annotations:
        rid = annotation.get('review_id')
        packet = lookup.get(rid)
        if rid in seen or packet is None:
            raise ValueError('unknown or duplicate annotation')
        seen.add(rid)
        if any(annotation.get(k) != packet[k] for k in ('sample_id', 'html_sha256')):
            raise ValueError('annotation identity mismatch')
        if annotation.get('reviewer_type') != 'ai' or annotation.get('annotation_only') is not True or annotation.get('eligible_for_training') is not False:
            raise ValueError('expected coordinator AI annotation')
        if annotation.get('ai_suggested_label') not in ('0', '1', 'uncertain'):
            raise ValueError('invalid annotation label')
        if annotation['ai_suggested_label'] == 'uncertain':
            try:
                normalized_url(packet.get('url'))
            except CaptureError:
                blocked.append({'review_id': rid, 'reason': 'invalid_or_userinfo_url_manual_resolution_required'})
                continue
            # A fresh allowlist: never forward votes, rationales or inferred timestamps.
            candidates.append({k: packet[k] for k in ('review_id', 'sample_id', 'html_sha256', 'url', 'scope', 'publisher_date')})
    candidates.sort(key=lambda c: sha((seed + ':' + c['review_id']).encode()))
    # Stable host diversity within each batch, without dropping repeat hosts.
    ordered = []
    pending = list(candidates)
    while pending:
        batch, hosts = [], set()
        for c in pending:
            host = urlsplit(c['url']).hostname
            if host not in hosts and len(batch) < batch_size:
                batch.append(c); hosts.add(host)
        ids = {c['review_id'] for c in batch}
        if len(batch) < batch_size:
            for c in pending:
                if c['review_id'] not in ids and len(batch) < batch_size:
                    batch.append(c); ids.add(c['review_id'])
        ordered.extend(batch)
        pending = [c for c in pending if c['review_id'] not in ids]
    if not ordered:
        raise ValueError('no uncertain candidates')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    private, public = output/'private', output/'public'
    private.mkdir(mode=0o700); public.mkdir()
    (private/'uncertain_candidates.jsonl').write_bytes(b''.join(encoded(c)+b'\n' for c in ordered))
    (private/'blocked_candidates.jsonl').write_bytes(b''.join(encoded(c)+b'\n' for c in blocked))
    for offset in range(0, len(ordered), batch_size):
        (private/f'batch-{offset//batch_size+1:03d}.jsonl').write_bytes(b''.join(encoded(c)+b'\n' for c in ordered[offset:offset+batch_size]))
    summary = dict(status='PREPARED_NOT_COLLECTED', packets_verified=len(packets),
        raw_snapshots_rehashed=len(packets), annotations_joined=len(annotations),
        uncertain_total=len(ordered)+len(blocked), uncertain_candidates=len(ordered),
        uncertain_blocked=len(blocked), batch_size=batch_size, batches=(len(ordered)+batch_size-1)//batch_size,
        distinct_hosts=len({urlsplit(c['url']).hostname for c in ordered}),
        distinct_normalized_urls=len({normalized_url(c['url']) for c in ordered}),
        ordering='seeded_sha256_then_hostname_diversity_within_batch_not_statistical_sampling', seed=seed,
        packet_file_sha256=sha(packet_path.read_bytes()), annotation_file_sha256=sha(annotation_path.read_bytes()),
        queue_sha256=sha(queue_path.read_bytes()), candidates_sha256=sha((private/'uncertain_candidates.jsonl').read_bytes()),
        ai_label_counts=dict(Counter(a['ai_suggested_label'] for a in annotations)),
        human_reviews_added=0, training_eligible_added=0, model_fits=0,
        timestamp_rule='publisher_date_is_not_capture_time',
        raw_urls_public=False)
    write_json(public/'batch_plan_summary.json', summary)
    return summary


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--packets', required=True, type=Path)
    p.add_argument('--annotations', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--batch-size', type=int, default=5)
    a = p.parse_args()
    try:
        print(encoded(plan(a.packets, a.annotations, a.output, batch_size=a.batch_size)).decode())
    except (ValueError, OSError, KeyError):
        raise SystemExit('packet_or_annotation_validation_failed') from None
