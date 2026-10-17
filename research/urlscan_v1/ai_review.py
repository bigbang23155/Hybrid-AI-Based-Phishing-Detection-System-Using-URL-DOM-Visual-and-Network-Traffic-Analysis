"""Import the supplied AI workbook as coordinator annotations, never human votes."""
import argparse
from collections import Counter
import json
from pathlib import Path, PurePosixPath
import re
import xml.etree.ElementTree as ET
import zipfile

from .collector import QUEUE, encoded, rows, sha, timestamp, write_json

NS = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
REL = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id'
HEADERS = ['序號', 'review_id', 'AI 初判標籤', '信心程度', '逐筆判斷理由',
    '快照關鍵證據', '後續複核事項', '來源主機', '快照頁面標題', '快照檔案',
    'publisher_date', '語言', '快照 SHA-256', 'AI 審閱時間（UTC）']


def read_ai_sheet(path):
    with zipfile.ZipFile(path) as archive:
        if sum(i.file_size for i in archive.infolist()) > 30_000_000:
            raise ValueError('workbook too large')
        def xml(name):
            data = archive.read(name)
            if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
                raise ValueError('XML entities not supported')
            return ET.fromstring(data)
        shared = [''.join(t.text or '' for t in si.findall('.//m:t', NS))
                  for si in xml('xl/sharedStrings.xml')] if 'xl/sharedStrings.xml' in archive.namelist() else []
        workbook = xml('xl/workbook.xml')
        sheets = [s for s in workbook.findall('m:sheets/m:sheet', NS) if s.get('name') == '表格B']
        if len(sheets) != 1:
            raise ValueError('expected exactly one 表格B sheet')
        relations = {r.get('Id'): r for r in xml('xl/_rels/workbook.xml.rels')}
        relation = relations[sheets[0].get(REL)]
        target = relation.get('Target', '')
        if relation.get('TargetMode') == 'External' or '..' in PurePosixPath(target).parts:
            raise ValueError('external or unsafe worksheet')
        target = target.lstrip('/') if target.startswith('/') else 'xl/' + target
        table, started = [], False
        for row in xml(target).findall('m:sheetData/m:row', NS):
            cells = {}
            for cell in row:
                col = re.sub(r'\d', '', cell.get('r', ''))
                v = cell.find('m:v', NS)
                value = v.text or '' if v is not None else ''.join(t.text or '' for t in cell.findall('.//m:t', NS))
                if cell.get('t') == 's':
                    value = shared[int(value)]
                cells[col] = value
                if started and cell.find('m:f', NS) is not None:
                    raise ValueError('formula in annotation data')
            values = [cells.get(chr(65+i), '') for i in range(len(HEADERS))]
            if values == HEADERS:
                if started:
                    raise ValueError('duplicate header')
                started = True
            elif started and any(values):
                table.append(dict(zip(HEADERS, values)))
        if not started or not table:
            raise ValueError('missing annotation table')
        return table


def import_ai(workbook, output, queue_path=QUEUE):
    source_rows = read_ai_sheet(workbook)
    known = {r['review_id']: r for r in rows(queue_path)}
    annotations, seen = [], set()
    for row in source_rows:
        rid = row['review_id']
        if rid in seen or rid not in known:
            raise ValueError('duplicate or unknown review ID')
        seen.add(rid)
        if row['快照 SHA-256'] != known[rid]['html_sha256']:
            raise ValueError('snapshot SHA-256 binding mismatch')
        if row['快照檔案'] != 'snapshots/' + rid + '.html.txt':
            raise ValueError('snapshot path binding mismatch')
        label = row['AI 初判標籤']
        if label not in ('0', '1', 'uncertain'):
            raise ValueError('invalid AI label')
        if row['信心程度'] not in ('low', 'medium', 'high') or not row['逐筆判斷理由'].strip():
            raise ValueError('incomplete AI annotation')
        timestamp(row['AI 審閱時間（UTC）'])
        annotations.append({'review_id': rid, 'sample_id': known[rid]['sample_id'],
            'html_sha256': known[rid]['html_sha256'], 'reviewer_type': 'ai',
            'reviewer_id': 'AI_ASSISTANT_NOT_HUMAN', 'annotation_only': True,
            'ai_suggested_label': label, 'confidence': row['信心程度'],
            'confidence_is_calibrated_probability': False,
            'rationale': row['逐筆判斷理由'], 'snapshot_evidence_text': row['快照關鍵證據'],
            'follow_up': row['後續複核事項'], 'publisher_date': row['publisher_date'],
            'original_captured_at': None, 'ai_reviewed_at': row['AI 審閱時間（UTC）'],
            'human_review_status': 'pending', 'eligible_for_training': False,
            'acquisition_priority': 0 if label == 'uncertain' else 1,
            'url_resolution': 'requires_original_packet_url_no_host_inference'})
    annotations.sort(key=lambda r: (r['acquisition_priority'], r['review_id']))
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    private, public = output/'private', output/'public'
    private.mkdir(mode=0o700); public.mkdir()
    annotation_path = private/'ai_annotations.jsonl'
    annotation_path.write_bytes(b''.join(encoded(a)+b'\n' for a in annotations))
    summary = {'status': 'AI_ANNOTATIONS_IMPORTED_HUMAN_REVIEW_PENDING',
        'annotations': len(annotations), 'known_queue_items': len(known),
        'unannotated_queue_items': len(known)-len(annotations),
        'ai_label_counts': dict(Counter(a['ai_suggested_label'] for a in annotations)),
        'confidence_counts': dict(Counter(a['confidence'] for a in annotations)),
        'matched_review_ids_and_snapshot_hashes': len(annotations),
        'raw_snapshots_rehashed_this_import': 0, 'human_reviews_added': 0,
        'accepted_labels_added': 0, 'training_eligible_added': 0,
        'workbook_sha256': sha(workbook.read_bytes()), 'queue_sha256': sha(queue_path.read_bytes()),
        'annotations_sha256': sha(annotation_path.read_bytes()),
        'original_capture_times_supplied': 0,
        'access_rule': 'coordinator only; do not expose AI suggestions to independent blind reviewers'}
    write_json(public/'ai_import_summary.json', summary)
    return summary


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workbook', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(import_ai(args.workbook, args.output), indent=2))
