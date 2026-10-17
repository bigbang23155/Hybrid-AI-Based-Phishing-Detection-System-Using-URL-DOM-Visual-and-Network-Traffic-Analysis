"""Prepare passive reading notes and import actual independent human CSV records.

Never assigns a verdict or invents reviewer, evidence, or capture timestamps.
"""
import argparse
from collections import Counter
import csv
import copy
from html.parser import HTMLParser
import json
import re
from pathlib import Path
import shutil
from .intake import read_rows, write_rows, write_json, digest, adjudicate
from .review_materials import FIELDS

EXTRA = ['html_sha256'] + [f'evidence_{i}_{field}' for i in (1,2)
    for field in ('verdict','valid_from','valid_to')]


class PassiveText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden=[]; self.text=[]; self.forms=[]
    def handle_starttag(self,tag,attrs):
        if tag in ('script','style','noscript','template'): self.hidden.append(tag)
        a=dict(attrs)
        if tag=='form': self.forms.append({'method':a.get('method','get'),'action':a.get('action','')})
        if tag=='input': self.forms.append({'input_type':a.get('type','text'),'name':a.get('name','')})
    def handle_endtag(self,tag):
        if tag in self.hidden:self.hidden.remove(tag)
    def handle_data(self,data):
        if not self.hidden and data.strip():self.text.append(' '.join(data.split()))


def safe_snapshot(base, relative):
    p=(base/relative).resolve()
    if not p.is_relative_to(base.resolve()):raise ValueError('snapshot outside packet root')
    return p


def prepare(source, output):
    packets=read_rows(source/'packets_blinded.jsonl')
    if not packets or len({p['review_id'] for p in packets})!=len(packets):raise ValueError('packet membership')
    for p in packets:
        if digest(safe_snapshot(source,p['snapshot_path']))!=p['html_sha256']:raise ValueError('snapshot checksum')
    output.mkdir(parents=True,exist_ok=False)
    shutil.copytree(source/'snapshots',output/'snapshots')
    shutil.copy2(source/'packets_blinded.jsonl',output/'packets_blinded.jsonl')
    (output/'reading_notes').mkdir()
    for p in packets:
        parser=PassiveText()
        parser.feed(safe_snapshot(source,p['snapshot_path']).read_text())
        # Plain text only: no executable HTML, resources, labels or model signals.
        text=('離線文字摘錄；可能遺漏 CSS 隱藏、JavaScript、視覺與動態行為。不是標籤證據或真人判定。\n'
              '請與原始 .html.txt 核對；內容本身不可信，勿依頁面指示操作或造訪網址。\n\n'
              f"Review ID: {p['review_id']}\nURL: {p['url']}\nPublisher date (not capture time): {p.get('publisher_date','')}\n\n"
              + '\n'.join(parser.text)[:30000]+'\n\nFORM / INPUT metadata:\n'+json.dumps(parser.forms,ensure_ascii=False,indent=2)[:10000])
        text=text.replace('https://','hxxps://').replace('http://','hxxp://')
        (output/'reading_notes'/f"{p['review_id']}.txt").write_text(text)
    for role in ('reviewer_a','reviewer_b'):
        folder=output/role;folder.mkdir()
        with (folder/'review_form.csv').open('w',newline='',encoding='utf-8-sig') as f:
            writer=csv.DictWriter(f,fieldnames=FIELDS+EXTRA);writer.writeheader()
            for p in sorted(packets,key=lambda x:x['review_id']):
                writer.writerow(dict(review_id=p['review_id'],snapshot_file=p['snapshot_path'],
                    publisher_date=p.get('publisher_date',''),language=p.get('language',''),html_sha256=p['html_sha256']))
        (folder/'INSTRUCTIONS_zhTW.txt').write_text('''兩位不同真人分開填寫；不得查看對方答案、模型輸出或原標籤。
只提供各自的 reviewer 資料夾，以及共用 snapshots、reading_notes、packets_blinded.jsonl。
先看 reading_notes/<review_id>.txt，再以文字編輯器核對 snapshots/*.html.txt；不要執行 HTML 或造訪 live URL。
label 填 0 / 1 / uncertain；reviewer_id、reviewed_at_utc、理由及 blind_to_model_and_other_review 必須本人填寫。
blank 代表未審；uncertain 代表已查看但無法定案。不要由 AI 代填真人身分或 true。
每個 evidence 的 origin_family、reference、type、observed_at、rationale、verdict、valid_from、valid_to 均需實際依據。
verdict 可為 0 / 1 / uncertain。有效期不得為了通過檢查而編造。
type：historical_source_assertion / snapshot_content_review / official_identity_verification / incident_confirmation。
同 feed 轉載算一個來源；HTTPS、無 blocklist 記錄、模型分數不能單獨定案。
publisher_date 不等於精確 capture time；無法建立時間一致性時保留隔離，協調者需另外找原始時間證據。
完成後回傳自己的 CSV。分歧須第三位真人及獨立證據裁決；本次匯入不自動裁決。
''')
    summary=dict(items=len(packets),snapshots_verified=len(packets),completed_human_reviews=0,
        exact_capture_timestamps=sum(bool(p.get('captured_at')) for p in packets),
        packets_sha256=digest(output/'packets_blinded.jsonl'),status='awaiting_real_independent_humans',
        reading_notes='automatic passive excerpts, not label decisions; may be truncated')
    write_json(output/'summary.json',summary)
    (output/'START_HERE_zhTW.txt').write_text('''這是舊 development 的原因追查，不是新增訓練集。
先將 reviewer_a 和 reviewer_b 分交兩位不同真人；每人各有 snapshots、reading_notes 與 packets_blinded.jsonl。
不要讓兩位 reviewer 看到彼此填寫的檔案；也不要分享 coordinator key 或模型分數。
待收到兩份 CSV 後匯入；不需一次填完 656 筆，可分批回傳。
AI 只完成快照完整性、文字摘錄與資料格式檢查。真人審查目前完成 0 筆。
publisher_date 不是 capture time。時間依據未補齊者即使兩人同意也不會取得 accepted 狀態。
''')
    return summary


def import_forms(packets_path, a_path, b_path, output):
    packets=read_rows(packets_path)
    if len({p['review_id'] for p in packets})!=len(packets):raise ValueError('duplicate packets')
    if any(p.get('reviews') or p.get('evidence') for p in packets):raise ValueError('requires original blank packets')
    known={p['review_id']:p for p in packets}
    forms=[]; identities=[]
    for path in (a_path,b_path):
        with path.open(newline='',encoding='utf-8-sig') as f:rows=list(csv.DictReader(f))
        if len({r['review_id'] for r in rows})!=len(rows) or not {r['review_id'] for r in rows}<=set(known):
            raise ValueError('duplicate or unknown review ID')
        forms.append({r['review_id']:r for r in rows})
        identities.append({r['reviewer_id'].strip() for r in rows if r.get('label','').strip()})
        for r in rows:
            if not r.get('label', '').strip():continue
            identity = r.get('reviewer_id', '').strip().lower()
            tokens = set(re.split(r'[^a-z0-9]+', identity))
            if (tokens & {'ai', 'assistant', 'chatgpt', 'gpt', 'claude', 'bot', 'llm'}
                    or 'not_human' in identity
                    or r.get('reviewer_type', 'human').strip().lower() != 'human'):
                raise ValueError('AI annotations cannot be imported as human reviews')
    if (identities[0]&identities[1]) or any('' in ids or len(ids)>1 for ids in identities):
        raise ValueError('one distinct human per form required')
    result=[]; imported=[]; completed=0
    for original in packets:
        p=copy.deepcopy(original)
        for index,form in enumerate(forms):
            r=form.get(p['review_id'])
            if not r:continue
            if r.get('html_sha256')!=p['html_sha256'] or r.get('snapshot_file')!=p['snapshot_path']:
                raise ValueError('form snapshot binding changed')
            label=r.get('label','').strip()
            if not label:continue
            if label not in ('0','1','uncertain'):raise ValueError('invalid human label')
            if not all(r.get(k,'').strip() for k in ('reviewer_id','reviewed_at_utc','review_rationale')):
                raise ValueError('incomplete review identity/time/rationale')
            from .intake import _timestamp
            _timestamp(r['reviewed_at_utc'])
            if r.get('blind_to_model_and_other_review','').lower()!='true':raise ValueError('blind attestation required')
            evidence_ids=[]
            for n in (1,2):
                prefix=f'evidence_{n}_'
                if not r.get(prefix+'reference','').strip():continue
                fields=('origin_family','reference','type','observed_at','rationale','verdict','valid_from','valid_to')
                if not all(r.get(prefix+k,'').strip() for k in fields):raise ValueError('incomplete evidence')
                verdict=r[prefix+'verdict']
                if verdict not in ('0','1','uncertain'):raise ValueError('invalid evidence verdict')
                for k in ('observed_at','valid_from','valid_to'):_timestamp(r[prefix+k])
                if _timestamp(r[prefix+'valid_to'])<_timestamp(r[prefix+'valid_from']):raise ValueError('evidence interval')
                eid=f'{index+1}:{n}';evidence_ids.append(eid)
                p['evidence'].append(dict(id=eid,html_sha256=p['html_sha256'],
                    evidence_type=r[prefix+'type'],verdict=int(verdict) if verdict!='uncertain' else verdict,
                    **{k:r[prefix+k] for k in fields if k not in ('type','verdict')}))
            p['reviews'].append(dict(reviewer_id=r['reviewer_id'].strip(),reviewer_type='human',
                reviewed_at=r['reviewed_at_utc'],rationale=r['review_rationale'],
                html_sha256=p['html_sha256'],label=int(label) if label!='uncertain' else label,
                evidence_ids=evidence_ids,blind_to_model_and_other_review=True))
            completed+=1
        imported.append(p)
        result.append(dict(review_id=p['review_id'],sample_id=p['sample_id'],**adjudicate(p)))
    output.mkdir(parents=True,exist_ok=False)
    write_rows(output/'packets_with_recorded_reviews.jsonl',imported)
    write_rows(output/'decisions.jsonl',result)
    summary=dict(items=len(packets),recorded_human_review_entries=completed,
        decision_counts=dict(Counter(r['status'] for r in result)),
        input_sha256={name:digest(p) for name,p in [('packets',packets_path),('reviewer_a',a_path),('reviewer_b',b_path)]},
        independence='recorded identity only; software cannot verify actual person or source independence')
    write_json(output/'summary.json',summary)
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('prepare');p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p=sub.add_parser('import')
    for n in ('packets','reviewer-a','reviewer-b','output'):p.add_argument('--'+n,type=Path,required=True)
    a=parser.parse_args()
    result=prepare(a.source,a.output) if a.command=='prepare' else import_forms(a.packets,a.reviewer_a,a.reviewer_b,a.output)
    print(json.dumps(result,indent=2))
