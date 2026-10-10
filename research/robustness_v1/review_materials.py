"""Build two independent blind human-review forms from private packets."""
import argparse
import csv
import json
from pathlib import Path
from .intake import read_rows, write_json, digest

FIELDS=['review_id','snapshot_file','publisher_date','language','reviewer_id','reviewed_at_utc',
        'label','confidence','evidence_1_origin_family','evidence_1_reference','evidence_1_type',
        'evidence_1_observed_at','evidence_1_rationale','evidence_2_origin_family',
        'evidence_2_reference','evidence_2_type','evidence_2_observed_at','evidence_2_rationale',
        'review_rationale','blind_to_model_and_other_review']


def run(packets_path,output):
    packets=read_rows(packets_path)
    if not packets or len({r['review_id'] for r in packets})!=len(packets):raise ValueError('empty or duplicate packets')
    output.mkdir(parents=True,exist_ok=False)
    for reviewer in ('reviewer_a','reviewer_b'):
        folder=output/reviewer;folder.mkdir()
        with (folder/'review_form.csv').open('w',newline='',encoding='utf-8') as stream:
            writer=csv.DictWriter(stream,fieldnames=FIELDS);writer.writeheader()
            for p in sorted(packets,key=lambda r:r['review_id']):
                writer.writerow(dict(review_id=p['review_id'],snapshot_file=p['snapshot_path'],
                    publisher_date=p.get('publisher_date') or '',language=p.get('language') or '',
                    reviewer_id='',reviewed_at_utc='',label='',confidence='',
                    blind_to_model_and_other_review='true'))
        (folder/'INSTRUCTIONS_zhTW.md').write_text('''# 獨立盲審說明

逐筆開啟 `snapshot_file` 指定的歷史 HTML 快照；不要造訪 live phishing URL，也不要查看模型分數、原標籤或另一位 reviewer 的答案。

`label` 僅填 `0`（benign）、`1`（phishing）或 `uncertain`。每筆需填 reviewer ID、UTC 時間、判斷理由，以及兩個實際獨立的 evidence family。相同 feed 的轉載只算一個來源；模型輸出、不在 blocklist、HTTPS 或網站目前已失效均不能單獨定案。

若快照是錯誤頁、停放頁、challenge、內容不足、品牌歸屬或時間證據不清楚，填 `uncertain`。不要為了完成率猜測。Reviewer A 與 B 必須分開作答，完成前不可交換結果。
''')
    (output/'adjudication_template.csv').write_text('review_id,reviewer_id,reviewed_at_utc,final_label,resolved_conflict_ids,rationale\n')
    summary=dict(status='ready_for_two_real_independent_human_reviews',items=len(packets),
                 reviewer_forms=2,completed_human_reviews=0,adjudications=0,
                 packets_sha256=digest(packets_path),
                 independence_requirement='different humans; blind to labels/model/other review',
                 completion_rule='two agreeing supported reviews, or a separate third human adjudicator; uncertain remains quarantined')
    write_json(output/'summary.json',summary);return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--packets',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(run(a.packets,a.output),indent=2))
