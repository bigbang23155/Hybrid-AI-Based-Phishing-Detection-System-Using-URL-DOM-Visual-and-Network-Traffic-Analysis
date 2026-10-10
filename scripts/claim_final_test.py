"""Atomically consume the v1 test authorization in a persistent GitHub ref.

A pre-existing ref is a hard stop, including after a failed/partial run.
This script never deletes or moves the claim and never reuses an old claim.
"""
import hashlib
import json
import os
from pathlib import Path
import urllib.request
from phishing_url.final_test import validate_execution, exclusive_json

root=Path('.')
lock,cfg=validate_execution(root)
public=Path(os.environ['FINAL_OUTPUT'])/'public'
ready_path=public/'ready.json';ready=json.loads(ready_path.read_text())
commit=os.environ['EXECUTION_COMMIT'];run_id=os.environ['EVALUATION_RUN_ID']
if os.environ['GITHUB_RUN_ATTEMPT']!='1':raise RuntimeError('automatic reruns are forbidden')
if ready['execution_commit']!=commit or str(ready['run_id'])!=run_id or len(ready['models'])!=6:
    raise RuntimeError('preparation mismatch')
if any(r['maximum_score_difference']>1e-12 for r in ready['models']):raise RuntimeError('reproduction failed')
for cell,row in zip(lock['evaluation_cells'],ready['models'],strict=True):
    if row['condition']!=cell['condition'] or row['model_sha256']!=cell['fitted_model_sha256']:
        raise RuntimeError('prepared model identity mismatch')
headers={'Authorization':'Bearer '+os.environ['GITHUB_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
api='https://api.github.com/repos/'+os.environ['GITHUB_REPOSITORY']+'/git/refs'
request=urllib.request.Request(api,data=json.dumps({'ref':cfg['persistent_claim_ref'],'sha':commit}).encode(),headers=headers,method='POST')
# GitHub's create-ref operation is atomic and fails if already present.
with urllib.request.urlopen(request,timeout=60) as response:
    if response.status!=201:raise RuntimeError('claim not newly created')
    result=json.load(response)
receipt={'ref':result['ref'],'object':{'sha':result['object']['sha']},'run_id':run_id,
         'run_attempt':os.environ['GITHUB_RUN_ATTEMPT'],'ready_sha256':hashlib.sha256(ready_path.read_bytes()).hexdigest()}
exclusive_json(public/'persistent_claim.json',receipt)
print(json.dumps(receipt,indent=2))
