import hashlib
from pathlib import Path
import pytest
from phishing_url.final_evaluation_contract import verify_file_hashes,verify


def test_file_lock_catches_changed_bytes(tmp_path):
    p=tmp_path/'x';p.write_bytes(b'original')
    lock={'x':hashlib.sha256(b'original').hexdigest()}
    verify_file_hashes(tmp_path,lock)
    p.write_bytes(b'changed')
    with pytest.raises(ValueError,match='hash mismatch'):verify_file_hashes(tmp_path,lock)


def test_file_lock_rejects_missing_and_escape(tmp_path):
    with pytest.raises(ValueError,match='invalid/missing'):verify_file_hashes(tmp_path,{'missing':'0'*64})
    with pytest.raises(ValueError,match='invalid/missing'):verify_file_hashes(tmp_path,{'../escape':'0'*64})


def test_frozen_evaluation_has_no_test_inference():
    root=Path(__file__).resolve().parents[1]
    if not (root/'config/assignment03_final_evaluation_v1.json').exists():pytest.skip('freeze created only after review evidence')
    r=verify(root)
    assert r['evaluation_cells']==6 and r['fit_rows']==3461 and r['future_test_rows']==742
    assert r['test_features_read']==r['test_predictions']==0 and not r['test_execution_authorized']
