"""Offline preflight for the frozen final evaluation specification. No test inference."""
import argparse
import hashlib
import json
from pathlib import Path
from .modality_contract import verify_contract, read_protocol, feature_names, make_unfitted_model


def verify_file_hashes(root, mapping):
    root=root.resolve()
    for relative,expected in mapping.items():
        path=(root/relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():raise ValueError('invalid/missing locked file: '+relative)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise ValueError('final freeze hash mismatch: '+relative)


def verify(root):
    lock=read_protocol(root/'config/assignment03_final_evaluation_v1.json')
    if lock['test_execution_authorized'] or lock['test_evaluated']:raise ValueError('specification freeze must keep test sealed')
    verify_file_hashes(root,lock['file_sha256'])
    original=verify_contract(root)
    protocol=read_protocol(root/'config/assignment03_modeling_protocol_v1.json')
    if lock['partition_manifest_sha256']!=original['partition_manifest_sha256'] or lock['definition_lock_sha256']!=original['definition_lock_sha256']:raise ValueError('original lock mismatch')
    if lock['fit_partition']!='train' or lock['refit_train_plus_validation'] or lock['threshold']!=protocol['threshold'] or lock['seed']!=protocol['primary_model_seed']:raise ValueError('frozen fit/seed/threshold mismatch')
    if lock['metrics']!=protocol['metrics'] or lock['uncertainty']!=protocol['uncertainty']:raise ValueError('metric/uncertainty contract changed')
    expected={f'{m}/{mode}/baseline' for m in protocol['models'] for mode in protocol['modalities']}
    if {r['condition'] for r in lock['evaluation_cells']}!=expected or len(lock['evaluation_cells'])!=6:raise ValueError('six prespecified cells required')
    for r in lock['evaluation_cells']:
        model,modality,_=r['condition'].split('/')
        if r['feature_names']!=list(feature_names(modality)) or r['parameters']!=make_unfitted_model(protocol,model,lock['seed']).get_params():raise ValueError('feature/estimator configuration changed')
        if len(r['fitted_model_sha256'])!=64:raise ValueError('missing replay model identity')
    review=read_protocol(root/'results/assignment03/review_v1/review_summary.json')
    independent=read_protocol(root/'results/assignment03/review_v1/independent_verification.json')
    if not independent['verification_passed'] or not review['feature_hashes_match_original'] or review['maximum_score_difference']>1e-12:raise ValueError('review reproduction gate failed')
    if review['test_feature_rows'] or review['test_predictions']:raise ValueError('unexpected test use')
    return dict(status='final_specification_verified_test_sealed',freeze_sha256=hashlib.sha256((root/'config/assignment03_final_evaluation_v1.json').read_bytes()).hexdigest(),locked_files=len(lock['file_sha256']),evaluation_cells=len(lock['evaluation_cells']),fit_rows=protocol['sample_counts']['train'],future_test_rows=protocol['sample_counts']['test'],test_features_read=0,test_predictions=0,test_execution_authorized=False,performance_or_deployment_approval=False)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path('.'));p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=verify(a.root);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
