"""Machine-readable checks after a fixed baseline experiment; no model reselection."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit
import numpy as np
import pandas as pd
from .experiment import _load, _matrix, _pipeline, _fit, _metrics
from .feature_registry import resolve_feature_set
from .randomness import derive_seed


def run(dataset, development, final, output):
    if output.exists():raise FileExistsError('diagnostic output already exists')
    output.mkdir(parents=True)
    config=json.loads((development/'experiment_config.json').read_text())
    frame=_load(dataset);split=pd.read_csv(development/'split_manifest.csv').set_index('sample_id').split
    assignment=frame.sample_id.map(split);train=assignment=='train';val=assignment=='validation'
    selected=pd.read_csv(development/'selected_hyperparameters.csv');rows=[]
    master=config['seed_plan']['master_seed']
    model_seeds=[derive_seed(master,f'model_sensitivity:{i}') for i in range(5)]
    for _,choice in selected.iterrows():
        names=resolve_feature_set(choice.feature_set);X=_matrix(frame,names)
        for seed in model_seeds:
            pipe=_fit(_pipeline(choice.model,json.loads(choice.parameters),names,seed),X.loc[train],frame.loc[train,'label'])
            rows.append({'feature_set':choice.feature_set,'model':choice.model,'model_seed':seed,
                'partition':'fixed_canonical_validation',**_metrics(frame.loc[val,'label'],pipe.predict_proba(X.loc[val])[:,1])})
    sensitivity=pd.DataFrame(rows);sensitivity.to_csv(output/'model_seed_sensitivity.csv',index=False)
    sensitivity.groupby(['feature_set','model']).f1.agg(['mean','std','min','max']).to_csv(output/'model_seed_summary.csv')
    predictions=pd.read_csv(final/'test_predictions.csv');metrics=pd.read_csv(final/'final_test_metrics.csv')
    checked=[]
    for (fs,model),part in predictions.groupby(['feature_set','model']):
        assert part.sample_id.is_unique and set(part.sample_id)==set(frame.loc[assignment=='test','sample_id'])
        calculated=_metrics(part.label,part.prediction_probability.to_numpy())
        expected=metrics[(metrics.feature_set==fs)&(metrics.model==model)].iloc[0]
        assert all(np.isclose(calculated[k],expected[k]) for k in ('accuracy','precision','recall','f1','fpr','tn','fp','fn','tp'))
        checked.append({'feature_set':fs,'model':model,'rows':len(part),'metrics_recomputed':True})
    info=frame.set_index('sample_id')
    predictions['uses_https']=predictions.sample_id.map(info.url_clean.map(lambda u:urlsplit(u).scheme=='https'))
    predictions['has_query']=predictions.sample_id.map(info.url_clean.map(lambda u:bool(urlsplit(u).query)))
    predictions['inner_page']=predictions.sample_id.map(info.url_clean.map(lambda u:urlsplit(u).path not in ('','/')))
    predictions['correct']=predictions.label==predictions.prediction
    strata=[]
    for key in ('uses_https','has_query','inner_page'):
        for (fs,model,label,value),p in predictions.groupby(['feature_set','model','label',key]):
            strata.append({'feature_set':fs,'model':model,'true_label':label,'stratum':key,'value':bool(value),
                           'rows':len(p),'errors':int((~p.correct).sum()),'error_rate':float((~p.correct).mean())})
    pd.DataFrame(strata).to_csv(output/'error_strata.csv',index=False)
    errors=predictions[~predictions.correct]
    errors.groupby(['feature_set','model','label','domain_group']).size().rename('error_count').sort_values(ascending=False).to_csv(output/'error_domain_counts.csv')
    examples=errors[errors.feature_set=='baseline'].sort_values(['model','label','prediction_probability'])
    examples.groupby(['model','label']).head(5).to_csv(output/'baseline_error_review_ids.csv',index=False)
    importance=pd.read_csv(final/'feature_importance.csv')
    importance[(importance.feature_set=='baseline')&(importance.method=='validation_permutation')].sort_values(['model','importance'],ascending=[True,False]).groupby('model').head(5).to_csv(output/'baseline_top_validation_importance.csv',index=False)
    (output/'verification.json').write_text(json.dumps({'planned_comparisons_verified':checked,
        'all_metrics_recomputed':True,'model_seed_sensitivity_uses_test':False,
        'model_reselection_performed':False,'fixed_model_seeds':model_seeds,
        'limitations':['LR default lbfgs is deterministic; changing random_state need not change results.','Five seed runs characterize this split procedure, not independent population samples.','Feature importance is associational and sensitive to correlated features.','Test error strata are descriptive and will not be used to retune this frozen experiment.']},indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('dataset','development','final','output'):p.add_argument('--'+arg,type=Path,required=True)
    a=p.parse_args();run(a.dataset,a.development,a.final,a.output)


if __name__=='__main__':main()
