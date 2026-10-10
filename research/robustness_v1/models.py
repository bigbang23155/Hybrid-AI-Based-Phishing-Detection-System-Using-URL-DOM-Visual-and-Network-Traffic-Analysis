"""Bounded general-purpose model candidates; every preprocessing fit stays in training."""
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import (RandomForestClassifier, ExtraTreesClassifier,
                             GradientBoostingClassifier, HistGradientBoostingClassifier)
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

MODELS = ('logistic_regression', 'random_forest', 'extra_trees', 'gradient_boosting',
          'hist_gradient_boosting', 'rbf_svm')


def make_model(name, variant, seed, calibration_splits=None):
    if name not in MODELS or variant not in (0, 1):
        raise ValueError('unknown candidate')
    if name == 'logistic_regression':
        return make_pipeline(StandardScaler(), LogisticRegression(C=(.1, 1.)[variant], max_iter=2000, random_state=seed))
    if name in ('random_forest', 'extra_trees'):
        cls = RandomForestClassifier if name == 'random_forest' else ExtraTreesClassifier
        return cls(n_estimators=100, min_samples_leaf=(1, 5)[variant], max_features='sqrt', random_state=seed, n_jobs=1)
    if name == 'gradient_boosting':
        return GradientBoostingClassifier(n_estimators=100, learning_rate=.1, max_depth=(2, 3)[variant], random_state=seed)
    if name == 'hist_gradient_boosting':
        # No hidden row-wise early-stopping split across domain groups.
        return HistGradientBoostingClassifier(max_iter=100, max_leaf_nodes=(15, 31)[variant], early_stopping=False, random_state=seed)
    if not calibration_splits:
        raise ValueError('SVM probabilities require explicit training-group calibration folds')
    base = make_pipeline(StandardScaler(), SVC(C=(.1, 1.)[variant], kernel='rbf', gamma='scale', probability=False, random_state=seed))
    return CalibratedClassifierCV(base, method='sigmoid', cv=calibration_splits, ensemble=True)
