"""Model factories. Each returns an unfitted sklearn estimator, so fitting only ever happens inside a CV fold."""
import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from xgboost import XGBClassifier

from carpet import config


class AllNegative(ClassifierMixin, BaseEstimator):
    """Baseline A: never predicts an attack. Any real model has to beat its recall of 0."""

    def fit(self, X, y):
        self.classes_ = np.array([0, 1])
        return self

    def predict_proba(self, X):
        return np.tile([1.0, 0.0], (len(X), 1))

    def predict(self, X):
        return np.zeros(len(X), dtype=int)


class SingleFeatureThreshold(ClassifierMixin, BaseEstimator):
    """Baseline B: one feature and one cut, the cut chosen on the training rows only.

    The cut is the value that gives the best F1 on the training rows. Direction (high or low
    means attack) is picked by the same rule, so the baseline gets a fair chance.
    """

    def __init__(self, feature_index: int = 0):
        self.feature_index = feature_index

    def fit(self, X, y):
        x = np.asarray(X)[:, self.feature_index]
        y = np.asarray(y)
        best = (-1.0, 0.0, 1)
        for sign in (1, -1):
            for cut in np.unique(x):
                pred = sign * x >= sign * cut
                tp = int((pred & (y == 1)).sum())
                f1 = 2 * tp / max(int(pred.sum()) + int((y == 1).sum()), 1)
                if f1 > best[0]:
                    best = (f1, cut, sign)
        _, self.cut_, self.sign_ = best
        self.classes_ = np.array([0, 1])
        return self

    def _score(self, X):
        # Signed distance to the cut, squashed to 0..1, so ROC and PR curves work on the baseline too.
        d = self.sign_ * (np.asarray(X)[:, self.feature_index] - self.cut_)
        return 1 / (1 + np.exp(-np.clip(d / (np.abs(self.cut_) + 1e-9), -30, 30)))

    def predict_proba(self, X):
        p = self._score(X)
        return np.column_stack([1 - p, p])

    def predict(self, X):
        return (self.sign_ * (np.asarray(X)[:, self.feature_index] - self.cut_) >= 0).astype(int)


def random_forest(**params):
    """Random Forest. Median imputer sits inside the pipeline, so it learns from train rows only."""
    base = dict(n_estimators=300, class_weight="balanced", random_state=config.SEED, n_jobs=-1)
    return make_pipeline(SimpleImputer(strategy="median"), RandomForestClassifier(**{**base, **params}))


def xgboost(scale_pos_weight: float, **params):
    """XGBoost. scale_pos_weight is negatives over positives of the TRAIN fold, so the caller passes it."""
    base = dict(n_estimators=300, learning_rate=0.1, max_depth=4, subsample=0.9, colsample_bytree=0.9,
                scale_pos_weight=scale_pos_weight, random_state=config.SEED, n_jobs=-1,
                eval_metric="logloss", tree_method="hist")
    return make_pipeline(SimpleImputer(strategy="median"), XGBClassifier(**{**base, **params}))
