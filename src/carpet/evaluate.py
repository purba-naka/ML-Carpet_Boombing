"""Metrics and the one cross validation loop every experiment goes through."""
import time
from collections.abc import Callable

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score

from carpet import config
from carpet.config import Status

# Accuracy is last on purpose: the PDF lists it, but on 20 percent positives it flatters any model.
METRICS = ["recall", "precision", "f1", "fpr", "pr_auc", "roc_auc", "accuracy"]
POS = 1

# A model factory gets the training labels and returns an unfitted estimator.
ModelFactory = Callable[[pd.Series], object]


def scale_pos_weight(y: pd.Series) -> float:
    return float((y == 0).sum() / max((y == 1).sum(), 1))


def score(y: np.ndarray, proba: np.ndarray, pred: np.ndarray) -> dict:
    """Positive class is carpet bombing. AUCs need both classes, otherwise NaN instead of a made up number."""
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    both = len(np.unique(y)) == 2
    return {
        "recall": tp / (tp + fn) if tp + fn else np.nan,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "f1": 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else np.nan,
        "fpr": fp / (fp + tn) if fp + tn else np.nan,
        "pr_auc": average_precision_score(y, proba) if both else np.nan,
        "roc_auc": roc_auc_score(y, proba) if both else np.nan,
        "accuracy": (tp + tn) / len(y) if len(y) else np.nan,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def run_cv(df: pd.DataFrame, make_model: ModelFactory, features: list[str], *, weak_in_train: bool,
           shuffle_train_labels: bool = False) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Group CV over trainval. Returns (per fold metrics, out of fold predictions).

    `df` must be trainval only (table.trainval). Test side of each fold always keeps the weak
    windows, so recall stays honest. Only the training side may drop them.
    `shuffle_train_labels` is the leakage alarm: labels are shuffled on the train side, so a
    working pipeline must fall to chance. If it does not, something besides the label leaks in.
    """
    if (df.partition != "trainval").any():
        raise ValueError("run_cv got non trainval rows")
    forbidden = set(features) & config.FORBIDDEN_FEATURES
    if forbidden:
        raise ValueError(f"forbidden features requested: {sorted(forbidden)}")
    folds, oof = [], []
    for k in sorted(df.fold.unique()):
        test = df[df.fold == k]
        train = df[df.fold != k]
        if not weak_in_train:
            train = train[train.status != Status.OK_WEAK]
        y_train = train.label.to_numpy()
        if shuffle_train_labels:
            y_train = np.random.default_rng(config.SEED + int(k)).permutation(y_train)
        model = make_model(pd.Series(y_train))
        model.fit(train[features].to_numpy(), y_train)
        t0 = time.perf_counter()
        proba = model.predict_proba(test[features].to_numpy())[:, POS]
        pred = model.predict(test[features].to_numpy())
        ms = (time.perf_counter() - t0) / len(test) * 1000
        folds.append({"fold": int(k), "n_train": len(train), "n_test": len(test),
                      "n_test_pos": int(test.label.sum()), "ms_per_window": ms,
                      **score(test.label.to_numpy(), proba, pred)})
        oof.append(test[["subnet", "w", "group", "run_id", "subclass", "status", "near_attack", "label"]]
                   .assign(fold=int(k), proba=proba, pred=pred))
    return pd.DataFrame(folds), pd.concat(oof, ignore_index=True)


def summarize(folds: pd.DataFrame) -> pd.Series:
    """Mean and standard deviation over folds. NaN folds are skipped, and the count is kept visible."""
    out = {}
    for m in METRICS:
        out[f"{m}_mean"] = folds[m].mean()
        out[f"{m}_std"] = folds[m].std()
        out[f"{m}_n_folds"] = int(folds[m].notna().sum())
    return pd.Series(out)


def per_group(oof: pd.DataFrame) -> pd.DataFrame:
    """Share of windows flagged, per run (carpet runs: recall, other runs: false alarm rate)."""
    g = oof.groupby(["group", "subclass"], observed=True).agg(
        n=("pred", "size"), flagged=("pred", "sum"), mean_proba=("proba", "mean"))
    g["flagged_share"] = g.flagged / g.n
    return g.reset_index().sort_values(["subclass", "group"])


def false_alarm_by_proximity(oof: pd.DataFrame) -> pd.DataFrame:
    """False positive rate on benign windows, near vs far from an attack (D18)."""
    b = oof[oof.subclass == "benign"]
    g = b.groupby("near_attack").agg(n=("pred", "size"), false_alarms=("pred", "sum"))
    g["fpr"] = g.false_alarms / g.n
    return g


def group_permutation(model, X: np.ndarray, y: np.ndarray, groups: dict[str, list[int]], *,
                      n_repeats: int, seed: int) -> pd.DataFrame:
    """PR-AUC drop when all columns of a group are shuffled together, one row per group.

    Shuffling correlated columns one at a time hides them: the twin column still carries the
    signal. Moving the whole group with one row permutation removes it for real.
    """
    rng = np.random.default_rng(seed)
    base = average_precision_score(y, model.predict_proba(X)[:, POS])
    rows = []
    for name, idx in groups.items():
        drops = []
        for _ in range(n_repeats):
            Xp = X.copy()
            Xp[:, idx] = X[rng.permutation(len(X))][:, idx]
            drops.append(base - average_precision_score(y, model.predict_proba(Xp)[:, POS]))
        rows.append({"group": name, "pr_auc_drop_mean": float(np.mean(drops)), "pr_auc_drop_std": float(np.std(drops))})
    return pd.DataFrame(rows)


def bootstrap_runs(res: pd.DataFrame, n_boot: int, rng: np.random.Generator) -> dict:
    """Quantiles of every metric when runs (groups) are resampled with replacement, never single windows.

    A run is the unit the model has never seen, so the uncertainty it carries is what the numbers
    should show. `res` needs group, label, proba and pred.
    """
    groups = res.group.unique()
    by_group = {g: part for g, part in res.groupby("group")}
    draws = []
    for _ in range(n_boot):
        parts = pd.concat([by_group[g] for g in rng.choice(groups, size=len(groups), replace=True)])
        draws.append(score(parts.label.to_numpy(), parts.proba.to_numpy(), parts.pred.to_numpy()))
    b = pd.DataFrame(draws)
    return {"n_runs": len(groups)} | {f"{c}_{q}": b[c].quantile(q_)
            for c in METRICS for q, q_ in (("q025", 0.025), ("q50", 0.5), ("q975", 0.975))}
