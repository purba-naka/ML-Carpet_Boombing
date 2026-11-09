"""EDA helpers. Everything here sees trainval only, the hold-out is cut off at load time."""
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from carpet import table

def load_trainval() -> pd.DataFrame:
    """Usable trainval windows with labels, features and fold. The only door EDA uses."""
    return table.trainval(table.load_table())


def single_feature_auc(df: pd.DataFrame, cols: list[str], positive: str, negatives: list[str]) -> pd.Series:
    """ROC-AUC of each feature alone, `positive` subclass vs the `negatives`. 0.5 is chance.

    Sign is folded (max of auc, 1 - auc), because a low value can separate as well as a high one.
    """
    d = df[df.subclass.isin([positive, *negatives])]
    y = (d.subclass == positive).astype(int)
    auc = pd.Series({c: roc_auc_score(y, d[c]) for c in cols})
    return np.maximum(auc, 1 - auc).sort_values(ascending=False)


def effect_size(df: pd.DataFrame, cols: list[str], a: str, b: str) -> pd.Series:
    """Cohen's d between subclass a and b, on log1p scale because counts here span 5 orders of magnitude."""
    x, y = df[df.subclass == a], df[df.subclass == b]
    out = {}
    for c in cols:
        u, v = np.log1p(x[c].clip(lower=0)), np.log1p(y[c].clip(lower=0))
        pooled = np.sqrt((u.var() + v.var()) / 2)
        out[c] = (u.mean() - v.mean()) / pooled if pooled > 0 else 0.0
    return pd.Series(out).abs().sort_values(ascending=False)


def high_correlation_pairs(df: pd.DataFrame, cols: list[str], threshold: float = 0.95) -> pd.DataFrame:
    corr = df[cols].corr(method="spearman")
    pairs = [(a, b, corr.loc[a, b]) for i, a in enumerate(cols) for b in cols[i + 1:] if abs(corr.loc[a, b]) >= threshold]
    return pd.DataFrame(pairs, columns=["a", "b", "spearman"]).sort_values("spearman", key=abs, ascending=False)
