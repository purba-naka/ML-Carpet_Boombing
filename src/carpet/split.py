"""Hold-out and CV folds. Always by group, because neighbour windows of one run are near twins."""
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from carpet import config
from carpet.config import Subclass

HOLDOUT = "holdout"
TRAINVAL = "trainval"
NO_FOLD = -1


def holdout_groups(windows: pd.DataFrame) -> set[str]:
    """The fixed hold-out runs plus a seeded share of benign blocks."""
    missing = set(config.HOLDOUT_RUNS) - set(windows.group)
    if missing:
        raise ValueError(f"hold-out runs not among usable windows: {sorted(missing)}")
    benign = np.sort(windows.loc[windows.subclass == Subclass.BENIGN, "group"].unique())
    n = round(len(benign) * config.HOLDOUT_BENIGN_FRACTION)
    picked = np.random.default_rng(config.SEED).choice(benign, size=n, replace=False)
    return set(config.HOLDOUT_RUNS) | set(picked)


def make_split(windows: pd.DataFrame) -> pd.DataFrame:
    """Usable windows to (subnet, w, partition, fold). Fold is NO_FOLD for the hold-out."""
    usable = windows[windows.status.isin(list(config.USABLE_STATUSES))].reset_index(drop=True)
    held = usable.group.isin(holdout_groups(usable)).to_numpy()
    fold = np.full(len(usable), NO_FOLD)
    tv = np.flatnonzero(~held)
    cv = StratifiedGroupKFold(n_splits=config.CV_FOLDS, shuffle=True, random_state=config.SEED)
    # Stratify by subclass, not label: with label only, one fold got no focused window at all,
    # and telling carpet from focused is the point of the thesis.
    for k, (_, test) in enumerate(cv.split(tv, usable.subclass.iloc[tv], usable.group.iloc[tv])):
        fold[tv[test]] = k
    return pd.DataFrame({"subnet": usable.subnet, "w": usable.w,
                         "partition": np.where(held, HOLDOUT, TRAINVAL), "fold": fold})


def check_split(split: pd.DataFrame, windows: pd.DataFrame) -> None:
    """Every group sits in exactly one bucket. Every bucket has both classes, and every CV fold has each subclass."""
    s = split.merge(windows[["subnet", "w", "group", "label"]], on=["subnet", "w"], validate="1:1")
    bucket = s.fold.astype(str).where(s.partition == TRAINVAL, HOLDOUT)
    problems = []
    spread = s.assign(bucket=bucket).groupby("group").bucket.nunique()
    if (spread > 1).any():
        problems.append(f"groups in more than one bucket: {spread[spread > 1].index.tolist()}")
    sub = windows[["subnet", "w", "subclass"]]
    s = s.merge(sub, on=["subnet", "w"], validate="1:1")
    missing = s[s.partition == TRAINVAL].groupby("fold").subclass.nunique()
    if (missing < s.subclass.nunique()).any():
        problems.append(f"CV folds missing a subclass: {missing[missing < s.subclass.nunique()].index.tolist()}")
    one_class = s.groupby(bucket).label.nunique()
    if (one_class < 2).any():
        problems.append(f"buckets with one class only: {one_class[one_class < 2].index.tolist()}")
    if problems:
        raise ValueError("split broken:\n  " + "\n  ".join(problems))
