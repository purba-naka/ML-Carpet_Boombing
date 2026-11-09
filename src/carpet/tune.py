"""Small randomized search on the CV folds. Picks the simplest setting when scores tie."""
import json

import pandas as pd
from sklearn.model_selection import ParameterSampler

from carpet import config, evaluate, models

SCORE = "pr_auc"


def sample_params(model: str, n: int = config.TUNE_COMBINATIONS) -> list[dict]:
    """n distinct settings, always the same for a given seed."""
    space = config.TUNE_SPACE[model]
    return list(ParameterSampler(space, n_iter=n, random_state=config.SEED))


def complexity(model: str, params: dict) -> float:
    """Rough size of the model: more trees and deeper trees mean more complex. Used only to break ties."""
    depth = params.get("max_depth") or 30
    return params["n_estimators"] * depth


def search(df: pd.DataFrame, model: str, features: list[str], *, weak_in_train: bool) -> pd.DataFrame:
    """One row per setting: mean and std of every metric over the folds."""
    factory = {"rf": lambda params, y: models.random_forest(**params),
               "xgb": lambda params, y: models.xgboost(evaluate.scale_pos_weight(y), **params)}[model]
    rows = []
    for i, params in enumerate(sample_params(model)):
        folds, _ = evaluate.run_cv(df, lambda y: factory(params, y), features, weak_in_train=weak_in_train)
        rows.append({"setting": i, "params": json.dumps(params), "complexity": complexity(model, params),
                     **evaluate.summarize(folds).to_dict()})
    return pd.DataFrame(rows)


def pick(results: pd.DataFrame) -> pd.Series:
    """Best mean score, unless another setting is inside one fold std of it: then the simplest of those wins.

    Fold std is the honest noise level here (5 folds of 2 to 4 runs). A gain below it is not a gain.
    """
    best = results[f"{SCORE}_mean"].idxmax()
    noise = results.loc[best, f"{SCORE}_std"]
    close = results[results[f"{SCORE}_mean"] >= results.loc[best, f"{SCORE}_mean"] - noise]
    return results.loc[close.complexity.idxmin()]


def params_of(row: pd.Series) -> dict:
    return json.loads(row["params"])
