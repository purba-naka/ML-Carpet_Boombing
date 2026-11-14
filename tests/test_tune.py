import json

import pandas as pd

from carpet import config, tune


def _results(rows):
    return pd.DataFrame([{"setting": i, "params": json.dumps({"n_estimators": c}), "complexity": c,
                          "pr_auc_mean": m, "pr_auc_std": s, "pr_auc_n_folds": 4} for i, (m, s, c) in enumerate(rows)])


def test_sampling_is_reproducible_distinct_and_inside_the_space():
    for model in config.TUNE_SPACE:
        a, b = tune.sample_params(model), tune.sample_params(model)
        assert a == b and len({json.dumps(p, sort_keys=True) for p in a}) == len(a) == config.TUNE_COMBINATIONS
        assert all(v in config.TUNE_SPACE[model][k] for p in a for k, v in p.items())


def test_a_gain_inside_one_standard_error_picks_the_simpler_model():
    # std 0.05 over 4 folds gives a standard error of 0.025: 0.88 is a tie with 0.90, 0.70 is not.
    r = _results([(0.90, 0.05, 5000), (0.88, 0.05, 100), (0.70, 0.05, 50)])
    assert tune.params_of(tune.pick(r)) == {"n_estimators": 100}


def test_a_gain_beyond_one_standard_error_picks_the_better_model():
    # Inside one fold std (0.05) but outside the standard error (0.025): v1 would have called it a tie.
    r = _results([(0.90, 0.05, 5000), (0.86, 0.05, 100)])
    assert tune.params_of(tune.pick(r)) == {"n_estimators": 5000}


def test_rf_space_never_offers_bagging():
    assert 1.0 not in config.TUNE_SPACE["rf"]["max_features"]
