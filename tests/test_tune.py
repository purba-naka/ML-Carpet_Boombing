import json

import pandas as pd

from carpet import config, tune


def _results(rows):
    return pd.DataFrame([{"setting": i, "params": json.dumps({"n_estimators": c}), "complexity": c,
                          "pr_auc_mean": m, "pr_auc_std": s} for i, (m, s, c) in enumerate(rows)])


def test_sampling_is_reproducible_distinct_and_inside_the_space():
    for model in config.TUNE_SPACE:
        a, b = tune.sample_params(model), tune.sample_params(model)
        assert a == b and len({json.dumps(p, sort_keys=True) for p in a}) == len(a) == config.TUNE_COMBINATIONS
        assert all(v in config.TUNE_SPACE[model][k] for p in a for k, v in p.items())


def test_a_gain_inside_fold_noise_picks_the_simpler_model():
    r = _results([(0.90, 0.05, 5000), (0.88, 0.05, 100), (0.70, 0.05, 50)])
    assert tune.params_of(tune.pick(r)) == {"n_estimators": 100}


def test_a_gain_beyond_fold_noise_picks_the_better_model():
    r = _results([(0.95, 0.01, 5000), (0.80, 0.01, 100)])
    assert tune.params_of(tune.pick(r)) == {"n_estimators": 5000}
