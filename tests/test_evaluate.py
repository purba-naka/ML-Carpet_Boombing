import numpy as np
import pandas as pd
import pytest

from carpet import config, evaluate, models


def _table(n_folds=3, per_fold=40, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for k in range(n_folds):
        for i in range(per_fold):
            pos = i % 4 == 0
            rows.append(dict(
                subnet="s", w=len(rows) * 60, fold=k, partition="trainval", group=f"G{k}_{i % 5}",
                run_id="C1", subclass="carpet" if pos else "benign", label=int(pos),
                status="ok_weak" if pos and i == 0 else "ok", near_attack=False,
                signal=rng.normal(5 if pos else 0, 1), noise=rng.normal()))
    return pd.DataFrame(rows)


def test_a_clean_signal_beats_chance_and_all_negative_scores_zero_recall():
    df = _table()
    folds, _ = evaluate.run_cv(df, lambda y: models.random_forest(n_estimators=30), ["signal", "noise"], weak_in_train=True)
    assert folds.roc_auc.mean() > 0.95
    base, _ = evaluate.run_cv(df, lambda y: models.AllNegative(), ["signal"], weak_in_train=True)
    assert (base.recall == 0).all() and (base.fpr == 0).all()


def test_shuffled_labels_fall_to_chance():
    df = _table(per_fold=200)
    folds, _ = evaluate.run_cv(df, lambda y: models.random_forest(n_estimators=30), ["signal", "noise"],
                               weak_in_train=True, shuffle_train_labels=True)
    assert 0.35 < folds.roc_auc.mean() < 0.65


def test_weak_windows_leave_training_but_stay_in_test():
    df = _table()
    with_weak, oof = evaluate.run_cv(df, lambda y: models.AllNegative(), ["signal"], weak_in_train=True)
    without, oof2 = evaluate.run_cv(df, lambda y: models.AllNegative(), ["signal"], weak_in_train=False)
    assert (without.n_train < with_weak.n_train).all()
    assert (oof2.status == "ok_weak").sum() == (oof.status == "ok_weak").sum() > 0


def test_forbidden_or_hold_out_input_is_refused():
    df = _table()
    with pytest.raises(ValueError, match="forbidden"):
        evaluate.run_cv(df, lambda y: models.AllNegative(), ["attacker_flows"], weak_in_train=True)
    df.loc[0, "partition"] = "holdout"
    with pytest.raises(ValueError, match="non trainval"):
        evaluate.run_cv(df, lambda y: models.AllNegative(), ["signal"], weak_in_train=True)


def test_threshold_baseline_learns_direction_and_cut_from_train_only():
    x = np.r_[np.zeros(20), np.full(20, 10.0)].reshape(-1, 1)
    y = np.r_[np.zeros(20), np.ones(20)].astype(int)
    assert (models.SingleFeatureThreshold().fit(x, y).predict(x) == y).all()
    assert (models.SingleFeatureThreshold().fit(-x, y).predict(-x) == y).all()


def test_score_marks_undefined_metrics_as_nan_not_zero():
    s = evaluate.score(np.zeros(4), np.full(4, 0.1), np.zeros(4, dtype=int))
    assert np.isnan(s["recall"]) and np.isnan(s["roc_auc"]) and s["fpr"] == 0


def test_accuracy_matches_the_confusion_matrix():
    # The phase 10 RF hold-out: tn 129, fp 1, fn 10, tp 43.
    y = np.r_[np.zeros(130), np.ones(53)].astype(int)
    pred = np.r_[np.zeros(129), np.ones(1), np.zeros(10), np.ones(43)].astype(int)
    s = evaluate.score(y, pred.astype(float), pred)
    assert s["accuracy"] == pytest.approx(172 / 183)


def test_scale_pos_weight_is_negatives_over_positives():
    assert evaluate.scale_pos_weight(pd.Series([0, 0, 0, 1])) == 3.0


def test_group_permutation_finds_the_signal_group_and_ignores_noise():
    df = _table(per_fold=60)
    X, y = df[["signal", "noise"]].to_numpy(), df.label.to_numpy()
    m = models.random_forest(n_estimators=30).fit(X, y)
    out = evaluate.group_permutation(m, X, y, {"signal": [0], "noise": [1]}, n_repeats=3, seed=0).set_index("group")
    assert out.loc["signal", "pr_auc_drop_mean"] > 0.3 > abs(out.loc["noise", "pr_auc_drop_mean"])
