"""Phase 7: baselines and first models on the CV folds. Never touches the hold-out."""
import json
import time

import pandas as pd

from carpet import config, evaluate, models, table

EXPERIMENT = "phase7_baselines"
OUT = config.EXPERIMENTS / EXPERIMENT
THRESHOLD_FEATURES = ["dst_entropy_norm", "n_unique_dst"]


def experiments(df: pd.DataFrame) -> dict:
    agg, agg_flow = list(config.FEATURE_SETS["agg"]), list(config.FEATURE_SETS["agg_flow"])
    exp = {"all_negative": (lambda y: models.AllNegative(), agg)}
    for f in THRESHOLD_FEATURES:
        exp[f"threshold_{f}"] = (lambda y: models.SingleFeatureThreshold(0), [f])
    for name, cols in (("agg", agg), ("agg_flow", agg_flow)):
        exp[f"rf_{name}"] = (lambda y: models.random_forest(), cols)
        exp[f"xgb_{name}"] = (lambda y: models.xgboost(evaluate.scale_pos_weight(y)), cols)
    return exp


def main() -> None:
    start = time.time()
    df = table.trainval(table.load_table())
    OUT.mkdir(parents=True, exist_ok=True)
    rows, oofs = [], {}
    for weak in config.WEAK_IN_TRAIN_SETTINGS:
        for name, (factory, cols) in experiments(df).items():
            folds, oof = evaluate.run_cv(df, factory, cols, weak_in_train=weak)
            tag = f"{name}|weak_in_train={weak}"
            rows.append(pd.concat([pd.Series({"experiment": name, "weak_in_train": weak, "n_features": len(cols)}),
                                   evaluate.summarize(folds)]))
            oofs[tag] = (folds, oof)
            print(f"{tag:55s} recall={folds.recall.mean():.3f} precision={folds.precision.mean():.3f} "
                  f"fpr={folds.fpr.mean():.3f} pr_auc={folds.pr_auc.mean():.3f} ({time.time() - start:.0f}s)", flush=True)
    summary = pd.DataFrame(rows)
    summary.to_csv(OUT / "summary.csv", index=False)

    # Leakage alarm: the same pipeline with shuffled train labels must fall to chance.
    alarm = []
    for name in ("rf_agg", "rf_agg_flow", "xgb_agg_flow"):
        factory, cols = experiments(df)[name]
        folds, _ = evaluate.run_cv(df, factory, cols, weak_in_train=True, shuffle_train_labels=True)
        alarm.append({"experiment": name, "roc_auc_mean": folds.roc_auc.mean(), "pr_auc_mean": folds.pr_auc.mean(),
                      "positive_rate": df.label.mean()})
    alarm = pd.DataFrame(alarm)
    alarm.to_csv(OUT / "shuffle_alarm.csv", index=False)
    print("\nshuffle alarm (roc_auc should be near 0.5, pr_auc near the positive rate):\n", alarm.round(3).to_string(index=False))

    for tag in ("rf_agg|weak_in_train=True", "rf_agg_flow|weak_in_train=True", "xgb_agg|weak_in_train=True"):
        folds, oof = oofs[tag]
        stem = tag.split("|")[0]
        folds.to_csv(OUT / f"{stem}_folds.csv", index=False)
        evaluate.per_group(oof).to_csv(OUT / f"{stem}_per_group.csv", index=False)
        evaluate.false_alarm_by_proximity(oof).to_csv(OUT / f"{stem}_false_alarm_by_proximity.csv")
    (OUT / "config.json").write_text(json.dumps({k: config.snapshot()[k] for k in
                                                 ("SEED", "CV_FOLDS", "HOLDOUT_RUNS", "FEATURE_SETS")}, indent=2))
    (OUT / "note.txt").write_text("Phase 7: defaults only, no tuning. Hold-out untouched.\n")
    print(f"done in {time.time() - start:.0f}s -> {OUT}")


if __name__ == "__main__":
    main()
