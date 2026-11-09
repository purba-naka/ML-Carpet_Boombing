"""D21: does cutting long flows over the windows they touch fix the weak windows? CV on trainval only.

Run twice, once per window assignment, with the phase 8 picked params and the same folds seed:
    CARPET_WINDOW_ASSIGNMENT=start  python scripts/run_window_experiment.py
    CARPET_WINDOW_ASSIGNMENT=spread python scripts/run_window_experiment.py
Then `python scripts/run_window_experiment.py --compare`. The hold-out is not read: v1 already burned it,
and this experiment must not turn it into a tuning set.
"""
import json
import sys
import time

import pandas as pd

from carpet import config, evaluate, models, table

NAME = "window_assignment"
CHOSEN = config.REPORTS / "experiments" / "phase8_tuning" / "chosen_params.json"
OUT = config.EXPERIMENTS / NAME
SET = "agg_flow"


def factory(model: str, weak: bool):
    params = json.loads(CHOSEN.read_text())[f"{model}_{SET}_weak{int(weak)}"]["params"]
    if model == "rf":
        return lambda y: models.random_forest(**params)
    return lambda y: models.xgboost(evaluate.scale_pos_weight(y), **params)


def run() -> None:
    start = time.time()
    df = table.trainval(table.load_table())
    OUT.mkdir(parents=True, exist_ok=True)
    cols = list(config.FEATURE_SETS[SET])
    rows, per_status = [], []
    for weak in (True, False):
        for model in ("rf", "xgb"):
            folds, oof = evaluate.run_cv(df, factory(model, weak), cols, weak_in_train=weak)
            rows.append(pd.concat([pd.Series({"assignment": config.WINDOW_ASSIGNMENT, "model": model,
                                              "weak_in_train": weak}), evaluate.summarize(folds)]))
            c = oof[oof.subclass == "carpet"].groupby("status").agg(n=("pred", "size"), flagged=("pred", "sum"))
            c["recall"] = c.flagged / c.n
            per_status.append(c.reset_index().assign(assignment=config.WINDOW_ASSIGNMENT, model=model, weak_in_train=weak))
            print(f"{config.WINDOW_ASSIGNMENT:6s} {model:3s} weak{int(weak)} recall={folds.recall.mean():.3f} "
                  f"precision={folds.precision.mean():.3f} fpr={folds.fpr.mean():.3f} pr_auc={folds.pr_auc.mean():.3f} "
                  f"({time.time() - start:.0f}s)", flush=True)
    pd.DataFrame(rows).to_csv(OUT / "summary.csv", index=False)
    pd.concat(per_status).to_csv(OUT / "recall_by_status.csv", index=False)
    (OUT / "config.json").write_text(json.dumps({k: config.snapshot()[k] for k in
                                                 ("SEED", "CV_FOLDS", "HOLDOUT_RUNS", "WINDOW_ASSIGNMENT")}, indent=2))
    (OUT / "note.txt").write_text(f"D21 window assignment = {config.WINDOW_ASSIGNMENT}. {SET}, phase 8 params, "
                                  "CV on trainval only, hold-out not read.\n")


def compare() -> None:
    root = config.REPORTS
    a = pd.read_csv(root / "experiments" / NAME / "summary.csv")
    b = pd.read_csv(root / "experiments_spread" / NAME / "summary.csv")
    both = pd.concat([a, b])
    cols = ["assignment", "model", "weak_in_train", "recall_mean", "recall_std", "precision_mean", "fpr_mean",
            "pr_auc_mean", "pr_auc_std", "roc_auc_mean"]
    print(both[cols].round(3).to_string(index=False))
    s = pd.concat([pd.read_csv(root / "experiments" / NAME / "recall_by_status.csv"),
                   pd.read_csv(root / "experiments_spread" / NAME / "recall_by_status.csv")])
    print("\ncarpet recall by window status:\n", s.round(3).to_string(index=False))
    both.to_csv(root / "tables" / "window_assignment_comparison.csv", index=False)


if __name__ == "__main__":
    compare() if "--compare" in sys.argv else run()
