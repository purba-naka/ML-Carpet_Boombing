"""Phase 9: ablation. Feature group removals and the D19 artifact columns added back, phase 8 picked params.

Hold-out untouched, as always.
"""
import json
import time

import pandas as pd

from carpet import config, evaluate, models, table

EXPERIMENT = "phase9_ablation"
OUT = config.REPORTS / "experiments" / EXPERIMENT
CHOSEN = config.REPORTS / "experiments" / "phase8_tuning" / "chosen_params.json"
SETS = ("agg", "agg_flow", "agg_flow_no_src", "agg_flow_no_udp", "agg_flow_no_volume",
        "agg_flow_dst_only", "agg_flow_artifact")


def factory(model: str, set_name: str, weak: bool):
    """Phase 8 params of the base set. Every ablation set is agg_flow minus a feature group,
    so it borrows the agg_flow params; only the agg row borrows the agg params."""
    base = "agg" if set_name == "agg" else "agg_flow"
    params = json.loads(CHOSEN.read_text())[f"{model}_{base}_weak{int(weak)}"]["params"]
    if model == "rf":
        return lambda y: models.random_forest(**params)
    return lambda y: models.xgboost(evaluate.scale_pos_weight(y), **params)


def main() -> None:
    start = time.time()
    df = table.trainval(table.load_table())
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for weak in (True, False):
        for set_name in SETS:
            cols = list(config.FEATURE_SETS[set_name])
            for model in ("rf", "xgb"):
                folds, _ = evaluate.run_cv(df, factory(model, set_name, weak), cols, weak_in_train=weak)
                rows.append(pd.concat([pd.Series({"set": set_name, "model": model,
                                                  "weak_in_train": weak, "n_features": len(cols)}),
                                       evaluate.summarize(folds)]))
                print(f"{set_name:18s} {model:3s} weak{int(weak)} recall={folds.recall.mean():.3f} "
                      f"precision={folds.precision.mean():.3f} fpr={folds.fpr.mean():.3f} "
                      f"pr_auc={folds.pr_auc.mean():.3f} ({time.time() - start:.0f}s)", flush=True)
    summary = pd.DataFrame(rows)
    summary.to_csv(OUT / "summary.csv", index=False)
    summary.to_csv(config.TABLES / "ablation.csv", index=False)
    (OUT / "config.json").write_text(json.dumps({k: config.snapshot()[k] for k in
                                                 ("SEED", "CV_FOLDS", "HOLDOUT_RUNS", "FEATURE_SETS",
                                                  "ARTIFACT_FLOW_COLUMNS")}, indent=2))
    (OUT / "note.txt").write_text("Phase 9 ablation: agg_flow with feature groups removed one at a time, plus the "
                                 "D19 artifact columns (Bwd, TCP flag) added back. Phase 8 picked params, both "
                                 "weak settings. Hold-out untouched.\n")
    print(f"done in {time.time() - start:.0f}s -> {OUT / 'summary.csv'} and reports/tables/ablation.csv")


if __name__ == "__main__":
    main()
