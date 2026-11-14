"""Phase 9: ablation. Feature group removals and the D19 artifact columns added back, phase 8 picked params.

Hold-out untouched, as always.
"""
import json
import time

import pandas as pd

from carpet import config, evaluate, models, table

EXPERIMENT = "phase9_ablation"
OUT = config.EXPERIMENTS / EXPERIMENT
CHOSEN = config.EXPERIMENTS / "phase8_tuning" / "chosen_params.json"
SETS = ("agg", "flow", "agg_flow", "agg_flow_no_src", "agg_flow_no_udp", "agg_flow_no_volume",
        "agg_flow_dst_only", "agg_flow_no_dst_count", "agg_flow_no_dst_count_no_volume",
        "agg_flow_no_entropy", "agg_flow_no_dst_spread", "agg_flow_artifact")


def factory(model: str, set_name: str, weak: bool):
    """Phase 8 params of the base set. Every ablation set is agg_flow minus a feature group,
    so it borrows the agg_flow params; only the agg row borrows the agg params."""
    base = "agg" if set_name == "agg" else "agg_flow"
    params = json.loads(CHOSEN.read_text())[f"{model}_{base}_weak{int(weak)}"]["params"]
    # The flow-only set is not agg_flow minus a group, it is the conventional baseline of the thesis
    # question, so it gets the defaults rather than params tuned with the aggregates present.
    if set_name == "flow":
        params = {}
    if model == "rf":
        return lambda y: models.random_forest(**params)
    return lambda y: models.xgboost(evaluate.scale_pos_weight(y), **params)


def main() -> None:
    start = time.time()
    df = table.trainval(table.load_table())
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for weak in config.WEAK_IN_TRAIN_SETTINGS:
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
    ref = summary[summary.set == "agg_flow"].set_index(["model", "weak_in_train"])
    for m in ("recall", "pr_auc", "fpr"):
        summary[f"{m}_minus_agg_flow"] = summary[f"{m}_mean"] - [ref.loc[(r.model, r.weak_in_train), f"{m}_mean"]
                                                                 for r in summary.itertuples()]
    summary.to_csv(OUT / "summary.csv", index=False)
    summary.to_csv(config.TABLES / "ablation.csv", index=False)
    (OUT / "config.json").write_text(json.dumps({k: config.snapshot()[k] for k in
                                                 ("SEED", "CV_FOLDS", "WINDOW_ASSIGNMENT", "HOLDOUT_RUNS", "FEATURE_SETS",
                                                  "FEATURE_GROUPS", "ARTIFACT_FLOW_COLUMNS")}, indent=2))
    (OUT / "note.txt").write_text("Phase 9 ablation: agg_flow with feature groups removed one at a time, plus the "
                                 "D19 artifact columns (Bwd, TCP flag) added back, the PDF 3.2.2.4 removals "
                                 "(destination count, volume), entropy removed, and flow features alone (defaults). "
                                 "Phase 8 picked params otherwise. Hold-out untouched.\n")
    print(f"done in {time.time() - start:.0f}s -> {OUT / 'summary.csv'} and {config.TABLES / 'ablation.csv'}")


if __name__ == "__main__":
    main()
