"""Phase 8: small randomized search on the CV folds, trainval only. Never touches the hold-out."""
import json
import time

import pandas as pd

from carpet import config, evaluate, models, table, tune

EXPERIMENT = "phase8_tuning"
OUT = config.REPORTS / "experiments" / EXPERIMENT


def main() -> None:
    start = time.time()
    df = table.trainval(table.load_table())
    OUT.mkdir(parents=True, exist_ok=True)
    chosen = {}
    for model in ("rf", "xgb"):
        for set_name, cols in config.FEATURE_SETS.items():
            for weak in (True, False):
                results = tune.search(df, model, list(cols), weak_in_train=weak)
                tag = f"{model}_{set_name}_weak{int(weak)}"
                results.to_csv(OUT / f"search_{tag}.csv", index=False)
                best, picked = results.loc[results.pr_auc_mean.idxmax()], tune.pick(results)
                default_factory = (lambda y: models.random_forest()) if model == "rf" else \
                    (lambda y: models.xgboost(evaluate.scale_pos_weight(y)))
                dfolds, _ = evaluate.run_cv(df, default_factory, list(cols), weak_in_train=weak)
                chosen[tag] = {"params": tune.params_of(picked), "pr_auc_mean": picked.pr_auc_mean,
                               "pr_auc_std": picked.pr_auc_std, "best_pr_auc_mean": best.pr_auc_mean,
                               "default_pr_auc_mean": dfolds.pr_auc.mean(), "default_pr_auc_std": dfolds.pr_auc.std(),
                               "spread_across_settings": results.pr_auc_mean.max() - results.pr_auc_mean.min()}
                c = chosen[tag]
                print(f"{tag:22s} picked {c['pr_auc_mean']:.3f}±{c['pr_auc_std']:.3f}  best {c['best_pr_auc_mean']:.3f}  "
                      f"default {c['default_pr_auc_mean']:.3f}±{c['default_pr_auc_std']:.3f}  "
                      f"range over settings {c['spread_across_settings']:.3f}  ({time.time() - start:.0f}s)", flush=True)
    (OUT / "chosen_params.json").write_text(json.dumps(chosen, indent=2, default=float))
    (OUT / "config.json").write_text(json.dumps({k: config.snapshot()[k] for k in
                                                 ("SEED", "CV_FOLDS", "TUNE_COMBINATIONS", "TUNE_SPACE")}, indent=2))
    (OUT / "note.txt").write_text("Phase 8: 10 settings per model, PR-AUC, ties go to the simplest. Hold-out untouched.\n")
    print(f"done in {time.time() - start:.0f}s -> {OUT}")


if __name__ == "__main__":
    main()
