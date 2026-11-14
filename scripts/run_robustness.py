"""Phase 9: robustness. Feature importance, seed stability, cluster bootstrap over runs, per scenario recall.

Everything runs on trainval only, with the phase 8 picked params on agg_flow. Hold-out untouched.
"""
import json
import time

import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance

from carpet import config, evaluate, io, models, table

EXPERIMENT = "phase9_robustness"
OUT = config.EXPERIMENTS / EXPERIMENT
CHOSEN = config.EXPERIMENTS / "phase8_tuning" / "chosen_params.json"
SEEDS = [config.SEED + i for i in range(5)]
N_BOOT = 1000
N_PERM = 20


def picked(model: str, weak: bool) -> dict:
    return json.loads(CHOSEN.read_text())[f"{model}_agg_flow_weak{int(weak)}"]["params"]


def make_model(model: str, weak: bool, seed: int):
    params = picked(model, weak)
    if model == "rf":
        return lambda y: models.random_forest(**params, random_state=seed)
    return lambda y: models.xgboost(evaluate.scale_pos_weight(y), **params, random_state=seed)


def importance(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Per feature and per group importance, every fold as judge in turn (PL-5).

    The model trains on the other four folds. Permutation on training rows would flatter the features,
    and one judge fold (v1 used fold 0 only) is a single small sample of 2 to 4 runs.
    Returns (per feature, per group), each with the mean and std over folds.
    """
    cols = list(config.FEATURE_SETS["agg_flow"])
    groups = {g: [cols.index(f) for f in fs] for g, fs in config.FEATURE_GROUPS.items()}
    feat_rows, group_rows = [], []
    for k in sorted(df.fold.unique()):
        train, valid = df[df.fold != k], df[df.fold == k]
        Xt, yt, Xv, yv = train[cols].to_numpy(), train.label.to_numpy(), valid[cols].to_numpy(), valid.label.to_numpy()
        rf = models.random_forest(**picked("rf", True)).fit(Xt, yt)
        xgb = models.xgboost(evaluate.scale_pos_weight(train.label), **picked("xgb", True)).fit(Xt, yt)
        impurity = rf.named_steps["randomforestclassifier"].feature_importances_
        gain = xgb.named_steps["xgbclassifier"].get_booster().get_score(importance_type="gain")
        gain = pd.Series({cols[int(c[1:])]: v for c, v in gain.items()}).reindex(cols).fillna(0.0)
        for name, m in (("rf", rf), ("xgb", xgb)):
            perm = permutation_importance(m, Xv, yv, scoring="average_precision", n_repeats=N_PERM,
                                          random_state=config.SEED)
            feat_rows.append(pd.DataFrame({"fold": int(k), "model": name, "feature": cols,
                                           "permutation_pr_auc_drop": perm.importances_mean,
                                           "native": impurity / impurity.sum() if name == "rf" else
                                           (gain / gain.sum()).to_numpy()}))
            g = evaluate.group_permutation(m, Xv, yv, groups, n_repeats=N_PERM, seed=config.SEED + int(k))
            group_rows.append(g.assign(fold=int(k), model=name))
        print(f"importance fold {k} done", flush=True)
    feat = (pd.concat(feat_rows).groupby(["model", "feature"])
            .agg(native_mean=("native", "mean"), native_std=("native", "std"),
                 permutation_mean=("permutation_pr_auc_drop", "mean"), permutation_std=("permutation_pr_auc_drop", "std"))
            .reset_index().sort_values(["model", "native_mean"], ascending=[True, False]))
    grp = (pd.concat(group_rows).groupby(["model", "group"])
           .agg(pr_auc_drop_mean=("pr_auc_drop_mean", "mean"), pr_auc_drop_std_over_folds=("pr_auc_drop_mean", "std"))
           .reset_index().sort_values(["model", "pr_auc_drop_mean"], ascending=[True, False]))
    return feat, grp


def seed_stability(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Same data, same folds, only the model seed moves. Returns per seed means, the spread,
    and the out of fold predictions of the base seed for the bootstrap and the scenario cuts."""
    cols = list(config.FEATURE_SETS["agg_flow"])
    rows, keep = [], {}
    for weak in config.WEAK_IN_TRAIN_SETTINGS:
        for model in ("rf", "xgb"):
            for seed in SEEDS:
                folds, oof = evaluate.run_cv(df, make_model(model, weak, seed), cols, weak_in_train=weak)
                rows.append(pd.concat([pd.Series({"model": model, "weak_in_train": weak, "seed": seed}),
                                       evaluate.summarize(folds)]))
                if seed == config.SEED:
                    keep[(model, weak)] = oof
    seeds = pd.DataFrame(rows)
    spread = (seeds.groupby(["model", "weak_in_train"])
              .agg(recall_min=("recall_mean", "min"), recall_max=("recall_mean", "max"),
                   pr_auc_min=("pr_auc_mean", "min"), pr_auc_max=("pr_auc_mean", "max")))
    return seeds, spread, keep


def per_scenario(oof: pd.DataFrame) -> pd.DataFrame:
    """Carpet recall by attack scenario, source count, and window status (ok vs weak)."""
    log = io.read_attack_log().set_index("run_id")
    carpet = oof[oof.subclass == "carpet"].assign(scenario=oof.run_id.map(log.scenario),
                                                  n_src=oof.run_id.map(log.n_src))
    rows = []
    for cut in ("scenario", "n_src", "status"):
        g = carpet.groupby(cut).agg(n=("pred", "size"), flagged=("pred", "sum"))
        g["recall"] = g.flagged / g.n
        g = g.reset_index().rename(columns={cut: "cut_value"})
        g.insert(0, "cut", cut)
        rows.append(g[["cut", "cut_value", "n", "recall"]])
    return pd.concat(rows, ignore_index=True)


def main() -> None:
    start = time.time()
    df = table.trainval(table.load_table())
    OUT.mkdir(parents=True, exist_ok=True)

    imp, imp_groups = importance(df)
    imp.to_csv(OUT / "importance.csv", index=False)
    imp_groups.to_csv(OUT / "importance_groups.csv", index=False)
    print("top features (native importance, mean over folds):\n",
          imp.groupby("model").head(8).round(3).to_string(index=False))
    print("groups (PR-AUC drop when shuffled together):\n", imp_groups.round(3).to_string(index=False),
          f"\n({time.time() - start:.0f}s)\n")

    seeds, spread, keep = seed_stability(df)
    seeds.to_csv(OUT / "seed_stability.csv", index=False)
    spread.to_csv(OUT / "seed_spread.csv")
    print("seed spread (min..max over 5 seeds):\n", spread.round(3).to_string(), f"\n({time.time() - start:.0f}s)\n")

    boot, scen = [], []
    rng = np.random.default_rng(config.SEED)
    for (model, weak), oof in keep.items():
        boot.append({"model": model, "weak_in_train": weak, **evaluate.bootstrap_runs(oof, N_BOOT, rng)})
        s = per_scenario(oof)
        s.insert(0, "weak_in_train", weak)
        s.insert(0, "model", model)
        scen.append(s)
        print(f"bootstrap {model} weak{int(weak)} ({time.time() - start:.0f}s)", flush=True)
    pd.DataFrame(boot).to_csv(OUT / "bootstrap_over_runs.csv", index=False)
    pd.concat(scen).to_csv(OUT / "per_scenario_recall.csv", index=False)

    (OUT / "config.json").write_text(json.dumps({k: config.snapshot()[k] for k in
                                                 ("SEED", "CV_FOLDS", "WINDOW_ASSIGNMENT", "HOLDOUT_RUNS", "FEATURE_SETS", "FEATURE_GROUPS")}, indent=2))
    (OUT / "note.txt").write_text(f"Phase 9 robustness: importance with every fold as judge ({N_PERM} permutations, per feature and per "
                                  f"group), {len(SEEDS)} model seeds, "
                                  f"{N_BOOT} run bootstraps, carpet recall by scenario, source count and status. "
                                  "agg_flow set, phase 8 picked params. Hold-out untouched.\n")
    print(f"done in {time.time() - start:.0f}s -> {OUT}")


if __name__ == "__main__":
    main()
