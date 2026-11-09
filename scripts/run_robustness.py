"""Phase 9: robustness. Feature importance, seed stability, cluster bootstrap over runs, per scenario recall.

Everything runs on trainval only, with the phase 8 picked params on agg_flow. Hold-out untouched.
"""
import json
import time

import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import roc_auc_score

from carpet import config, evaluate, io, models, table

EXPERIMENT = "phase9_robustness"
OUT = config.REPORTS / "experiments" / EXPERIMENT
CHOSEN = config.REPORTS / "experiments" / "phase8_tuning" / "chosen_params.json"
SEEDS = [config.SEED + i for i in range(5)]
N_BOOT = 1000


def picked(model: str, weak: bool) -> dict:
    return json.loads(CHOSEN.read_text())[f"{model}_agg_flow_weak{int(weak)}"]["params"]


def make_model(model: str, weak: bool, seed: int):
    params = picked(model, weak)
    if model == "rf":
        return lambda y: models.random_forest(**params, random_state=seed)
    return lambda y: models.xgboost(evaluate.scale_pos_weight(y), **params, random_state=seed)


def importance(df: pd.DataFrame) -> pd.DataFrame:
    """RF impurity and permutation, XGB gain. The model trains on four folds, fold 0 stays
    the judge: permutation importance on train data would flatter the features."""
    cols = list(config.FEATURE_SETS["agg_flow"])
    fold0 = df.fold.min()
    train, valid = df[df.fold != fold0], df[df.fold == fold0]
    rf = models.random_forest(**picked("rf", True))
    rf.fit(train[cols].to_numpy(), train.label.to_numpy())
    impurity = pd.Series(rf.named_steps["randomforestclassifier"].feature_importances_, index=cols)
    perm = permutation_importance(rf, valid[cols].to_numpy(), valid.label.to_numpy(),
                                  scoring=lambda est, X, y: roc_auc_score(y, est.predict_proba(X)[:, 1]),
                                  n_repeats=10, random_state=config.SEED)
    xgb = models.xgboost(evaluate.scale_pos_weight(train.label), **picked("xgb", True))
    xgb.fit(train[cols].to_numpy(), train.label.to_numpy())
    gain = xgb.named_steps["xgbclassifier"].get_booster().get_score(importance_type="gain")
    gain = pd.Series({cols[int(k[1:])]: v for k, v in gain.items()})
    out = pd.DataFrame({
        "rf_impurity": impurity / impurity.sum(),
        "rf_permutation_auc_drop": pd.Series(perm.importances_mean, index=cols),
        "xgb_gain": (gain / gain.sum()).reindex(cols).fillna(0.0),
    })
    return out.sort_values("rf_impurity", ascending=False)


def seed_stability(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Same data, same folds, only the model seed moves. Returns per seed means, the spread,
    and the out of fold predictions of the base seed for the bootstrap and the scenario cuts."""
    cols = list(config.FEATURE_SETS["agg_flow"])
    rows, keep = [], {}
    for weak in (True, False):
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


def bootstrap(oof: pd.DataFrame, rng: np.random.Generator) -> dict:
    """Resample runs with replacement, never windows on their own: a run is the unit the
    model has never seen, so the uncertainty it carries is what the numbers should show."""
    groups = oof.group.unique()
    draws = []
    for _ in range(N_BOOT):
        parts = pd.concat([oof[oof.group == g] for g in rng.choice(groups, size=len(groups), replace=True)])
        draws.append(evaluate.score(parts.label.to_numpy(), parts.proba.to_numpy(), parts.pred.to_numpy()))
    b = pd.DataFrame(draws)
    return {"n_runs": len(groups)} | {f"{c}_{q}": b[c].quantile(q_)
            for c in evaluate.METRICS for q, q_ in (("q025", 0.025), ("q50", 0.5), ("q975", 0.975))}


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

    imp = importance(df)
    imp.to_csv(OUT / "importance.csv")
    print("top features by RF impurity:\n", imp.head(10).round(3).to_string(), f"\n({time.time() - start:.0f}s)\n")

    seeds, spread, keep = seed_stability(df)
    seeds.to_csv(OUT / "seed_stability.csv", index=False)
    spread.to_csv(OUT / "seed_spread.csv")
    print("seed spread (min..max over 5 seeds):\n", spread.round(3).to_string(), f"\n({time.time() - start:.0f}s)\n")

    boot, scen = [], []
    rng = np.random.default_rng(config.SEED)
    for (model, weak), oof in keep.items():
        boot.append({"model": model, "weak_in_train": weak, **bootstrap(oof, rng)})
        s = per_scenario(oof)
        s.insert(0, "weak_in_train", weak)
        s.insert(0, "model", model)
        scen.append(s)
        print(f"bootstrap {model} weak{int(weak)} ({time.time() - start:.0f}s)", flush=True)
    pd.DataFrame(boot).to_csv(OUT / "bootstrap_over_runs.csv", index=False)
    pd.concat(scen).to_csv(OUT / "per_scenario_recall.csv", index=False)

    (OUT / "config.json").write_text(json.dumps({k: config.snapshot()[k] for k in
                                                 ("SEED", "CV_FOLDS", "HOLDOUT_RUNS", "FEATURE_SETS")}, indent=2))
    (OUT / "note.txt").write_text(f"Phase 9 robustness: importance on fold 0 as judge, {len(SEEDS)} model seeds, "
                                  f"{N_BOOT} run bootstraps, carpet recall by scenario, source count and status. "
                                  "agg_flow set, phase 8 picked params. Hold-out untouched.\n")
    print(f"done in {time.time() - start:.0f}s -> {OUT}")


if __name__ == "__main__":
    main()
