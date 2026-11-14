"""Phase 10: final evaluation. Train on all of trainval, predict the one shot test set, report, never iterate.

Final mode is the real hold-out and may only be run once. Rehearsal mode (--rehearse) runs the exact
same code path on trainval fold 0 as a fake hold-out, so a mechanical bug burns a fold, not the hold-out.

Roles follow the proposal (PDF 3.2.4.1): Random Forest is the main model, XGBoost the comparison.
The first version of this script declared XGBoost primary, which contradicted the PDF (IMPLEMENTATION.md
change log, D20). Both train on all of trainval, agg_flow features, weak windows in train, phase 8
picked params, seed 42, threshold 0.5.
"""
import json
import sys
import time

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay, PrecisionRecallDisplay, RocCurveDisplay, confusion_matrix

from carpet import config, evaluate, models, split, table

FINAL = config.EXPERIMENTS / "phase10_final"
REHEARSAL = config.EXPERIMENTS / "phase10_rehearsal"
CHOSEN = config.EXPERIMENTS / "phase8_tuning" / "chosen_params.json"
FIG = config.FIGURES


def one_shot_split(df: pd.DataFrame, rehearse: bool) -> tuple[pd.DataFrame, pd.DataFrame]:
    if rehearse:
        tv = table.trainval(df)
        judge = tv.fold.min()
        return tv[tv.fold != judge], tv[tv.fold == judge]
    return table.trainval(df), df[df.partition == split.HOLDOUT]


N_BOOT = 1000
# PL-6: the one-threshold rules tie the models on CV, so they are judged on the same test rows,
# fitted on the same train rows. Without them the final table cannot say whether the model was needed.
BASELINES = {"threshold_dst_entropy_norm": "dst_entropy_norm", "threshold_n_unique_dst": "n_unique_dst",
             "all_negative": None}


def fit(model: str, params: dict, train: pd.DataFrame, cols: list[str]):
    y = train.label.to_numpy()
    if model == "xgb":
        m = models.xgboost(evaluate.scale_pos_weight(pd.Series(y)), **params)
    elif model == "rf":
        m = models.random_forest(**params)
    elif BASELINES[model] is None:
        m = models.AllNegative()
    else:
        m = models.SingleFeatureThreshold(feature_index=cols.index(BASELINES[model]))
    m.fit(train[cols].to_numpy(), y)
    return m


def run_model(name: str, role: str, params: dict, train: pd.DataFrame, test: pd.DataFrame,
              cols: list[str], out, figures, save: bool, where: str) -> dict:
    m = fit(name, params, train, cols)
    X_test = test[cols].to_numpy()
    proba = m.predict_proba(X_test)[:, 1]
    pred = m.predict(X_test)
    times = []
    for _ in range(5):
        t0 = time.perf_counter()
        m.predict(X_test)
        times.append((time.perf_counter() - t0) / len(test) * 1000)
    metrics = evaluate.score(test.label.to_numpy(), proba, pred)
    metrics["ms_per_window"] = float(np.median(times))

    res = test[["subnet", "w", "run_id", "group", "subclass", "status", "near_attack", "label"]].assign(
        proba=proba, pred=pred)
    pd.DataFrame(confusion_matrix(test.label, pred, labels=[0, 1]), columns=["pred_0", "pred_1"],
                 index=["true_0", "true_1"]).to_csv(out / f"confusion_{name}.csv")
    evaluate.per_group(res).to_csv(out / f"per_run_{name}.csv", index=False)
    missed = res[(res.label == 1) & (res.pred == 0)]
    false_alarms = res[(res.label == 0) & (res.pred == 1)]
    missed.to_csv(out / f"missed_{name}.csv", index=False)
    false_alarms.to_csv(out / f"false_alarms_{name}.csv", index=False)

    if role == "main":
        fig, ax = plt.subplots(figsize=(4, 4))
        ConfusionMatrixDisplay.from_predictions(test.label, pred, ax=ax)
        ax.set_title(f"{where}: confusion matrix ({name})")
        fig.tight_layout(); fig.savefig(figures / f"final_confusion_{name}.png", dpi=110); plt.close(fig)
        fig, ax = plt.subplots(figsize=(4.5, 4))
        RocCurveDisplay.from_predictions(test.label, proba, ax=ax)
        ax.set_title(f"{where}: ROC ({name})")
        fig.tight_layout(); fig.savefig(figures / f"final_roc_{name}.png", dpi=110); plt.close(fig)
        fig, ax = plt.subplots(figsize=(4.5, 4))
        PrecisionRecallDisplay.from_predictions(test.label, proba, ax=ax)
        ax.set_title(f"{where}: PR ({name})")
        fig.tight_layout(); fig.savefig(figures / f"final_pr_{name}.png", dpi=110); plt.close(fig)
    if "xgbclassifier" in getattr(m, "named_steps", {}):
        gain = m.named_steps["xgbclassifier"].get_booster().get_score(importance_type="gain")
        gain = pd.Series({cols[int(k[1:])]: v for k, v in gain.items()}).sort_values(ascending=True).tail(15)
        fig, ax = plt.subplots(figsize=(6, 5))
        ax.barh(gain.index, gain.values)
        ax.set_title(f"XGBoost gain importance ({where})")
        fig.tight_layout(); fig.savefig(figures / "final_importance_xgb.png", dpi=110); plt.close(fig)
    boot = evaluate.bootstrap_runs(res, N_BOOT, np.random.default_rng(config.SEED))
    boot = {k: v for k, v in boot.items() if k.split("_q")[0] in ("recall", "precision", "fpr", "pr_auc", "n_runs")}
    if save and role != "baseline":
        joblib.dump({"model": m, "features": cols, "params": params, "role": role,
                     "trained_on": "trainval"}, config.MODELS / f"final_{name}.joblib")
    return {"model": name, "role": role, "n_train": len(train), "n_train_pos": int(train.label.sum()),
            "n_test": len(test), "n_test_pos": int(test.label.sum()), "missed": len(missed),
            "false_alarms": len(false_alarms), **metrics, **boot}


def main() -> None:
    start = time.time()
    if len(sys.argv) != 2 or sys.argv[1] not in ("--rehearse", "--final"):
        sys.exit("usage: run_final.py --rehearse | --final   (no flag guesswork: a typo must not run the real thing)")
    rehearse = sys.argv[1] == "--rehearse"
    out, figures = (REHEARSAL, REHEARSAL) if rehearse else (FINAL, FIG)
    out.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    if not rehearse:
        config.MODELS.mkdir(parents=True, exist_ok=True)
        config.TABLES.mkdir(parents=True, exist_ok=True)
    df = table.load_table()
    train, test = one_shot_split(df, rehearse)
    cols = list(config.FEATURE_SETS["agg_flow"])
    forbidden = set(cols) & config.FORBIDDEN_FEATURES
    overlap = set(train.group) & set(test.group)
    holdout_leak = train.group.isin(config.HOLDOUT_RUNS).any()
    partition_leak = not rehearse and (set(train.partition) != {split.TRAINVAL} or set(test.partition) != {split.HOLDOUT})
    problems = []
    if forbidden or overlap or holdout_leak or partition_leak:
        problems.append(f"forbidden={sorted(forbidden)} shared groups={sorted(overlap)} "
                        f"holdout in train={holdout_leak} wrong partitions={partition_leak}")
    if not {0, 1} <= set(train.label.unique()) or not {0, 1} <= set(test.label.unique()):
        problems.append(f"one-class side: train {sorted(train.label.unique())}, "
                        f"test {sorted(test.label.unique())}")
    if not rehearse and not set(config.HOLDOUT_RUNS) <= set(test.group):
        problems.append(f"hold-out runs missing from the test side: "
                        f"{sorted(set(config.HOLDOUT_RUNS) - set(test.group))}")
    if problems:
        raise ValueError("one shot guards failed: " + "; ".join(problems))
    print(f"train {len(train)} windows ({train.group.nunique()} groups, {int(train.label.sum())} carpet), "
          f"test {len(test)} windows ({test.group.nunique()} groups, {int(test.label.sum())} carpet), "
          f"{'REHEARSAL on trainval fold ' + str(test.fold.min()) if rehearse else 'REAL HOLD-OUT'}", flush=True)

    where = f"REHEARSAL trainval fold {test.fold.min()}" if rehearse else "hold-out"
    params = json.loads(CHOSEN.read_text())
    rows = []
    plan = [("rf", "main"), ("xgb", "comparison")] + [(b, "baseline") for b in BASELINES]
    for name, role in plan:
        model_params = params[f"{name}_agg_flow_weak1"]["params"] if role != "baseline" else {}
        rows.append(run_model(name, role, model_params,
                              train, test, cols, out, figures, save=not rehearse, where=where))
        r = rows[-1]
        print(f"{name} ({role}): recall={r['recall']:.3f} precision={r['precision']:.3f} "
              f"fpr={r['fpr']:.3f} pr_auc={r['pr_auc']:.3f} roc_auc={r['roc_auc']:.3f} "
              f"missed={r['missed']} false_alarms={r['false_alarms']} ({time.time() - start:.0f}s)", flush=True)
    summary = pd.DataFrame(rows)
    summary.to_csv(out / "metrics.csv", index=False)
    if not rehearse:
        summary.to_csv(config.TABLES / "final_metrics.csv", index=False)
    (out / "config.json").write_text(json.dumps({k: config.snapshot()[k] for k in
                                                 ("SEED", "HOLDOUT_RUNS", "FEATURE_SETS")}, indent=2))
    (out / "note.txt").write_text("Phase 10: RF main, XGBoost comparison (PDF 3.2.4.1), agg_flow, weak in train, "
                                  "phase 8 params, seed 42, threshold 0.5. " +
                                  ("REHEARSAL on a trainval fold, hold-out untouched.\n" if rehearse else
                                   "One shot on the real hold-out, no iteration after.\n"))
    print(f"done in {time.time() - start:.0f}s -> {out}")


if __name__ == "__main__":
    main()
