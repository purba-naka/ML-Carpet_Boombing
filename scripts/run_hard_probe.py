"""Probe, not a result: how do the models and one line rules do on carpet that touches fewer destinations?

Real hard runs need the testbed. This is the cheap stand-in: every carpet window of trainval is thinned to
k of its destinations (the flows to the other destinations are dropped, per destination rate is kept, so total
volume falls with k as it would for a real narrower carpet). Features are recomputed from the thinned flows.
Out of fold: a model never sees thinned windows of its own run in training, and trains on the original data
of the other folds only. Needs the spread assignment (D21): CARPET_WINDOW_ASSIGNMENT=spread.

What it cannot show: a real attacker with k targets, uneven rates, or benign traffic crowding the same subnet.
"""
import json
import time

import numpy as np
import pandas as pd

from carpet import config, evaluate, features, io, models, table, windows

OUT = config.EXPERIMENTS / "hard_probe"
CHOSEN = config.REPORTS / "experiments" / "phase8_tuning" / "chosen_params.json"
KS = (4, 6, 8, 12)
SET = "agg_flow"
COLUMNS = list(dict.fromkeys([*features.FLOW_COLUMNS, *config.FLOW_SUMMARY_COLUMNS]))


def run_flows(start_ts: int, end_ts: int) -> pd.DataFrame:
    parts = []
    for f in io.iter_artifact(config.FLOWS_CLEAN, COLUMNS):
        f = f[(f.ts >= start_ts - 120) & (f.ts <= end_ts + 120) & f["Dst IP"].str.startswith(config.VICTIM_PREFIX)]
        if len(f):
            parts.append(f)
    return pd.concat(parts, ignore_index=True)


def thinned_rows(run: str, ws: set[int], log: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    """One feature row per (window, k) for the carpet windows `ws` of one run."""
    r = log.loc[run]
    flows = run_flows(r.start_ts, r.end_ts)
    whole = windows.spread_flows(flows, split=())          # flow-level columns stay whole (D21)
    split = windows.spread_flows(flows)                    # packets and bytes divided, used for the aggregates
    assert len(whole) == len(split) and (whole.ts.to_numpy() == split.ts.to_numpy()).all()
    w = (whole.ts // config.WINDOW_SECONDS * config.WINDOW_SECONDS).to_numpy()
    in_run = np.isin(w, list(ws))
    whole, split, w = whole[in_run], split[in_run], w[in_run]

    # One random draw per (window, destination), so the subsets are nested: the 4 kept are among the 6 kept.
    u = pd.DataFrame({"w": w, "dst": whole["Dst IP"].to_numpy()}).drop_duplicates()
    u["rank"] = pd.Series(rng.random(len(u)), index=u.index).groupby(u.w).rank(method="first")
    rank = pd.DataFrame({"w": w, "dst": whole["Dst IP"].to_numpy()}).merge(u, on=["w", "dst"], how="left")["rank"].to_numpy()
    out = []
    for k in (*KS, None):
        keep = np.ones(len(whole), bool) if k is None else rank <= k
        agg = features.build_features(features.pair_counts(split[keep]))
        flow = features.flow_summary(whole[keep], list(config.FLOW_SUMMARY_COLUMNS))
        out.append(agg.merge(flow, on=["subnet", "w"]).assign(k=0 if k is None else k, group=run))
    return pd.concat(out, ignore_index=True)


def fit(model: str, train: pd.DataFrame, cols: list[str]):
    params = json.loads(CHOSEN.read_text())[f"{model}_{SET}_weak1"]["params"]
    m = (models.random_forest(**params) if model == "rf"
         else models.xgboost(evaluate.scale_pos_weight(train.label), **params))
    return m.fit(train[cols].to_numpy(), train.label.to_numpy())


def main() -> None:
    if config.WINDOW_ASSIGNMENT != "spread":
        raise SystemExit("run with CARPET_WINDOW_ASSIGNMENT=spread (the start assignment has the weak windows)")
    start = time.time()
    tv = table.trainval(table.load_table())
    cols = list(config.FEATURE_SETS[SET])
    log = io.read_attack_log().set_index("run_id")
    carpet = tv[tv.subclass == "carpet"]
    rng = np.random.default_rng(config.SEED)
    thin = pd.concat([thinned_rows(run, set(g.w), log, rng) for run, g in carpet.groupby("group")], ignore_index=True)
    thin = thin.merge(carpet[["subnet", "w", "fold", "label"]], on=["subnet", "w"], validate="m:1")
    print(f"thinned {len(thin)} rows from {carpet.shape[0]} carpet windows ({time.time() - start:.0f}s)", flush=True)

    shape = thin.groupby("k")[["n_unique_dst", "dst_entropy_norm", "total_pkts", "concentration_ratio"]].median()
    neg = tv[tv.label == 0]
    shape.loc["benign (max)"] = [neg.n_unique_dst.max(), neg.dst_entropy_norm.max(), neg.total_pkts.max(), neg.concentration_ratio.min()]
    print("median feature value of the thinned carpet, k=0 is the original:\n", shape.round(3).to_string(), flush=True)

    rows = []
    for name, make, use in (("rf", lambda tr: fit("rf", tr, cols), cols), ("xgb", lambda tr: fit("xgb", tr, cols), cols),
                            ("threshold n_unique_dst", lambda tr: models.SingleFeatureThreshold(0).fit(tr[["n_unique_dst"]].to_numpy(), tr.label.to_numpy()), ["n_unique_dst"]),
                            ("threshold dst_entropy_norm", lambda tr: models.SingleFeatureThreshold(0).fit(tr[["dst_entropy_norm"]].to_numpy(), tr.label.to_numpy()), ["dst_entropy_norm"])):
        hit = {k: [] for k in (0, *KS)}
        fa, n_neg = 0, 0
        for fold in sorted(tv.fold.unique()):
            model = make(tv[tv.fold != fold])
            test_neg = tv[(tv.fold == fold) & (tv.label == 0)]
            fa += int(model.predict(test_neg[use].to_numpy()).sum()); n_neg += len(test_neg)
            for k, g in thin[thin.fold == fold].groupby("k"):
                hit[k] += model.predict(g[use].to_numpy()).tolist()
        for k, h in hit.items():
            rows.append({"model": name, "k_destinations": k or "original", "n_carpet_windows": len(h),
                         "recall": float(np.mean(h)), "false_alarm_rate_on_negatives": fa / n_neg})
        print(f"{name:28s} " + "  ".join(f"k={k or 'orig'}: {np.mean(h):.3f}" for k, h in hit.items()) +
              f"   FPR {fa / n_neg:.3f}", flush=True)

    OUT.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(OUT / "recall_by_k.csv", index=False)
    shape.to_csv(OUT / "feature_shape_by_k.csv")
    (OUT / "note.txt").write_text("Probe: carpet windows thinned to k destinations, out of fold, trainval only, "
                                  "spread assignment. Not a substitute for real hard runs. Hold-out not read.\n")
    print(f"done in {time.time() - start:.0f}s -> {OUT}")


if __name__ == "__main__":
    main()
