"""PL-7: how long one window takes from clean flows to an alarm, trainval windows only.

Deployment works one window at a time: every minute the flows of the last minute come in, features are
built, the model predicts. So the timing is per window, on the busiest windows (worst case), not a batch
average over the whole day. CICFlowMeter's own extraction time is not measured here.
"""
import json
import time

import numpy as np
import pandas as pd

from carpet import config, evaluate, features, io, models, table, windows

OUT = config.EXPERIMENTS / "latency"
CHOSEN = config.EXPERIMENTS / "phase8_tuning" / "chosen_params.json"
PER_SUBCLASS = 10
REPEATS = 5
FLOW_TIMEOUT_S = 120  # CICFlowMeter flow timeout of capture S1 (AGENT.md section 10)


def busiest(df: pd.DataFrame) -> pd.DataFrame:
    """The PER_SUBCLASS windows with the most packets in each subclass: the slow cases."""
    return df.sort_values("total_pkts", ascending=False).groupby("subclass").head(PER_SUBCLASS)


def window_features(flows: pd.DataFrame, w: int, cols: list[str]) -> pd.DataFrame:
    """Every feature of one window, from the raw clean flows that can touch it."""
    near = flows[(flows.ts >= w - FLOW_TIMEOUT_S) & (flows.ts < w + config.WINDOW_SECONDS)]
    agg_in = windows.assign(near[features.FLOW_COLUMNS])
    agg = features.build_features(features.pair_counts(agg_in[agg_in.ts // config.WINDOW_SECONDS * config.WINDOW_SECONDS == w]))
    flow_in = windows.assign(near[["Dst IP", "ts", *config.FLOW_SUMMARY_COLUMNS]], split=())
    flow_in = flow_in[flow_in.ts // config.WINDOW_SECONDS * config.WINDOW_SECONDS == w]
    summary = features.flow_summary(flow_in, list(config.FLOW_SUMMARY_COLUMNS))
    return agg.merge(summary, on=["subnet", "w"])[cols]


def main() -> None:
    start = time.time()
    df = table.trainval(table.load_table())
    cols = list(config.FEATURE_SETS["agg_flow"])
    picks = busiest(df)
    need = list(dict.fromkeys([*features.FLOW_COLUMNS, *config.FLOW_SUMMARY_COLUMNS]))
    lo, hi = picks.w.min() - FLOW_TIMEOUT_S, picks.w.max() + config.WINDOW_SECONDS
    flows = pd.concat([f[(f.ts >= lo) & (f.ts < hi)] for f in io.iter_artifact(config.FLOWS_CLEAN, need)],
                      ignore_index=True)
    print(f"{len(picks)} windows, {len(flows):,} candidate flows loaded ({time.time() - start:.0f}s)", flush=True)

    params = json.loads(CHOSEN.read_text())
    fitted = {"rf": models.random_forest(**params["rf_agg_flow_weak1"]["params"]),
              "xgb": models.xgboost(evaluate.scale_pos_weight(df.label), **params["xgb_agg_flow_weak1"]["params"])}
    for m in fitted.values():
        m.fit(df[cols].to_numpy(), df.label.to_numpy())

    rows = []
    for r in picks.itertuples():
        feat_ms, X = [], None
        for _ in range(REPEATS):
            t0 = time.perf_counter()
            X = window_features(flows, r.w, cols)
            feat_ms.append((time.perf_counter() - t0) * 1000)
        # The rebuilt row must equal the stored feature row, or the timing measured some other computation.
        if not np.allclose(X.to_numpy(dtype=float), df.loc[[r.Index], cols].to_numpy(dtype=float), equal_nan=True, rtol=1e-6):
            raise ValueError(f"window {r.w}: features rebuilt for timing differ from the feature table")
        row = {"w": r.w, "subclass": r.subclass, "total_pkts": r.total_pkts, "features_ms": float(np.median(feat_ms))}
        for name, m in fitted.items():
            ts = []
            for _ in range(REPEATS):
                t0 = time.perf_counter()
                m.predict_proba(X.to_numpy())
                ts.append((time.perf_counter() - t0) * 1000)
            row[f"predict_{name}_ms"] = float(np.median(ts))
        rows.append(row)
    per_window = pd.DataFrame(rows)
    OUT.mkdir(parents=True, exist_ok=True)
    per_window.to_csv(OUT / "per_window.csv", index=False)
    summary = per_window.drop(columns=["w", "total_pkts"]).groupby("subclass").median()
    summary.loc["max over windows"] = per_window.drop(columns=["w", "subclass", "total_pkts"]).max()
    summary.to_csv(OUT / "summary.csv")
    config.TABLES.mkdir(parents=True, exist_ok=True)
    summary.to_csv(config.TABLES / "latency.csv")
    worst = summary.loc["max over windows"]
    compute_s = (worst.features_ms + max(worst.predict_rf_ms, worst.predict_xgb_ms)) / 1000
    note = (f"Worst detection delay = window {config.WINDOW_SECONDS} s + flow timeout {FLOW_TIMEOUT_S} s "
            f"(an attack flow is only exported when it ends or times out) + compute {compute_s:.2f} s "
            f"= {config.WINDOW_SECONDS + FLOW_TIMEOUT_S + compute_s:.1f} s. CICFlowMeter extraction time not measured.")
    (OUT / "note.txt").write_text(note + "\n")
    print(summary.round(2).to_string())
    print(note)
    print(f"done in {time.time() - start:.0f}s -> {OUT}")


if __name__ == "__main__":
    main()
