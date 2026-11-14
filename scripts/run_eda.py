"""Phase 5: EDA on trainval windows only. Writes figures and tables, prints the numbers behind the findings."""
import time

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from carpet import clean, config, eda, features, io

FIG = config.FIGURES
SUBCLASS_COLORS = {"benign": "tab:gray", "carpet": "tab:red", "focused": "tab:blue"}
FLOW_BATCH = 8


def flow_level_table(df: pd.DataFrame) -> pd.DataFrame:
    """Per window mean of every flow-level column, for trainval windows. Batches keep RAM small."""
    cols = clean.feature_columns(io.read_meta(config.FLOWS_CLEAN)["columns"])
    keys = df[["subnet", "w"]]
    out = keys.copy()
    for i in range(0, len(cols), FLOW_BATCH):
        batch = cols[i:i + FLOW_BATCH]
        flows = pd.concat(io.iter_artifact(config.FLOWS_CLEAN, ["Dst IP", "ts", *batch]))
        mean = features.flow_summary(flows, batch)[["subnet", "w", *[f"{c}__mean" for c in batch]]]
        out = out.merge(mean, on=["subnet", "w"], how="left", validate="1:1")
        print(f"flow columns {min(i + FLOW_BATCH, len(cols))}/{len(cols)}", flush=True)
    return out.rename(columns=lambda c: c.removesuffix("__mean"))


def main() -> None:
    start = time.time()
    FIG.mkdir(parents=True, exist_ok=True)
    config.TABLES.mkdir(parents=True, exist_ok=True)
    df = eda.load_trainval()
    F = features.AGG_FEATURES

    # 1 class balance
    bal = pd.crosstab(df.group, [df.subclass, df.status])
    bal.to_csv(config.TABLES / "eda_balance_per_group.csv")
    fig, ax = plt.subplots(figsize=(10, 3.5))
    df.groupby(["subclass", "status"]).size().unstack(fill_value=0).plot.bar(stacked=True, ax=ax)
    ax.set_title("trainval windows per subclass"); fig.tight_layout(); fig.savefig(FIG / "eda_balance.png", dpi=110); plt.close(fig)

    # 3 distributions by subclass, log scale
    fig, axes = plt.subplots(3, 4, figsize=(16, 9))
    for ax, c in zip(axes.flat, F):
        data = [np.log10(df.loc[df.subclass == s, c].clip(lower=1e-3)) for s in SUBCLASS_COLORS]
        ax.boxplot(data, tick_labels=list(SUBCLASS_COLORS)); ax.set_title(c + " (log10)")
    fig.tight_layout(); fig.savefig(FIG / "eda_features_by_subclass.png", dpi=100); plt.close(fig)

    # 4, 5 separability
    rows = {"carpet_vs_rest": eda.single_feature_auc(df, F, "carpet", ["benign", "focused"]),
            "carpet_vs_focused": eda.single_feature_auc(df, F, "carpet", ["focused"]),
            "carpet_vs_benign": eda.single_feature_auc(df, F, "carpet", ["benign"])}
    auc = pd.DataFrame(rows).loc[F]
    auc.to_csv(config.TABLES / "eda_single_feature_auc.csv")
    shortcut = auc[(auc > 0.99).any(axis=1)].index.tolist()

    # 6 weak vs benign
    weak = df[(df.subclass == "carpet")].groupby("status")[["n_unique_dst", "total_pkts", "n_unique_src", "n_flows"]].median()
    weak.to_csv(config.TABLES / "eda_weak_vs_ok_carpet.csv")

    # 7 correlation
    corr = eda.high_correlation_pairs(df, F)
    corr.to_csv(config.TABLES / "eda_high_correlation.csv", index=False)

    # 8 single vs multi source
    log = io.read_attack_log().set_index("run_id")
    runs = df[df.subclass != "benign"].assign(n_src=lambda d: d.run_id.map(log.n_src))
    by_src = runs.groupby(["subclass", "n_src"])[F].median().T
    by_src.to_csv(config.TABLES / "eda_single_vs_multi_source.csv")

    # 2 timeline (all windows keep their status so the exclusions are visible, labels of hold-out hidden)
    windows = io.read_artifact(config.WINDOWS_LABELED)
    fig, ax = plt.subplots(figsize=(14, 3.5))
    t = windows.window_start
    shown = windows.status.isin(list(config.USABLE_STATUSES)) & ~windows.group.isin(config.HOLDOUT_RUNS)
    ax.semilogy(t, windows.n_pkts.clip(lower=1), color="lightgray", lw=0.6, label="all windows")
    ax.scatter(t[windows.status == "exclude_unlogged"], windows.n_pkts[windows.status == "exclude_unlogged"].clip(lower=1),
               s=8, color="black", label="excluded unlogged")
    for s, c in SUBCLASS_COLORS.items():
        m = shown & (windows.subclass == s)
        ax.scatter(t[m], windows.n_pkts[m].clip(lower=1), s=5, color=c, label=s)
    ax.set_title("packets per window (hold-out runs hidden)"); ax.legend(ncol=5, fontsize=7)
    fig.tight_layout(); fig.savefig(FIG / "eda_timeline.png", dpi=110); plt.close(fig)

    # 9 flow-level columns: effect size carpet vs benign and carpet vs focused, plus constant/near duplicate
    fl = flow_level_table(df)
    flow_cols = [c for c in fl.columns if c not in ("subnet", "w")]
    both = df[["subnet", "w", "subclass"]].merge(fl, on=["subnet", "w"], validate="1:1")
    var = both[flow_cols].var()
    flow_cols = [c for c in flow_cols if var[c] > 0 and c not in config.CONSTANT_COLUMNS]
    d_benign = eda.effect_size(both.fillna(0), flow_cols, "carpet", "benign")
    d_focused = eda.effect_size(both.fillna(0), flow_cols, "carpet", "focused")
    eff = pd.DataFrame({"d_carpet_vs_benign": d_benign, "d_carpet_vs_focused": d_focused}).fillna(0)
    eff["d_min"] = eff.min(axis=1)
    eff = eff.sort_values("d_min", ascending=False)
    eff.to_csv(config.TABLES / "eda_flow_effect_size.csv")
    fcorr = eda.high_correlation_pairs(both.fillna(0), flow_cols, 0.98)
    fcorr.to_csv(config.TABLES / "eda_flow_high_correlation.csv", index=False)
    # 10 where the NaN sits
    nan_where = both[flow_cols].isna().sum()
    nan_where[nan_where > 0].to_csv(config.TABLES / "eda_flow_nan_windows.csv", header=["windows_with_nan"])

    pd.set_option("display.width", 200); pd.set_option("display.max_columns", 20)
    print(f"\nwindows {len(df)}, groups {df.group.nunique()}")
    print("\nAUC (alone):\n", auc.round(3).to_string())
    print("\nshortcut flags (>0.99):", shortcut or "none")
    print("\ncarpet ok vs weak (median):\n", weak.to_string())
    print("\nsingle vs multi (median):\n", by_src.round(2).to_string())
    print("\nflow-level: usable non-constant columns", len(flow_cols), "| top by min effect size:\n", eff.head(20).round(2).to_string())
    print("\nflow-level near duplicates (>=0.98):", len(fcorr))
    print("flow-level NaN windows:", nan_where[nan_where > 0].to_dict())
    print(f"done in {time.time() - start:.0f}s")


if __name__ == "__main__":
    main()
