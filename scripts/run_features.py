"""Phase 6: aggregate features and flow-level summaries (D15) per (subnet, window). Labels not touched."""
import time

import pandas as pd

from carpet import config, features, io

AGG_KEYS = ["WINDOW_SECONDS", "UDP", "AGG_FEATURES"]
FLOW_KEYS = ["WINDOW_SECONDS", "FLOW_SUMMARY_COLUMNS", "FLOW_STATS"]


def agg_table(start: float) -> pd.DataFrame:
    parts = []
    for flows in io.iter_artifact(config.FLOWS_CLEAN, features.FLOW_COLUMNS):
        parts.append(features.pair_counts(flows))
        print(f"agg {len(parts)} row groups ({time.time() - start:.0f}s)", flush=True)
    return features.build_features(features.combine_pairs(parts))


def flow_table(start: float, columns: list[str]) -> pd.DataFrame:
    """Mean, std, max per window of flow-level columns, a few columns at a time to keep RAM small."""
    flows = pd.concat(io.iter_artifact(config.FLOWS_CLEAN, ["Dst IP", "ts", *columns]), ignore_index=True)
    out = features.flow_summary(flows, columns)
    print(f"flow summary of {len(columns)} columns {out.shape} ({time.time() - start:.0f}s)", flush=True)
    return out


def main() -> None:
    start = time.time()
    agg = agg_table(start)
    flow = flow_table(start, list(config.FLOW_SUMMARY_COLUMNS))
    artifact = flow_table(start, list(config.ARTIFACT_FLOW_COLUMNS))
    windows = io.read_artifact(config.WINDOWS_LABELED, ["subnet", "w", "n_flows", "n_pkts"])
    joined = agg.merge(windows, on=["subnet", "w"], how="outer", validate="1:1", indicator=True)
    problems = []
    if (joined._merge != "both").any():
        problems.append(f"window keys differ between features and labels: {joined._merge.value_counts().to_dict()}")
    elif ((joined.n_flows_x != joined.n_flows_y) | (joined.total_pkts != joined.n_pkts)).any():
        problems.append("n_flows or packets differ between features and labeling")
    if agg[features.AGG_FEATURES].isna().any().any():
        problems.append("NaN in aggregate features")
    for name, tab in (("flow", flow), ("artifact", artifact)):
        if len(tab) != len(agg) or set(map(tuple, tab[features.KEY].to_numpy())) != set(map(tuple, agg[features.KEY].to_numpy())):
            problems.append(f"{name} summary covers other windows than the aggregates")
    if problems:
        raise ValueError("features refused:\n  " + "\n  ".join(problems))
    io.write_artifact(agg, config.FEATURES_AGG, script="scripts/run_features.py", config_keys=AGG_KEYS,
                      inputs=(config.FLOWS_CLEAN,), notes={"volume": "packets (D13)"})
    io.write_artifact(flow, config.FEATURES_FLOW, script="scripts/run_features.py", config_keys=FLOW_KEYS,
                      inputs=(config.FLOWS_CLEAN,),
                      notes={"nan_cells": {c: int(n) for c, n in flow.isna().sum().items() if n}})
    io.write_artifact(artifact, config.FEATURES_ARTIFACT, script="scripts/run_features.py",
                      config_keys=["WINDOW_SECONDS", "ARTIFACT_FLOW_COLUMNS", "FLOW_STATS"],
                      inputs=(config.FLOWS_CLEAN,),
                      notes={"nan_cells": {c: int(n) for c, n in artifact.isna().sum().items() if n}})
    print(f"wrote {config.FEATURES_AGG.name} {agg.shape}, {config.FEATURES_FLOW.name} {flow.shape}, "
          f"{config.FEATURES_ARTIFACT.name} {artifact.shape} in {time.time() - start:.0f}s")


if __name__ == "__main__":
    main()
