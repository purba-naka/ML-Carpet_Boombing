"""Phase 3: clean flows to one labeled row per (subnet, 60 s window)."""
import time

import pandas as pd

from carpet import config, io, labeling, windows

CONFIG_KEYS = ["WINDOW_SECONDS", "WINDOW_ASSIGNMENT", "VICTIM_PREFIX", "ATTACKER_IP", "BENIGN_SRC_EXTRA", "DNS_PORT", "UDP",
               "TEST_RUN", "UNLOGGED_MIN_FLOWS", "UNLOGGED_GAP_SECONDS", "BOUNDARY_BUFFER_SECONDS",
               "BENIGN_BLOCK_SECONDS", "NEAR_ATTACK_SECONDS", "MIN_USABLE_WINDOWS_PER_RUN"]


def main() -> None:
    start = time.time()
    log = io.read_attack_log()
    parts, pieces = [], 0
    for flows in io.iter_artifact(config.FLOWS_CLEAN, labeling.FLOW_COLUMNS):
        flows = windows.assign(flows)
        pieces += len(flows)
        parts.append(labeling.window_counts(flows))
    labeled = labeling.label_windows(labeling.combine_counts(parts), log)
    labeling.check_windows(labeled, log)

    usable = labeled[labeled.status.isin(list(config.USABLE_STATUSES))]
    summary = {
        "windows": len(labeled),
        "flows": int(labeled.n_flows.sum()),
        "status": labeled.status.value_counts().to_dict(),
        "usable_by_subclass": usable.subclass.value_counts().to_dict(),
        "weak_by_subclass": usable[usable.status == config.Status.OK_WEAK].subclass.value_counts().to_dict(),
        "benign_near_attack": int(usable[usable.subclass == config.Subclass.BENIGN].near_attack.sum()),
        "usable_by_label": {str(k): int(v) for k, v in usable.label.value_counts().items()},
    }
    io.write_artifact(labeled, config.WINDOWS_LABELED, script="scripts/run_label.py",
                      config_keys=CONFIG_KEYS, inputs=(config.FLOWS_CLEAN,),
                      notes={**summary, "window_assignment": config.WINDOW_ASSIGNMENT,
                             "empty_windows": "windows with no flow at all have no row"})

    config.TABLES.mkdir(parents=True, exist_ok=True)
    pd.crosstab(labeled.subclass, labeled.status).to_csv(config.TABLES / "label_subclass_status.csv")
    per_run = pd.crosstab(usable[usable.run_id != labeling.NO_RUN].run_id, usable.status)
    per_run.to_csv(config.TABLES / "label_per_run.csv")
    # Under `start` every flow is one row. Under `spread` a flow is one row per window it touches.
    if labeled.n_flows.sum() != pieces:
        raise ValueError("flows were lost between clean flows and windows")
    if config.WINDOW_ASSIGNMENT == "start" and pieces != io.read_meta(config.FLOWS_CLEAN)["rows"]:
        raise ValueError("start assignment must keep exactly one row per clean flow")
    print(f"wrote {config.WINDOWS_LABELED.name} in {time.time() - start:.0f}s ({config.WINDOW_ASSIGNMENT})")
    for k, v in summary.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
