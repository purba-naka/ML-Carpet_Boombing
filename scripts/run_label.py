"""Phase 3: clean flows to one labeled row per (subnet, 60 s window)."""
import time

import pandas as pd

from carpet import config, io, labeling

CONFIG_KEYS = ["WINDOW_SECONDS", "VICTIM_PREFIX", "ATTACKER_IP", "BENIGN_SRC_EXTRA", "DNS_PORT", "UDP",
               "TEST_RUN", "UNLOGGED_MIN_FLOWS", "UNLOGGED_GAP_SECONDS", "BOUNDARY_BUFFER_SECONDS",
               "BENIGN_BLOCK_SECONDS", "NEAR_ATTACK_SECONDS", "MIN_USABLE_WINDOWS_PER_RUN"]


def main() -> None:
    start = time.time()
    log = io.read_attack_log()
    parts = [labeling.window_counts(f) for f in io.iter_artifact(config.FLOWS_CLEAN, labeling.FLOW_COLUMNS)]
    counts = labeling.combine_counts(parts)
    windows = labeling.label_windows(counts, log)
    labeling.check_windows(windows, log)

    usable = windows[windows.status.isin(list(config.USABLE_STATUSES))]
    summary = {
        "windows": len(windows),
        "flows": int(windows.n_flows.sum()),
        "status": windows.status.value_counts().to_dict(),
        "usable_by_subclass": usable.subclass.value_counts().to_dict(),
        "weak_by_subclass": usable[usable.status == config.Status.OK_WEAK].subclass.value_counts().to_dict(),
        "benign_near_attack": int(usable[usable.subclass == config.Subclass.BENIGN].near_attack.sum()),
        "usable_by_label": {str(k): int(v) for k, v in usable.label.value_counts().items()},
    }
    io.write_artifact(windows, config.WINDOWS_LABELED, script="scripts/run_label.py",
                      config_keys=CONFIG_KEYS, inputs=(config.FLOWS_CLEAN,),
                      notes={**summary, "empty_windows": "windows with no flow at all have no row"})

    config.TABLES.mkdir(parents=True, exist_ok=True)
    pd.crosstab(windows.subclass, windows.status).to_csv(config.TABLES / "label_subclass_status.csv")
    per_run = pd.crosstab(usable[usable.run_id != labeling.NO_RUN].run_id, usable.status)
    per_run.to_csv(config.TABLES / "label_per_run.csv")
    if windows.n_flows.sum() != io.read_meta(config.FLOWS_CLEAN)["rows"]:
        raise ValueError("flows were lost between clean flows and windows")
    print(f"wrote {config.WINDOWS_LABELED.name} in {time.time() - start:.0f}s")
    for k, v in summary.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
