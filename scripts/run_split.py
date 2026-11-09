"""Phase 4: fix hold-out and CV folds once, before any EDA or model sees labels."""
import pandas as pd

from carpet import config, io, split

CONFIG_KEYS = ["SEED", "HOLDOUT_RUNS", "HOLDOUT_BENIGN_FRACTION", "CV_FOLDS"]


def main() -> None:
    windows = io.read_artifact(config.WINDOWS_LABELED)
    s = split.make_split(windows)
    split.check_split(s, windows)
    io.write_artifact(s, config.SPLIT, script="scripts/run_split.py",
                      config_keys=CONFIG_KEYS, inputs=(config.WINDOWS_LABELED,))

    j = s.merge(windows, on=["subnet", "w"], validate="1:1")
    bucket = j.fold.astype(str).where(j.partition == split.TRAINVAL, split.HOLDOUT).rename("bucket")
    table = pd.crosstab(bucket, [j.subclass, j.status])
    in_run = j.run_id != "-"
    table[("runs", "")] = j[in_run].groupby(bucket[in_run]).run_id.unique().map(sorted)
    table.to_csv(config.TABLES / "split_composition.csv")
    print(f"wrote {config.SPLIT.name} rows={len(s)}")
    with pd.option_context("display.width", 200, "display.max_colwidth", 80):
        print(table)


if __name__ == "__main__":
    main()
