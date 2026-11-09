"""The one modeling table: usable windows with labels, split and every feature, one row each."""
import pandas as pd

from carpet import config, io, split

META = ["subnet", "w", "window_start", "run_id", "group", "subclass", "label", "status", "near_attack"]


def load_table() -> pd.DataFrame:
    """All usable windows, hold-out included. Callers cut by `partition` themselves."""
    windows = io.read_artifact(config.WINDOWS_LABELED)
    sp = io.read_artifact(config.SPLIT)
    agg = io.read_artifact(config.FEATURES_AGG)
    flow = io.read_artifact(config.FEATURES_FLOW)
    artifact = io.read_artifact(config.FEATURES_ARTIFACT)
    key = ["subnet", "w"]
    df = (sp.merge(windows[META], on=key, validate="1:1")
          .merge(agg, on=key, validate="1:1").merge(flow, on=key, validate="1:1")
          .merge(artifact, on=key, validate="1:1"))
    if len(df) != len(sp):
        raise ValueError(f"table lost rows: split {len(sp)} -> table {len(df)}")
    return df


def trainval(df: pd.DataFrame) -> pd.DataFrame:
    """The only way modeling code gets rows: the hold-out never passes through here."""
    out = df[df.partition == split.TRAINVAL].reset_index(drop=True)
    if out.group.isin(config.HOLDOUT_RUNS).any():
        raise ValueError("hold-out run leaked into trainval")
    return out
