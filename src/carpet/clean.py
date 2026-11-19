"""Flow cleaning. Works per chunk, so the full 9.7M rows never sit in memory at once."""
import numpy as np
import pandas as pd

from carpet import config

NON_FEATURE_COLUMNS = ("Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "ts", "session",
                       "capture")


def feature_columns(columns: list[str]) -> list[str]:
    return [c for c in columns if c not in NON_FEATURE_COLUMNS]


def find_repeats(flows: pd.DataFrame, seen: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Mask of exact duplicate rows (D10), also against earlier chunks. Returns (repeat, seen).

    `seen` holds the sorted row hashes of every earlier chunk. A row repeats when its hash is
    already there or appeared earlier in this chunk. Overlapping capture files (a restart that
    writes the same minute twice) are the known cause.
    """
    h = pd.util.hash_pandas_object(flows, index=False).to_numpy()
    repeat = pd.Series(h).duplicated().to_numpy() | np.isin(h, seen)
    return repeat, np.union1d(seen, h)


def in_victim_subnets(flows: pd.DataFrame, settings: dict | None = None) -> pd.Series:
    """True where the destination sits in a victim subnet of the flow's own capture.

    `settings` defaults to the active captures; the capture validator passes its own.
    """
    settings = settings or config.CAPTURE_SETTINGS
    keep = pd.Series(False, index=flows.index)
    for capture in flows["capture"].unique():
        prefixes = tuple(settings[capture]["victim_prefixes"])
        keep |= (flows["capture"] == capture) & flows["Dst IP"].str.startswith(prefixes)
    return keep


def clean_chunk(flows: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Drop flows outside the victim subnets, blank impossible values. Returns (clean, counts).

    Every CICFlowMeter feature is a count, a size, a time or a rate, so none can be
    negative or infinite. Seeing one means the extractor tripped (zero duration gives
    inf rates, out of order packets give negative IAT). We keep the flow, because
    dropping it would quietly shrink the packet totals of its window, and only blank
    the broken cell. The model pipeline imputes it later, inside the train fold.
    """
    in_victim = in_victim_subnets(flows)
    out = flows[in_victim].copy()
    cols = feature_columns(list(out.columns))
    values = out[cols]
    inf = np.isinf(values)
    neg = values < 0
    out[cols] = values.mask(inf | neg)
    counts = {
        "rows_in": len(flows),
        "rows_dropped_outside_victim": int((~in_victim).sum()),
        "rows_out": len(out),
        "rows_with_blanked_cell": int((inf | neg).any(axis=1).sum()),
        "inf_cells": inf.sum().to_dict(),
        "negative_cells": neg.sum().to_dict(),
        "nan_cells_before": values.isna().sum().to_dict(),
    }
    return out, counts
