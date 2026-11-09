"""Flow cleaning. Works per chunk, so the full 9.7M rows never sit in memory at once."""
import numpy as np
import pandas as pd

from carpet import config

NON_FEATURE_COLUMNS = ("Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "ts", "session")


def feature_columns(columns: list[str]) -> list[str]:
    return [c for c in columns if c not in NON_FEATURE_COLUMNS]


def clean_chunk(flows: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Drop flows outside the victim /24, blank impossible values. Returns (clean, counts).

    Every CICFlowMeter feature is a count, a size, a time or a rate, so none can be
    negative or infinite. Seeing one means the extractor tripped (zero duration gives
    inf rates, out of order packets give negative IAT). We keep the flow, because
    dropping it would quietly shrink the packet totals of its window, and only blank
    the broken cell. The model pipeline imputes it later, inside the train fold.
    """
    in_victim = flows["Dst IP"].str.startswith(config.VICTIM_PREFIX)
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
