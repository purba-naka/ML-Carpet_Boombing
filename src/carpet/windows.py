"""The window definition, once: destination /24 subnet and a tumbling window start `w` (epoch seconds).

D21: with `start` (the proposal) a flow belongs to the window it starts in. With `spread` a flow is cut
into one piece per window it touches, so a long flow is visible in the windows it lasts through.
"""
import numpy as np
import pandas as pd

from carpet import config

KEY = ["subnet", "w"]
SPLIT_COLUMNS = ("Total Fwd Packet", "Total Length of Fwd Packet")


def window_keys(flows: pd.DataFrame) -> pd.DataFrame:
    """(subnet, w) for every flow. Under `start` a flow belongs to the window of its start time."""
    return pd.DataFrame({
        "subnet": flows["Dst IP"].str.rsplit(".", n=1).str[0] + ".0/24",
        "w": flows["ts"] // config.WINDOW_SECONDS * config.WINDOW_SECONDS,
    })


def _split_integer(total: np.ndarray, share: np.ndarray) -> np.ndarray:
    """Split `total` over pieces in proportion to `share`, so the pieces add up to `total` exactly.

    Running totals are rounded and then differenced. Rounding each piece alone would lose or invent
    a packet here and there, and the window sums would stop matching the flow sums.
    """
    cum = np.rint(np.cumsum(share, axis=1) / np.maximum(share.sum(axis=1, keepdims=True), 1e-12)
                  * total[:, None]).astype(np.int64)
    return np.diff(cum, axis=1, prepend=0)


def spread_flows(flows: pd.DataFrame, split: tuple[str, ...] = SPLIT_COLUMNS, max_pieces: int = 4) -> pd.DataFrame:
    """One row per (flow, window it touches). The `split` columns are divided by seconds spent in each window.

    The piece in the flow's own start window keeps the real start time, the later pieces start at their
    window edge. All other columns are copied whole into every piece, and `is_start_piece` marks the first one.
    A flow without a usable duration (missing, negative or zero) stays one piece, as under `start`.

    `max_pieces` is a guard: CICFlowMeter cuts at 120 s, so a flow touches 3 windows at most. More
    means that assumption is wrong and someone should look at the data, not silently go on.
    """
    w = config.WINDOW_SECONDS
    start = flows["ts"].to_numpy(dtype=np.int64)
    dur = (flows["Flow Duration"].fillna(0).clip(lower=0) / 1e6).to_numpy()
    end = start + dur
    first = start // w
    n = np.maximum(np.ceil(end / w).astype(np.int64) - first, 1)
    if n.max() > max_pieces:
        raise ValueError(f"a flow touches {int(n.max())} windows (more than {max_pieces}): "
                         f"longest duration {dur.max():.0f} s, the 120 s timeout assumption does not hold")

    # Seconds of each flow inside each of its windows, one column per possible piece.
    k = np.arange(max_pieces)[None, :]
    lo = (first[:, None] + k) * w
    secs = np.clip(np.minimum(end[:, None], lo + w) - np.maximum(start[:, None], lo), 0, None)
    secs = np.where(k < n[:, None], secs, 0.0)
    secs[secs.sum(axis=1) == 0, 0] = 1.0          # no duration: the whole flow sits in its start window

    parts = {c: _split_integer(flows[c].fillna(0).to_numpy(dtype=np.float64), secs)
             for c in split if c in flows.columns}
    flow_idx, piece = np.nonzero(secs > 0)
    out = flows.iloc[flow_idx].reset_index(drop=True)
    out["ts"] = np.where(piece == 0, start[flow_idx], (first[flow_idx] + piece) * w)
    for c, v in parts.items():
        out[c] = v[flow_idx, piece].astype(flows[c].dtype)
    out["is_start_piece"] = (piece == 0).astype(np.int8)
    return out


def assign(flows: pd.DataFrame, split: tuple[str, ...] = SPLIT_COLUMNS) -> pd.DataFrame:
    """The flows as the pipeline should see them under the configured window assignment.

    Callers that summarise flow-level columns pass `split=()`: a piece then keeps the whole flow's
    duration, lengths and rates (D21), and only the volume used for sums is divided.
    """
    if config.WINDOW_ASSIGNMENT == "start":
        return flows
    return spread_flows(flows, split)
