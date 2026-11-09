"""Window aggregate features (PDF 3.2.3.2). Volume is packets (D13). No label is read here."""
import numpy as np
import pandas as pd

from carpet import config
from carpet.windows import KEY, window_keys

FLOW_COLUMNS = ["Src IP", "Dst IP", "Protocol", "ts", "Total Fwd Packet", "Total Length of Fwd Packet"]
PAIR_KEY = [*KEY, "src", "dst"]

AGG_FEATURES = list(config.AGG_FEATURES)


def _hash_ip(ips: pd.Series) -> np.ndarray:
    """64 bit hash of an IP string. Same value in every chunk, 4 bytes of RAM less than a string
    per row, and a collision among 10M addresses is about 1 in 400,000."""
    return pd.util.hash_array(ips.to_numpy(dtype=object))


def pair_counts(flows: pd.DataFrame) -> pd.DataFrame:
    """Per (subnet, w, src, dst) sums of one chunk. Sum chunks with combine_pairs.

    Keeping the pair level is what lets unique sources and unique pairs come out exact
    after chunks are merged. Counting them per chunk would add up the same source twice.
    """
    pkts = flows["Total Fwd Packet"].astype("int64")
    pairs = window_keys(flows).assign(
        src=_hash_ip(flows["Src IP"]), dst=_hash_ip(flows["Dst IP"]), flows=1, pkts=pkts,
        bytes=flows["Total Length of Fwd Packet"].astype("int64"),
        udp_pkts=pkts.where(flows["Protocol"] == config.UDP, 0))
    return pairs.groupby(PAIR_KEY, as_index=False).sum()


def combine_pairs(parts: list[pd.DataFrame]) -> pd.DataFrame:
    return pd.concat(parts, ignore_index=True).groupby(PAIR_KEY, as_index=False).sum()


def flow_summary(flows: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """Per window mean, std and max of flow-level columns, named `<col>__mean` and so on.

    Needs all flows of the columns at once, so it is exact. Callers pass a few columns
    at a time (the full 66 columns would be 5 GB). std is the population std (ddof 0),
    so a window with a single flow gets 0 instead of NaN.
    """
    g = flows[columns].groupby([window_keys(flows)[k] for k in KEY])
    parts = [g.agg(stat).add_suffix(f"__{stat}") for stat in ("mean", "max")]
    parts.append(g.std(ddof=0).add_suffix("__std"))
    return pd.concat(parts, axis=1).reset_index()


def build_features(pairs: pd.DataFrame) -> pd.DataFrame:
    """One row per (subnet, w) with AGG_FEATURES."""
    per_dst = pairs.groupby([*KEY, "dst"], as_index=False)[["pkts", "flows", "bytes", "udp_pkts"]].sum()
    total = per_dst.groupby(KEY)["pkts"].transform("sum")
    if (total <= 0).any():
        raise ValueError(f"{int((total <= 0).groupby([per_dst.subnet, per_dst.w]).first().sum())} "
                         "windows have zero packets, entropy is undefined")
    p = per_dst["pkts"] / total
    # 0 * log(0) is 0 by convention, and the np.where keeps the log of 0 from warning.
    per_dst["h"] = -(p * np.log2(np.where(p > 0, p, 1.0)))

    g = per_dst.groupby(KEY)
    out = pd.DataFrame({
        "n_unique_dst": g.size(),
        "dst_entropy": g["h"].sum(),
        "total_pkts": g["pkts"].sum(),
        "total_bytes": g["bytes"].sum(),
        "max_pkts_per_dst": g["pkts"].max(),
        "n_flows": g["flows"].sum(),
        "udp_pkts": g["udp_pkts"].sum(),
    })
    pg = pairs.groupby(KEY)
    out["n_unique_src"] = pg["src"].nunique()
    out["n_src_dst_pairs"] = pg.size()
    out["dst_entropy_norm"] = np.where(out.n_unique_dst > 1, out.dst_entropy / np.log2(out.n_unique_dst.clip(lower=2)), 0.0)
    out["concentration_ratio"] = out.max_pkts_per_dst / out.total_pkts
    out["mean_pkts_per_dst"] = out.total_pkts / out.n_unique_dst
    out["udp_ratio"] = out.udp_pkts / out.total_pkts
    return out[AGG_FEATURES].reset_index()
