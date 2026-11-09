"""The window definition, once: destination /24 subnet and a tumbling window start `w` (epoch seconds)."""
import pandas as pd

from carpet import config

KEY = ["subnet", "w"]


def window_keys(flows: pd.DataFrame) -> pd.DataFrame:
    """(subnet, w) for every flow. A flow belongs to the window of its start time."""
    return pd.DataFrame({
        "subnet": flows["Dst IP"].str.rsplit(".", n=1).str[0] + ".0/24",
        "w": flows["ts"] // config.WINDOW_SECONDS * config.WINDOW_SECONDS,
    })
