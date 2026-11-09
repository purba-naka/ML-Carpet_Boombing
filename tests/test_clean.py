import numpy as np
import pandas as pd

from carpet import clean


def _flows():
    return pd.DataFrame({
        "Src IP": ["1.1.1.1"] * 4,
        "Dst IP": ["198.51.100.10", "198.51.100.11", "10.0.0.1", "198.51.100.12"],
        "ts": [1, 2, 3, 4],
        "Flow Duration": [10.0, -5.0, 1.0, 0.0],
        "Flow Bytes/s": [1.0, 2.0, 3.0, np.inf],
        "Total Fwd Packet": [3.0, 1.0, 1.0, 2.0],
    })


def test_drops_only_flows_outside_victim_subnet():
    out, counts = clean.clean_chunk(_flows())
    assert out["Dst IP"].tolist() == ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
    assert counts["rows_in"] - counts["rows_dropped_outside_victim"] == counts["rows_out"] == 3


def test_broken_cells_become_nan_but_the_flow_and_its_other_cells_stay():
    out, counts = clean.clean_chunk(_flows())
    assert np.isnan(out["Flow Duration"].iloc[1]) and np.isnan(out["Flow Bytes/s"].iloc[2])
    assert out["Total Fwd Packet"].tolist() == [3.0, 1.0, 2.0]
    assert counts["rows_with_blanked_cell"] == 2
    assert not np.isinf(out.select_dtypes("number")).any().any()


def test_identity_columns_are_never_touched():
    out, _ = clean.clean_chunk(_flows())
    assert out["ts"].tolist() == [1, 2, 4]
