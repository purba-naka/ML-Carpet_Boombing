import numpy as np
import pandas as pd

from carpet import clean, config


def _flows():
    return pd.DataFrame({
        "Src IP": ["1.1.1.1"] * 4,
        "Dst IP": ["198.51.100.10", "198.51.100.11", "10.0.0.1", "198.51.100.12"],
        "ts": [1, 2, 3, 4],
        "capture": ["S1"] * 4,
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


def test_victim_subnets_follow_the_capture_of_each_flow(monkeypatch):
    monkeypatch.setattr(config, "CAPTURE_SETTINGS", {c: config.CAPTURES[c] for c in ("S1", "TA")})
    flows = pd.DataFrame({"Dst IP": ["203.0.113.10", "203.0.113.10", "198.51.100.5"],
                          "capture": ["S1", "TA", "TA"]})
    assert clean.in_victim_subnets(flows).tolist() == [False, True, True]


def test_repeats_are_found_inside_a_chunk_and_against_earlier_chunks():
    seen = np.empty(0, np.uint64)
    first = pd.DataFrame({"a": [1, 2, 1], "capture": ["TA"] * 3})
    repeat, seen = clean.find_repeats(first, seen)
    assert repeat.tolist() == [False, False, True]
    second = pd.DataFrame({"a": [2, 3], "capture": ["TA", "TA"]})
    repeat, seen = clean.find_repeats(second, seen)
    assert repeat.tolist() == [True, False]
    other_capture = pd.DataFrame({"a": [3], "capture": ["A"]})
    assert clean.find_repeats(other_capture, seen)[0].tolist() == [False]
