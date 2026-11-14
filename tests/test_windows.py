import numpy as np
import pandas as pd

from carpet import windows


def _flows(rows):
    return pd.DataFrame(rows, columns=["Src IP", "Dst IP", "ts", "Flow Duration", "Total Fwd Packet",
                                       "Total Length of Fwd Packet"]).astype(
        {"ts": "int64", "Flow Duration": "float64", "Total Fwd Packet": "float64",
         "Total Length of Fwd Packet": "float64"})


def _row(ts, duration_s, pkts=100, nbytes=1000):
    return ["a", "198.51.100.5", ts, duration_s * 1e6, pkts, nbytes]


def test_flow_inside_one_window_is_left_alone():
    out = windows.spread_flows(_flows([_row(10, 30)]))
    assert len(out) == 1 and out.ts[0] == 10 and out["Total Fwd Packet"][0] == 100


def test_long_flow_is_cut_per_window_by_seconds_and_sums_exactly():
    # starts at 50 s, lasts 110 s: 10 s in window 0, 60 s in window 1, 40 s in window 2
    out = windows.spread_flows(_flows([_row(50, 110, pkts=110, nbytes=1100)]))
    assert out.ts.tolist() == [50, 60, 120] and out.is_start_piece.tolist() == [1, 0, 0]
    assert out["Total Fwd Packet"].tolist() == [10, 60, 40]
    assert out["Total Length of Fwd Packet"].sum() == 1100


def test_flow_that_ends_on_a_window_edge_makes_no_empty_piece():
    assert len(windows.spread_flows(_flows([_row(0, 60)]))) == 1
    assert len(windows.spread_flows(_flows([_row(30, 90)]))) == 2


def test_no_duration_stays_in_the_start_window_and_counts_once():
    for dur in (0, -5, np.nan):
        f = _flows([_row(75, 1)])
        f["Flow Duration"] = dur
        out = windows.spread_flows(f)
        assert len(out) == 1 and out.ts[0] == 75 and out["Total Fwd Packet"][0] == 100


def test_packets_are_conserved_over_many_random_flows():
    rng = np.random.default_rng(0)
    f = _flows([_row(int(t), float(d), pkts=int(p), nbytes=int(p) * 13)
                for t, d, p in zip(rng.integers(0, 10_000, 500), rng.uniform(0, 119, 500), rng.integers(1, 5000, 500))])
    out = windows.spread_flows(f)
    assert out["Total Fwd Packet"].sum() == f["Total Fwd Packet"].sum()
    assert out["Total Length of Fwd Packet"].sum() == f["Total Length of Fwd Packet"].sum()
    assert (out["Total Fwd Packet"] >= 0).all()
    assert out.is_start_piece.sum() == len(f)


def test_a_flow_longer_than_the_timeout_assumption_is_refused():
    try:
        windows.spread_flows(_flows([_row(0, 300)]))
    except ValueError as e:
        assert "timeout" in str(e)
    else:
        raise AssertionError("expected a refusal")
