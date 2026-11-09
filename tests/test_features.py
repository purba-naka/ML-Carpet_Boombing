import numpy as np
import pandas as pd

from carpet import features


def _flows(rows):
    """rows: (src, dst_last_octet, pkts, protocol, ts)."""
    return pd.DataFrame({
        "Src IP": [r[0] for r in rows], "Dst IP": [f"198.51.100.{r[1]}" for r in rows],
        "Protocol": [r[3] for r in rows], "ts": [r[4] for r in rows],
        "Total Fwd Packet": [r[2] for r in rows], "Total Length of Fwd Packet": [r[2] * 10 for r in rows]})


def _feat(rows, chunks=1):
    flows = _flows(rows)
    parts = [features.pair_counts(flows.iloc[i::chunks]) for i in range(chunks)]
    return features.build_features(features.combine_pairs(parts)).iloc[0]


def test_even_spread_has_entropy_log2_n_and_concentration_one_over_n():
    f = _feat([("1.1.1.1", d, 5, 17, 100) for d in range(1, 9)])
    assert f.n_unique_dst == 8 and np.isclose(f.dst_entropy, 3.0)
    assert np.isclose(f.dst_entropy_norm, 1.0) and np.isclose(f.concentration_ratio, 1 / 8)


def test_single_host_has_zero_entropy_and_concentration_one():
    f = _feat([("1.1.1.1", 7, 50, 17, 100), ("2.2.2.2", 7, 5, 17, 110)])
    assert f.dst_entropy == 0 and f.dst_entropy_norm == 0 and f.concentration_ratio == 1


def test_entropy_weighs_packets_not_flows():
    f = _feat([("1.1.1.1", 1, 99, 17, 100)] + [("1.1.1.1", 2, 1, 17, 100)])
    assert 0 < f.dst_entropy < 0.1


def test_unique_sources_are_exact_when_a_source_spans_chunks():
    rows = [("1.1.1.1", 1, 1, 17, 100)] * 3 + [("2.2.2.2", 2, 1, 6, 100)]
    f = _feat(rows, chunks=4)
    assert f.n_unique_src == 2 and f.n_src_dst_pairs == 2 and f.n_flows == 4
    assert np.isclose(f.udp_ratio, 3 / 4)


def test_one_row_per_window():
    flows = _flows([("1.1.1.1", 1, 1, 17, 100), ("1.1.1.1", 1, 1, 17, 160)])
    out = features.build_features(features.pair_counts(flows))
    assert out.w.tolist() == [60, 120]


def test_flow_summary_is_per_window_and_single_flow_std_is_zero():
    flows = _flows([("1.1.1.1", 1, 1, 17, 100), ("1.1.1.1", 1, 1, 17, 110), ("1.1.1.1", 1, 1, 17, 170)])
    flows["Flow Duration"] = [2.0, 4.0, 9.0]
    out = features.flow_summary(flows, ["Flow Duration"]).set_index("w")
    assert out.loc[60, "Flow Duration__mean"] == 3.0 and out.loc[60, "Flow Duration__max"] == 4.0
    assert np.isclose(out.loc[60, "Flow Duration__std"], 1.0) and out.loc[120, "Flow Duration__std"] == 0.0


def test_feature_sets_contain_no_forbidden_column_and_flow_set_extends_agg():
    from carpet import config
    for name, cols in config.FEATURE_SETS.items():
        assert not set(cols) & config.FORBIDDEN_FEATURES, name
        assert len(cols) == len(set(cols)), f"duplicate columns in {name}"
    assert set(config.FEATURE_SETS["agg"]) < set(config.FEATURE_SETS["agg_flow"])
    assert len(config.FLOW_FEATURES) == 3 * len(config.FLOW_SUMMARY_COLUMNS)
