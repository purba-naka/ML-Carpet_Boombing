import pandas as pd
import pytest

from carpet import config, io, labeling
from carpet.config import Status, Subclass

T0 = 1_800_000_000 // 60 * 60  # a whole minute, far from any real run


def _log(*runs):
    rows = [dict(run_id=r, scenario=s, subnet="198.51.100.0/24", dst=16, start_ts=T0 + a, end_ts=T0 + b,
                 rate=1000, rate_unit="pps", payload=0, n_src="1", attacker_ip="192.168.1.65", proto="udp",
                 dst_port=53, spread="uniform", sport_mode="fixed", background="normal", capture="S1")
            for r, s, a, b in runs]
    return pd.DataFrame(rows, columns=io.LOG_COLUMNS)


def _counts(minutes, attackers, attacker_pkts=None):
    return pd.DataFrame({"subnet": "198.51.100.0/24", "w": [T0 + 60 * m for m in minutes], "capture": "S1",
                         "n_flows": 100, "n_pkts": 200, "attacker_flows": attackers,
                         "attacker_pkts": attacker_pkts if attacker_pkts is not None else attackers})


def _by_minute(windows):
    return windows.set_index((windows.w - T0) // 60)


def test_carpet_run_inside_edge_and_neighbours():
    # Run from minute 5:30 to 10:30. Minute 5 and 10 cross the edges, 4 and 11 are the buffer.
    log = _log(("C1", "carpet-low", 330, 630))
    out = _by_minute(labeling.label_windows(_counts(range(0, 15), [0] * 6 + [500] * 3 + [0] * 6), log))
    assert out.loc[[6, 7, 8], "label"].tolist() == [1, 1, 1]
    assert (out.loc[6:8, "status"] == Status.OK).all() and out.loc[9, "status"] == Status.OK_WEAK
    assert out.loc[[5, 10], "status"].tolist() == [Status.EXCLUDE_BOUNDARY] * 2
    assert out.loc[[4, 11], "status"].tolist() == [Status.EXCLUDE_BOUNDARY] * 2
    assert out.loc[[0, 3, 12], "status"].tolist() == [Status.OK] * 3
    assert (out.loc[[0, 3, 12], "subclass"] == Subclass.BENIGN).all()
    assert out.loc[6, "group"] == "C1" and out.loc[0, "group"].startswith("B")


def test_focused_run_is_negative():
    out = _by_minute(labeling.label_windows(_counts(range(0, 5), [9] * 5), _log(("F1", "focused", 0, 300))))
    assert out.loc[1, "subclass"] == Subclass.FOCUSED and out.loc[1, "label"] == 0


def test_unlogged_bursts_go_with_the_quiet_minutes_between_them():
    attackers = [0] * 10 + [999, 0, 0, 999] + [0] * 10
    out = _by_minute(labeling.label_windows(_counts(range(0, 24), attackers), _log()))
    assert (out.loc[9:14, "status"] == Status.EXCLUDE_UNLOGGED).all()
    assert (out.loc[9:14, "subclass"] == Subclass.UNLOGGED).all()
    assert out.loc[8, "status"] == Status.OK and out.loc[15, "status"] == Status.OK


def test_small_attacker_trickle_outside_runs_stays_benign():
    out = labeling.label_windows(_counts(range(0, 3), [1, 50, 0]), _log())
    assert (out.status == Status.OK).all() and (out.label == 0).all()


def test_check_windows_catches_attacker_traffic_in_benign():
    log = _log(("C1", "carpet-low", 600, 1260))
    windows = labeling.label_windows(_counts(range(0, 30), [0] * 30), log)
    windows.loc[0, "attacker_flows"] = 999
    try:
        labeling.check_windows(windows, log)
    except ValueError as e:
        assert "attacker traffic" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_is_attacker_catches_spoofed_dns_but_not_lan_or_resolver():
    flows = pd.DataFrame({"Src IP": ["192.168.1.65", "77.1.2.3", "198.51.100.199", "8.6.0.1", "77.1.2.3"],
                          "Dst Port": [80, 53, 53, 53, 443], "Protocol": [6, 17, 17, 17, 17], "capture": "S1"})
    assert labeling.is_attacker(flows).tolist() == [True, True, False, False, False]


def test_near_attack_marks_only_benign_windows_close_to_an_attack(monkeypatch):
    monkeypatch.setattr(labeling.config, "NEAR_ATTACK_SECONDS", 180)
    log = _log(("C1", "carpet-low", 600, 1260))
    out = _by_minute(labeling.label_windows(_counts(range(0, 40), [0] * 40), log))
    benign = out[out.subclass == Subclass.BENIGN]
    assert benign.loc[[0, 1], "near_attack"].tolist() == [False, False]
    assert bool(benign.loc[6, "near_attack"]) is False  # boundary buffer window is excluded, not benign
    assert bool(benign.loc[24, "near_attack"]) and not bool(benign.loc[30, "near_attack"])
    assert not out[out.subclass != Subclass.BENIGN].near_attack.any()


def _two_captures(monkeypatch):
    monkeypatch.setattr(config, "CAPTURE_SETTINGS", {c: config.CAPTURES[c] for c in ("S1", "A")})


def test_spoofed_tcp_syn_counts_as_attacker_in_new_captures_but_not_in_s1(monkeypatch):
    _two_captures(monkeypatch)
    flows = pd.DataFrame({"Src IP": ["100.80.27.120", "100.80.27.120", "198.51.100.199", "192.168.1.65"],
                          "Dst Port": [80, 80, 80, 123], "Protocol": [6, 6, 6, 17],
                          "capture": ["A", "S1", "A", "A"]})
    assert labeling.is_attacker(flows).tolist() == [True, False, False, True]


def test_benign_hard_run_is_negative_never_weak_and_not_an_attack_time(monkeypatch):
    monkeypatch.setattr(labeling.config, "NEAR_ATTACK_SECONDS", 180)
    log = _log(("A-W01", "benign-wide", 600, 1320))
    out = _by_minute(labeling.label_windows(_counts(range(0, 40), [0] * 40), log))
    inside = out.loc[11:21]
    assert (inside.subclass == Subclass.BENIGN_HARD).all() and (inside.label == 0).all()
    assert (inside.status == Status.OK).all() and (inside.group == "A-W01").all()
    assert (inside.run_scenario == "benign-wide").all()
    assert not out.near_attack.any()


def test_test_runs_are_excluded_whatever_their_scenario_says():
    log = _log(("TEST1", "carpet", 600, 780), ("RETEST1", "carpet", 1200, 1380))
    out = _by_minute(labeling.label_windows(_counts(range(0, 30), [0] * 30), log))
    assert out.loc[[10, 12, 20, 22], "status"].tolist() == [Status.EXCLUDE_TEST] * 4


def test_unknown_scenario_is_refused():
    with pytest.raises(ValueError, match="unknown scenarios"):
        labeling.label_windows(_counts(range(0, 3), [0] * 3), _log(("X1", "ddos-other", 0, 120)))


def test_check_windows_catches_attacker_traffic_inside_a_benign_hard_run():
    log = _log(("A-W01", "benign-wide", 600, 1320))
    windows = labeling.label_windows(_counts(range(0, 40), [0] * 40), log)
    windows.loc[(windows.w - T0) // 60 == 15, "attacker_flows"] = 999
    with pytest.raises(ValueError, match="benign_hard windows carry attacker traffic"):
        labeling.check_windows(windows, log)


def test_a_window_seen_in_two_captures_is_refused():
    a = _counts([0], [0]).assign(capture="S1")
    b = _counts([0], [0]).assign(capture="A")
    with pytest.raises(ValueError, match="more than one capture"):
        labeling.combine_counts([a, b])


def test_log_factors_never_reach_a_feature_set():
    factor_columns = {f"run_{f}" for f in labeling.RUN_FACTORS} | {"capture"}
    assert factor_columns <= config.FORBIDDEN_FEATURES
    assert not factor_columns & {f for cols in config.FEATURE_SETS.values() for f in cols}


def test_few_flows_with_many_attacker_packets_outside_runs_are_unlogged():
    attackers = [0] * 10 + [28, 28] + [0] * 10
    packets = [0] * 10 + [20706, 24294] + [0] * 10
    out = _by_minute(labeling.label_windows(_counts(range(0, 22), attackers, packets), _log()))
    assert (out.loc[10:11, "status"] == Status.EXCLUDE_UNLOGGED).all()
    assert out.loc[0, "status"] == Status.OK and out.loc[21, "status"] == Status.OK


def test_a_small_attacker_packet_trickle_stays_benign():
    out = labeling.label_windows(_counts(range(0, 3), [5, 5, 5], [31, 300, 0]), _log())
    assert (out.status == Status.OK).all()
