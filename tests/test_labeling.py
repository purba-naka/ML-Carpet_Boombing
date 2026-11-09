import pandas as pd

from carpet import io, labeling
from carpet.config import Status, Subclass

T0 = 1_800_000_000 // 60 * 60  # a whole minute, far from any real run


def _log(*runs):
    rows = [dict(run_id=r, scenario=s, subnet="198.51.100.0/24", dst=16, start_ts=T0 + a, end_ts=T0 + b,
                 interval_us=1000, payload=0, n_src="1", attacker_ip="192.168.1.65") for r, s, a, b in runs]
    return pd.DataFrame(rows, columns=io.LOG_COLUMNS)


def _counts(minutes, attackers):
    return pd.DataFrame({"subnet": "198.51.100.0/24", "w": [T0 + 60 * m for m in minutes],
                         "n_flows": 100, "n_pkts": 200, "attacker_flows": attackers})


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
                          "Dst Port": [80, 53, 53, 53, 443], "Protocol": [6, 17, 17, 17, 17]})
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
