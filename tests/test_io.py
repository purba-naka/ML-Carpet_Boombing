import pandas as pd
import pytest

from carpet import config, io


def _write(path, keys, inputs=()):
    io.write_artifact(pd.DataFrame({"a": [1, 2]}), path, script="test", config_keys=keys, inputs=inputs)


def test_roundtrip_and_meta(tmp_path):
    p = tmp_path / "x.parquet"
    _write(p, ["SEED"])
    assert io.read_artifact(p)["a"].tolist() == [1, 2]
    meta = io.read_meta(p)
    assert meta["rows"] == 2 and meta["config"] == {"SEED": config.SEED}


def test_missing_meta_is_refused(tmp_path):
    p = tmp_path / "x.parquet"
    _write(p, ["SEED"])
    p.with_suffix(".meta.json").unlink()
    with pytest.raises(FileNotFoundError):
        io.read_artifact(p)


def test_changed_config_makes_artifact_stale(tmp_path, monkeypatch):
    p = tmp_path / "x.parquet"
    _write(p, ["WINDOW_SECONDS"])
    monkeypatch.setattr(config, "WINDOW_SECONDS", 30)
    with pytest.raises(RuntimeError, match="WINDOW_SECONDS"):
        io.read_artifact(p)


def test_stale_input_poisons_everything_downstream(tmp_path, monkeypatch):
    up, down = tmp_path / "up.parquet", tmp_path / "down.parquet"
    _write(up, ["WINDOW_SECONDS"])
    _write(down, ["SEED"], inputs=(up,))
    monkeypatch.setattr(config, "WINDOW_SECONDS", 30)
    with pytest.raises(RuntimeError, match="WINDOW_SECONDS"):
        io.read_artifact(down)


def test_dict_config_survives_meta_roundtrip(tmp_path):
    p = tmp_path / "x.parquet"
    _write(p, ["CAPTURE_SETTINGS", "HOLDOUT_RUNS", "LOG_DOMAINS"])
    assert io.stale_keys(io.read_meta(p)) == []


def test_type_flows_parses_timestamp_to_epoch():
    raw = pd.DataFrame({"Flow ID": ["a"], "Src IP": ["1.1.1.1"], "Dst IP": ["2.2.2.2"],
                        "Timestamp": ["02/11/2026 09:00:04 AM"], "Label": ["NeedManualLabel"]})
    out = io.type_flows(raw, "S1", 1)
    assert out.ts.tolist() == [1793610004] and out.session.tolist() == [1] and out.capture.tolist() == ["S1"]
    assert "Label" not in out and "Timestamp" not in out


def test_type_flows_refuses_bad_timestamp():
    raw = pd.DataFrame({"Flow ID": ["a"], "Src IP": ["x"], "Dst IP": ["y"], "Timestamp": ["garbage"]})
    with pytest.raises(ValueError, match="unparsable"):
        io.type_flows(raw, "S1", 1)


def test_stream_write_leaves_no_file_when_the_source_fails(tmp_path):
    def frames():
        yield pd.DataFrame({"a": [1]})
        raise RuntimeError("boom")

    p = tmp_path / "x.parquet"
    with pytest.raises(RuntimeError):
        io.write_parquet_stream(p, frames())
    assert list(tmp_path.iterdir()) == []


def test_stream_write_keeps_all_chunks(tmp_path):
    p = tmp_path / "x.parquet"
    rows, cols = io.write_parquet_stream(p, (pd.DataFrame({"a": [i, i]}) for i in range(3)))
    assert rows == 6 and cols == ["a"] and pd.read_parquet(p)["a"].tolist() == [0, 0, 1, 1, 2, 2]


def test_unknown_config_key_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        _write(tmp_path / "x.parquet", ["NOT_A_KEY"])


def test_forbidden_features_cover_label_side_columns():
    assert {"attacker_flows", "run_id", "group", "status", "label"} <= config.FORBIDDEN_FEATURES


S1_LOG = ("run_id,scenario,subnet,dst,start_ts,end_ts,interval_us,payload,n_src,attacker_ip\n"
          "C1,carpet-low,198.51.100.0/24,32,1000,1900,10000,0,1,192.168.1.65\n"
          "F1,focused,198.51.100.0/24,1,2000,2900,1000,0,multi,192.168.1.65\n")
V2_HEADER = ",".join(io.LOG_COLUMNS) + "\n"


def _v2_row(run_id, start, end, scenario="carpet", proto="tcp", capture="A"):
    return (f"{run_id},{scenario},203.0.113.0/24,16,{start},{end},500,pps,0,multi,192.168.1.65,"
            f"{proto},80,uniform,fixed,normal,{capture}\n")


def _logs(monkeypatch, tmp_path, **texts):
    files = {}
    for capture, text in texts.items():
        path = tmp_path / f"{capture}.csv"
        path.write_text(text, encoding="utf-8")
        files[capture] = {"csvs": {}, "attack_log": path}
    monkeypatch.setattr(config, "CAPTURE_FILES", files)
    monkeypatch.setattr(config, "ACTIVE_CAPTURES", tuple(texts))


def test_s1_log_is_read_onto_the_v2_columns(monkeypatch, tmp_path):
    _logs(monkeypatch, tmp_path, S1=S1_LOG)
    log = io.read_attack_log()
    assert list(log.columns) == io.LOG_COLUMNS
    c1, f1 = log.set_index("run_id").loc["C1"], log.set_index("run_id").loc["F1"]
    assert (c1.rate, c1.rate_unit, c1.proto, c1.dst_port, c1.capture) == (10000, "us_interval", "udp", 53, "S1")
    assert c1.spread == "uniform" and f1.spread == "-" and f1.n_src == "multi"


def test_registry_id_wins_over_the_capture_column_of_the_file(monkeypatch, tmp_path):
    _logs(monkeypatch, tmp_path, TA=V2_HEADER + _v2_row("TEST1", 100, 280, capture="A"))
    assert io.read_attack_log().capture.tolist() == ["TA"]


def test_two_logs_stack_and_a_run_id_used_twice_is_refused(monkeypatch, tmp_path):
    _logs(monkeypatch, tmp_path, S1=S1_LOG, A=V2_HEADER + _v2_row("A-C01", 5000, 5720))
    assert io.read_attack_log().groupby("capture").size().to_dict() == {"A": 1, "S1": 2}
    _logs(monkeypatch, tmp_path, S1=S1_LOG, A=V2_HEADER + _v2_row("C1", 5000, 5720))
    with pytest.raises(ValueError, match="duplicate run_id"):
        io.read_attack_log()


def test_overlapping_runs_and_unknown_values_are_refused(monkeypatch, tmp_path):
    text = V2_HEADER + _v2_row("A-C01", 100, 820) + _v2_row("A-C02", 800, 1520, proto="icmp")
    _logs(monkeypatch, tmp_path, A=text)
    with pytest.raises(ValueError) as err:
        io.read_attack_log()
    assert "overlapping runs" in str(err.value) and "icmp" in str(err.value)


def test_a_log_with_other_columns_is_refused(monkeypatch, tmp_path):
    _logs(monkeypatch, tmp_path, A="run_id,start_ts,end_ts\nX,1,2\n")
    with pytest.raises(ValueError, match="match neither"):
        io.read_attack_log()


def test_count_csv_rows_with_and_without_a_final_newline(tmp_path):
    p = tmp_path / "x.csv"
    p.write_bytes(b"a,b\n1,2\n3,4\n")
    assert io.count_csv_rows(p) == 2
    p.write_bytes(b"a,b\n1,2\n3,4")
    assert io.count_csv_rows(p) == 2
