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
    _write(p, ["RAW_ROWS_EXPECTED", "HOLDOUT_RUNS"])
    assert io.stale_keys(io.read_meta(p)) == []


def test_type_flows_parses_timestamp_to_epoch():
    raw = pd.DataFrame({"Flow ID": ["a"], "Src IP": ["1.1.1.1"], "Dst IP": ["2.2.2.2"],
                        "Timestamp": ["02/11/2026 09:00:04 AM"], "Label": ["NeedManualLabel"]})
    out = io.type_flows(raw, 1)
    assert out.ts.tolist() == [1793610004] and out.session.tolist() == [1]
    assert "Label" not in out and "Timestamp" not in out


def test_type_flows_refuses_bad_timestamp():
    raw = pd.DataFrame({"Flow ID": ["a"], "Src IP": ["x"], "Dst IP": ["y"], "Timestamp": ["garbage"]})
    with pytest.raises(ValueError, match="unparsable"):
        io.type_flows(raw, 1)


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
