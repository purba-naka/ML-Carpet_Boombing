"""Read raw data, read and write artifacts. Artifacts know which config they were built with."""
import json
import sys
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from carpet import config

LOG_COLUMNS_S1 = ["run_id", "scenario", "subnet", "dst", "start_ts", "end_ts",
                  "interval_us", "payload", "n_src", "attacker_ip"]
LOG_COLUMNS = ["run_id", "scenario", "subnet", "dst", "start_ts", "end_ts", "rate", "rate_unit",
               "payload", "n_src", "attacker_ip", "proto", "dst_port", "spread", "sport_mode",
               "background", "capture"]
LOG_INT_COLUMNS = ["start_ts", "end_ts"]
LOG_NUMBER_COLUMNS = ["dst", "rate", "payload", "dst_port"]


ID_COLUMNS = ["Flow ID", "Src IP", "Dst IP", "Timestamp"]
INT_COLUMNS = ["Src Port", "Dst Port", "Protocol"]
DROP_COLUMNS = ["Label"]


def raw_csvs() -> list[tuple[str, int, Path]]:
    """(capture, session, path) of every raw flow CSV of the active captures."""
    return [(c, int(s), p) for c in config.ACTIVE_CAPTURES for s, p in config.CAPTURE_FILES[c]["csvs"].items()]


def iter_raw_flows(usecols: list[str], dtype: dict | None = None,
                   chunksize: int = 500_000) -> Iterator[tuple[str, int, pd.DataFrame]]:
    """Yield (capture, session, chunk). Chunked because one CSV can be 0.9 to 1.5 GB."""
    for capture, session, path in raw_csvs():
        for chunk in pd.read_csv(path, usecols=usecols, dtype=dtype, chunksize=chunksize):
            yield capture, session, chunk


def raw_header() -> list[str]:
    """Header shared by all raw CSVs. Refuses to go on if any two files disagree."""
    headers = {(c, s): pd.read_csv(p, nrows=0).columns.tolist() for c, s, p in raw_csvs()}
    first = next(iter(headers.values()))
    bad = [k for k, h in headers.items() if h != first]
    if bad:
        raise ValueError(f"raw CSV header differs in (capture, session) {bad}")
    return first


def count_csv_rows(path: Path) -> int:
    """Data rows of a CSV (lines minus the header), counted on the raw bytes."""
    lines, last = 0, b"\n"
    with open(path, "rb") as f:
        while block := f.read(1 << 24):
            lines += block.count(b"\n")
            last = block[-1:]
    return lines + (last != b"\n") - 1


def raw_dtypes(header: list[str]) -> dict:
    """One fixed schema for every chunk.

    Features are all float64 on purpose. Inferring per chunk would flip a column
    from int to float the first time a chunk holds a NaN, and float32 would round
    the IAT and duration values (up to 1.2e8). float64 is exact for any integer
    below 2**53, so nothing is lost.
    """
    dtypes = {c: "float64" for c in header if c not in ID_COLUMNS + INT_COLUMNS + DROP_COLUMNS}
    dtypes.update({c: "int32" for c in INT_COLUMNS})
    dtypes.update({c: "string" for c in ID_COLUMNS})
    return dtypes


def type_flows(chunk: pd.DataFrame, capture: str, session: int) -> pd.DataFrame:
    """Raw CSV chunk to typed flows: epoch `ts` instead of the text Timestamp, plus `session` and `capture`."""
    t = pd.to_datetime(chunk["Timestamp"], format=config.TIMESTAMP_FORMAT, errors="coerce")
    if t.isna().any():
        bad = chunk.loc[t.isna(), "Timestamp"].head(3).tolist()
        raise ValueError(f"{capture} session {session}: {int(t.isna().sum())} unparsable timestamps, e.g. {bad}")
    out = chunk.drop(columns=["Timestamp", *DROP_COLUMNS], errors="ignore")
    out.insert(3, "ts", ((t - pd.Timestamp("1970-01-01")) // pd.Timedelta("1s")).astype("int64"))
    out.insert(4, "session", pd.Series(session, index=out.index, dtype="int8"))
    out.insert(5, "capture", pd.Series(capture, index=out.index, dtype="string"))
    return out


def _from_s1_log(log: pd.DataFrame) -> pd.DataFrame:
    """S1 log (10 columns) onto the v2 columns, with the values S1 was captured with.

    S1 logged the gap between packets in microseconds. It is kept as is with unit `us_interval`
    rather than turned into a rate nobody measured. Every S1 run was spoofed or plain DNS over
    UDP with a fixed source port and no concurrent hard benign traffic.
    """
    return log.drop(columns="interval_us").assign(
        rate=log.interval_us, rate_unit="us_interval", proto="udp", dst_port="53",
        spread=log.scenario.map(lambda s: "-" if s == "focused" else "uniform"),
        sport_mode="fixed", background="normal")


def read_capture_log(capture: str) -> pd.DataFrame:
    """One capture's attack log in LOG_COLUMNS, with `capture` set from the registry id.

    The registry id wins over the file's own `capture` column: the test capture TA logged its
    runs as `A`, and a rehearsal must never be mistaken for the session it rehearsed.
    """
    path = config.CAPTURE_FILES[capture]["attack_log"]
    log = pd.read_csv(path, dtype=str, keep_default_na=False)
    if list(log.columns) == LOG_COLUMNS_S1:
        log = _from_s1_log(log)
    elif list(log.columns) != LOG_COLUMNS:
        raise ValueError(f"{capture} attack_log columns {list(log.columns)} match neither "
                         f"{LOG_COLUMNS_S1} nor {LOG_COLUMNS}")
    log = log.assign(capture=capture)[LOG_COLUMNS]
    for c in LOG_INT_COLUMNS:
        log[c] = log[c].astype("int64")
    for c in LOG_NUMBER_COLUMNS:
        log[c] = pd.to_numeric(log[c], errors="coerce")
    return log


def check_attack_log(log: pd.DataFrame) -> None:
    """Refuses a log that would make labels wrong. Every broken rule is listed at once."""
    problems = []
    dup = log.run_id[log.run_id.duplicated()].tolist()
    if dup:
        problems.append(f"duplicate run_id across logs: {dup}")
    backwards = log.run_id[log.end_ts <= log.start_ts].tolist()
    if backwards:
        problems.append(f"end_ts <= start_ts in runs {backwards}")
    for capture, runs in log.sort_values("start_ts").groupby("capture"):
        ids = runs.run_id.to_numpy()
        clash = runs.start_ts.to_numpy()[1:] < runs.end_ts.to_numpy()[:-1]
        if clash.any():
            problems.append(f"{capture}: overlapping runs {list(zip(ids[:-1][clash], ids[1:][clash]))}")
    for col, allowed in config.LOG_DOMAINS.items():
        bad = sorted(set(log[col]) - set(allowed))
        if bad:
            problems.append(f"{col} has values outside {list(allowed)}: {bad}")
    if problems:
        raise ValueError("attack log refused:\n  " + "\n  ".join(problems))


def read_attack_log() -> pd.DataFrame:
    """The attack logs of every active capture, checked and stacked."""
    log = pd.concat([read_capture_log(c) for c in config.ACTIVE_CAPTURES], ignore_index=True)
    check_attack_log(log)
    return log


def write_parquet_stream(path: Path, frames: Iterable[pd.DataFrame]) -> tuple[int, list[str]]:
    """Write frames one by one into one parquet. Returns (rows, columns).

    Goes to a .tmp file and is renamed only at the end. If anything raises, even
    the generator feeding us, the .tmp is removed, so a half file never looks finished.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    writer, rows = None, 0
    try:
        for df in frames:
            table = pa.Table.from_pandas(df, preserve_index=False)
            # The first chunk pins the schema, so a later chunk can never sneak in another type.
            writer = writer or pq.ParquetWriter(tmp, table.schema)
            writer.write_table(table.cast(writer.schema))
            rows += len(df)
    except BaseException:
        if writer:
            writer.close()
        tmp.unlink(missing_ok=True)
        raise
    if writer is None:
        raise ValueError(f"no data to write to {path.name}")
    writer.close()
    tmp.replace(path)
    return rows, writer.schema.names


def iter_artifact(path: Path, columns: list[str] | None = None) -> Iterator[pd.DataFrame]:
    """Yield an artifact one row group at a time, after the same stale check as read_artifact."""
    _check_fresh(path)
    f = pq.ParquetFile(path)
    for i in range(f.num_row_groups):
        yield f.read_row_group(i, columns=columns).to_pandas()


def _meta_path(path: Path) -> Path:
    return path.with_suffix(".meta.json")


def read_meta(path: Path) -> dict:
    meta = _meta_path(path)
    if not meta.exists():
        raise FileNotFoundError(f"{path.name} has no meta file. Re-run the stage that makes it.")
    return json.loads(meta.read_text(encoding="utf-8"))


def write_artifact(df: pd.DataFrame, path: Path, *, script: str, config_keys: list[str],
                   inputs: tuple[Path, ...] = (), notes: dict | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(path, index=False)
    write_meta(path, rows=len(df), columns=list(df.columns), script=script,
               config_keys=config_keys, inputs=inputs, notes=notes)


def write_meta(path: Path, *, rows: int, columns: list[str], script: str, config_keys: list[str],
               inputs: tuple[Path, ...] = (), notes: dict | None = None) -> None:
    """Write the meta next to an already written parquet.

    The meta records the config values this stage depends on, plus everything its
    input artifacts depended on. So changing an old decision makes every
    downstream artifact refuse to load, no matter how far down it sits.
    """
    snap = config.snapshot()
    unknown = [k for k in config_keys if k not in snap]
    if unknown:
        raise ValueError(f"config_keys not in config: {unknown}")
    keys = set(config_keys)
    for p in inputs:
        keys |= set(read_meta(p)["config"])
    meta = {
        "script": script,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rows": rows,
        "columns": columns,
        "inputs": [p.name for p in inputs],
        "config": {k: snap[k] for k in sorted(keys)},
        "versions": {"python": sys.version.split()[0], "pandas": pd.__version__},
        "notes": notes or {},
    }
    _meta_path(path).write_text(json.dumps(meta, indent=2), encoding="utf-8")


def stale_keys(meta: dict) -> list[str]:
    """Config keys whose current value differs from the value the artifact was built with."""
    now = config.snapshot()
    return [k for k, v in meta["config"].items() if now.get(k) != v]


def _check_fresh(path: Path) -> None:
    meta = read_meta(path)
    stale = stale_keys(meta)
    if stale:
        raise RuntimeError(f"{path.name} is stale, config changed: {stale}. "
                           f"Re-run '{meta['script']}' and every stage after it.")


def read_artifact(path: Path, columns: list[str] | None = None) -> pd.DataFrame:
    _check_fresh(path)
    return pd.read_parquet(path, columns=columns)
