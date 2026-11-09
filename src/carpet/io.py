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

LOG_COLUMNS = ["run_id", "scenario", "subnet", "dst", "start_ts", "end_ts",
               "interval_us", "payload", "n_src", "attacker_ip"]


ID_COLUMNS = ["Flow ID", "Src IP", "Dst IP", "Timestamp"]
INT_COLUMNS = ["Src Port", "Dst Port", "Protocol"]
DROP_COLUMNS = ["Label"]


def iter_raw_flows(usecols: list[str], dtype: dict | None = None,
                   chunksize: int = 500_000) -> Iterator[tuple[int, pd.DataFrame]]:
    """Yield (session, chunk). Chunked because the 3 CSVs are 0.9 to 1.5 GB each."""
    for session, path in config.RAW_FLOW_CSVS.items():
        for chunk in pd.read_csv(path, usecols=usecols, dtype=dtype, chunksize=chunksize):
            yield session, chunk


def raw_header() -> list[str]:
    """Header shared by all raw CSVs. Refuses to go on if the sessions disagree."""
    headers = {s: pd.read_csv(p, nrows=0).columns.tolist() for s, p in config.RAW_FLOW_CSVS.items()}
    first = next(iter(headers.values()))
    bad = [s for s, h in headers.items() if h != first]
    if bad:
        raise ValueError(f"raw CSV header differs in sessions {bad}")
    return first


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


def type_flows(chunk: pd.DataFrame, session: int) -> pd.DataFrame:
    """Raw CSV chunk to typed flows: epoch `ts` instead of the text Timestamp, plus `session`."""
    t = pd.to_datetime(chunk["Timestamp"], format=config.TIMESTAMP_FORMAT, errors="coerce")
    if t.isna().any():
        bad = chunk.loc[t.isna(), "Timestamp"].head(3).tolist()
        raise ValueError(f"session {session}: {int(t.isna().sum())} unparsable timestamps, e.g. {bad}")
    out = chunk.drop(columns=["Timestamp", *DROP_COLUMNS], errors="ignore")
    out.insert(3, "ts", ((t - pd.Timestamp("1970-01-01")) // pd.Timedelta("1s")).astype("int64"))
    out.insert(4, "session", pd.Series(session, index=out.index, dtype="int8"))
    return out


def read_attack_log() -> pd.DataFrame:
    log = pd.read_csv(config.ATTACK_LOG, dtype={"n_src": "string"})
    if list(log.columns) != LOG_COLUMNS:
        raise ValueError(f"attack_log columns {list(log.columns)} != expected {LOG_COLUMNS}")
    if log.run_id.duplicated().any():
        raise ValueError(f"duplicate run_id in attack_log: {log.run_id[log.run_id.duplicated()].tolist()}")
    if (log.end_ts <= log.start_ts).any():
        raise ValueError("attack_log has a run with end_ts <= start_ts")
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
