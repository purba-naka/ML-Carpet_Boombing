"""Phase 1: raw CSVs to one typed parquet. Changes types only, never drops a row."""
import time

import pandas as pd

from carpet import config, io

CONFIG_KEYS = ["TIMESTAMP_FORMAT", "RAW_ROWS_EXPECTED"]


def main() -> None:
    start = time.time()
    header = io.raw_header()
    usecols = [c for c in header if c not in io.DROP_COLUMNS]
    rows = dict.fromkeys(config.RAW_FLOW_CSVS, 0)
    span = [None, None]

    def typed_chunks():
        for session, chunk in io.iter_raw_flows(usecols, io.raw_dtypes(header)):
            flows = io.type_flows(chunk, session)
            rows[session] += len(flows)
            span[0] = min(span[0] or flows.ts.min(), flows.ts.min())
            span[1] = max(span[1] or flows.ts.max(), flows.ts.max())
            print(f"session {session}: {rows[session]:,} rows ({time.time() - start:.0f}s)", flush=True)
            yield flows

    total, columns = io.write_parquet_stream(config.FLOWS, typed_chunks())
    if rows != config.RAW_ROWS_EXPECTED:
        config.FLOWS.unlink()
        raise ValueError(f"row counts {rows} != expected {config.RAW_ROWS_EXPECTED}")
    span = [str(pd.Timestamp(int(x), unit="s")) for x in span]
    io.write_meta(config.FLOWS, rows=total, columns=columns, script="scripts/run_ingest.py",
                  config_keys=CONFIG_KEYS,
                  notes={"rows_per_session": rows, "ts_span": span, "dropped_columns": io.DROP_COLUMNS})
    print(f"wrote {config.FLOWS.name} rows={total:,} span={span} in {time.time() - start:.0f}s")


if __name__ == "__main__":
    main()
