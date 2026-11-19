"""Phase 1: raw CSVs of every active capture to one typed parquet. Changes types only, never drops a row."""
import time

import pandas as pd

from carpet import config, io

CONFIG_KEYS = ["TIMESTAMP_FORMAT", "ACTIVE_CAPTURES", "CAPTURE_SETTINGS"]


def expected_rows() -> dict[str, int]:
    """Rows per `capture/session`: the registered count where known, else the CSV's own line count."""
    out = {}
    for capture, session, path in io.raw_csvs():
        known = config.CAPTURE_SETTINGS[capture]["rows_expected"]
        out[f"{capture}/{session}"] = known[str(session)] if known else io.count_csv_rows(path)
    return out


def overlapping_spans(spans: dict[str, list[int]]) -> list[tuple[str, str]]:
    """Capture pairs whose flow time spans overlap. Windows are keyed by (subnet, w) alone, so they must not."""
    ordered = sorted(spans.items(), key=lambda kv: kv[1][0])
    return [(a, b) for (a, sa), (b, sb) in zip(ordered, ordered[1:]) if sb[0] <= sa[1]]


def main() -> None:
    start = time.time()
    header = io.raw_header()
    usecols = [c for c in header if c not in io.DROP_COLUMNS]
    expected = expected_rows()
    rows = dict.fromkeys(expected, 0)
    spans: dict[str, list[int]] = {}

    def typed_chunks():
        for capture, session, chunk in io.iter_raw_flows(usecols, io.raw_dtypes(header)):
            flows = io.type_flows(chunk, capture, session)
            key = f"{capture}/{session}"
            rows[key] += len(flows)
            lo, hi = int(flows.ts.min()), int(flows.ts.max())
            span = spans.setdefault(capture, [lo, hi])
            span[0], span[1] = min(span[0], lo), max(span[1], hi)
            print(f"{key}: {rows[key]:,} rows ({time.time() - start:.0f}s)", flush=True)
            yield flows

    total, columns = io.write_parquet_stream(config.FLOWS, typed_chunks())
    problems = []
    if rows != expected:
        problems.append(f"row counts {rows} != expected {expected}")
    clash = overlapping_spans(spans)
    if clash:
        problems.append(f"captures overlap in time, windows would mix: {clash}")
    if problems:
        config.FLOWS.unlink()
        raise ValueError("ingest refused:\n  " + "\n  ".join(problems))
    span_text = {c: [str(pd.Timestamp(x, unit="s")) for x in s] for c, s in spans.items()}
    io.write_meta(config.FLOWS, rows=total, columns=columns, script="scripts/run_ingest.py",
                  config_keys=CONFIG_KEYS,
                  notes={"rows_per_capture_session": rows, "ts_span_per_capture": span_text,
                         "dropped_columns": io.DROP_COLUMNS})
    print(f"wrote {config.FLOWS} rows={total:,} in {time.time() - start:.0f}s")
    for c, s in span_text.items():
        print(f"  {c}: {s[0]} to {s[1]}")


if __name__ == "__main__":
    main()
