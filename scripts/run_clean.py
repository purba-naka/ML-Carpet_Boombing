"""Phase 2: data quality profile of the raw flows, then cleaning. One pass over the data."""
import time
from collections import Counter

import numpy as np
import pandas as pd

from carpet import clean, config, io

CONFIG_KEYS = ["CAPTURE_SETTINGS", "CONSTANT_COLUMNS"]


def main() -> None:
    start = time.time()
    counts = Counter()
    cells = {k: Counter() for k in ("inf_cells", "negative_cells", "nan_cells_before")}
    lo, hi = {}, {}
    seen = [np.empty(0, np.uint64)]
    protocols, sessions, repeats = Counter(), Counter(), Counter()

    def cleaned_chunks():
        for flows in io.iter_artifact(config.FLOWS):
            feats = flows[clean.feature_columns(list(flows.columns))]
            for c in feats.columns:
                lo[c] = min(lo.get(c, np.inf), feats[c].min())
                hi[c] = max(hi.get(c, -np.inf), feats[c].max())
            protocols.update(flows.Protocol.value_counts().to_dict())
            where = flows.capture + "/" + flows.session.astype(str)
            sessions.update(where.value_counts().to_dict())
            repeat, seen[0] = clean.find_repeats(flows, seen[0])
            repeats.update(where[repeat].value_counts().to_dict())
            counts["rows_raw"] += len(flows)
            counts["rows_dropped_duplicate"] += int(repeat.sum())
            out, c = clean.clean_chunk(flows[~repeat])
            for k in ("rows_in", "rows_dropped_outside_victim", "rows_out", "rows_with_blanked_cell"):
                counts[k] += c[k]
            for k in cells:
                cells[k].update(c[k])
            print(f"{counts['rows_in']:,} rows ({time.time() - start:.0f}s)", flush=True)
            yield out

    rows, columns = io.write_parquet_stream(config.FLOWS_CLEAN, cleaned_chunks())

    constant = sorted(c for c in lo if lo[c] == hi[c])
    problems = []
    if (counts["rows_raw"] - counts["rows_dropped_duplicate"] != counts["rows_in"]
            or counts["rows_in"] - counts["rows_dropped_outside_victim"] != counts["rows_out"]
            or rows != counts["rows_out"]):
        problems.append(f"row bookkeeping does not add up: {dict(counts)}, written {rows}")
    if constant != sorted(config.CONSTANT_COLUMNS):
        problems.append(f"constant columns changed: found {constant}, config says {sorted(config.CONSTANT_COLUMNS)}")
    if problems:
        config.FLOWS_CLEAN.unlink()
        raise ValueError("cleaning refused:\n  " + "\n  ".join(problems))

    config.TABLES.mkdir(parents=True, exist_ok=True)
    dq = pd.DataFrame({k: pd.Series(v, dtype="int64") for k, v in cells.items()}).fillna(0).astype("int64")
    dq["min"], dq["max"] = pd.Series(lo), pd.Series(hi)
    dq["constant"] = dq.index.isin(constant)
    dq.index.name = "column"
    dq.to_csv(config.TABLES / "dq_columns.csv")
    summary = {**counts, "duplicates_per_capture_session": dict(repeats),
               "protocols": dict(protocols), "rows_per_capture_session": dict(sessions)}
    pd.Series(summary).to_csv(config.TABLES / "dq_summary.csv", header=["value"])

    io.write_meta(config.FLOWS_CLEAN, rows=rows, columns=columns, script="scripts/run_clean.py",
                  config_keys=CONFIG_KEYS, inputs=(config.FLOWS,),
                  notes={**summary, "constant_columns": constant,
                         "rules": ["drop flows with Dst IP outside the victim_prefixes of their capture",
                                   "inf and negative feature cells set to NaN, flow kept (D11)",
                                   "exact duplicate rows dropped, the first copy kept (D10)"]})
    blanked = {k: {c: n for c, n in v.items() if n} for k, v in cells.items()}
    print(f"wrote {config.FLOWS_CLEAN.name} rows={rows:,} in {time.time() - start:.0f}s")
    print(f"summary {dict(counts)} duplicates={dict(repeats)}")
    print(f"cells {blanked}")


if __name__ == "__main__":
    main()
