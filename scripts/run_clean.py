"""Phase 2: data quality profile of the raw flows, then cleaning. One pass over the data."""
import time
from collections import Counter

import numpy as np
import pandas as pd

from carpet import clean, config, io

CONFIG_KEYS = ["VICTIM_PREFIX", "CONSTANT_COLUMNS"]


def main() -> None:
    start = time.time()
    counts = Counter()
    cells = {k: Counter() for k in ("inf_cells", "negative_cells", "nan_cells_before")}
    lo, hi = {}, {}
    hashes, protocols, sessions = [], Counter(), Counter()

    def cleaned_chunks():
        for flows in io.iter_artifact(config.FLOWS):
            feats = flows[clean.feature_columns(list(flows.columns))]
            for c in feats.columns:
                lo[c] = min(lo.get(c, np.inf), feats[c].min())
                hi[c] = max(hi.get(c, -np.inf), feats[c].max())
            hashes.append(pd.util.hash_pandas_object(flows, index=False).to_numpy())
            protocols.update(flows.Protocol.value_counts().to_dict())
            sessions.update(flows.session.value_counts().to_dict())
            out, c = clean.clean_chunk(flows)
            for k in ("rows_in", "rows_dropped_outside_victim", "rows_out", "rows_with_blanked_cell"):
                counts[k] += c[k]
            for k in cells:
                cells[k].update(c[k])
            print(f"{counts['rows_in']:,} rows ({time.time() - start:.0f}s)", flush=True)
            yield out

    rows, columns = io.write_parquet_stream(config.FLOWS_CLEAN, cleaned_chunks())

    constant = sorted(c for c in lo if lo[c] == hi[c])
    duplicates = int(pd.Series(np.concatenate(hashes)).duplicated().sum())
    problems = []
    if counts["rows_in"] - counts["rows_dropped_outside_victim"] != counts["rows_out"] or rows != counts["rows_out"]:
        problems.append(f"row bookkeeping does not add up: {dict(counts)}, written {rows}")
    if constant != sorted(config.CONSTANT_COLUMNS):
        problems.append(f"constant columns changed: found {constant}, config says {sorted(config.CONSTANT_COLUMNS)}")
    # ponytail: D10 says drop exact duplicates, but the measured count is 0, so there is no drop code.
    # If this fires, add a global hash filter here (hashes are already collected above).
    if duplicates:
        problems.append(f"{duplicates} exact duplicate rows found, D10 drop is not implemented yet")
    if problems:
        config.FLOWS_CLEAN.unlink()
        raise ValueError("cleaning refused:\n  " + "\n  ".join(problems))

    config.TABLES.mkdir(parents=True, exist_ok=True)
    dq = pd.DataFrame({k: pd.Series(v, dtype="int64") for k, v in cells.items()}).fillna(0).astype("int64")
    dq["min"], dq["max"] = pd.Series(lo), pd.Series(hi)
    dq["constant"] = dq.index.isin(constant)
    dq.index.name = "column"
    dq.to_csv(config.TABLES / "dq_columns.csv")
    summary = {**counts, "exact_duplicate_rows": duplicates,
               "protocols": dict(protocols), "rows_per_session": dict(sessions)}
    pd.Series(summary).to_csv(config.TABLES / "dq_summary.csv", header=["value"])

    io.write_meta(config.FLOWS_CLEAN, rows=rows, columns=columns, script="scripts/run_clean.py",
                  config_keys=CONFIG_KEYS, inputs=(config.FLOWS,),
                  notes={**summary, "constant_columns": constant,
                         "rules": ["drop flows with Dst IP outside VICTIM_PREFIX",
                                   "inf and negative feature cells set to NaN, flow kept (D11)",
                                   "exact duplicates: none found (D10)"]})
    blanked = {k: {c: n for c, n in v.items() if n} for k, v in cells.items()}
    print(f"wrote {config.FLOWS_CLEAN.name} rows={rows:,} in {time.time() - start:.0f}s")
    print(f"summary {dict(counts)} duplicates={duplicates}")
    print(f"cells {blanked}")


if __name__ == "__main__":
    main()
