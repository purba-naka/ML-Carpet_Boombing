"""DS-8: is a new capture fit for the pipeline? Read only: raw CSV, attack log and target files.

Usage: python scripts/validate_capture.py --capture TA
Writes reports/tables/capture_validation_<capture>.csv and prints a one screen summary. Exits 1
when a check fails. For the hold-out capture B it prints counts and pass or fail only, never a
feature value per class.
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from carpet import clean, config, io, labeling

READ_COLUMNS = ["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packet"]
PROTOCOL_NUMBER = {"udp": 17, "tcp": 6}
PASS, FAIL, WARN, SKIP = "pass", "fail", "warn", "skip"


class Report:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, check: str, scope: str, value, expected, result: str) -> None:
        self.rows.append({"check": check, "scope": scope, "value": value, "expected": expected, "result": result})

    def frame(self) -> pd.DataFrame:
        return pd.DataFrame(self.rows, columns=["check", "scope", "value", "expected", "result"])


def scan_flows(capture: str, settings: dict) -> dict:
    """One pass over the capture's CSVs: row counts, bad timestamps, flows per minute, and the attacker flows.

    Attacker flows are taken among flows into the victim subnets only, as the pipeline does after cleaning.
    That leaves out CICFlowMeter's misread ARP rows (8.6.0.1 to 8.0.6.4, protocol 0).
    """
    out = {"rows": {}, "bad_ts": 0, "per_minute": [], "attacker": []}
    for session, path in config.CAPTURE_FILES[capture]["csvs"].items():
        out["rows"][session] = 0
        for chunk in pd.read_csv(path, usecols=READ_COLUMNS, chunksize=500_000):
            out["rows"][session] += len(chunk)
            t = pd.to_datetime(chunk["Timestamp"], format=config.TIMESTAMP_FORMAT, errors="coerce")
            out["bad_ts"] += int(t.isna().sum())
            chunk = chunk[t.notna()].assign(ts=((t[t.notna()] - pd.Timestamp("1970-01-01")) // pd.Timedelta("1s")),
                                            capture=capture)
            minute = chunk.ts // 60 * 60
            out["per_minute"].append(minute.value_counts())
            victim = chunk[clean.in_victim_subnets(chunk, {capture: settings})]
            att = labeling.is_attacker(victim, {capture: settings})
            out["attacker"].append(victim.loc[att, ["ts", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
                                                    "Flow Duration", "Total Fwd Packet"]])
    out["per_minute"] = pd.concat(out["per_minute"]).groupby(level=0).sum().sort_index()
    out["attacker"] = pd.concat(out["attacker"], ignore_index=True)
    return out


def read_targets(capture: str, run_id: str) -> set[str] | None:
    """Target IPs of a run, from `<run>_targets.txt` next to the log or in `targets/`. None if absent."""
    folder = Path(config.CAPTURE_FILES[capture]["attack_log"]).parent
    for path in (folder / f"{run_id}_targets.txt", folder / "targets" / f"{run_id}_targets.txt"):
        if path.exists():
            return {line.split()[-1] for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
    return None


def check_files(r: Report, capture: str, scan: dict) -> None:
    s1_header = pd.read_csv(config.CAPTURE_FILES["S1"]["csvs"]["1"], nrows=0).columns.tolist()
    for session, path in config.CAPTURE_FILES[capture]["csvs"].items():
        header = pd.read_csv(path, nrows=0).columns.tolist()
        r.add("1 header", f"csv {session}", f"{len(header)} columns", f"{len(s1_header)} columns, same as S1",
              PASS if header == s1_header else FAIL)
        lines = io.count_csv_rows(Path(path))
        r.add("1 rows", f"csv {session}", scan["rows"][session], lines, PASS if lines == scan["rows"][session] else FAIL)
    r.add("2 timestamps", "all", scan["bad_ts"], 0, PASS if scan["bad_ts"] == 0 else FAIL)


def check_log(r: Report, capture: str, log: pd.DataFrame) -> None:
    try:
        io.check_attack_log(pd.concat([log, io.read_capture_log("S1")], ignore_index=True))
        r.add("3 log", "all", f"{len(log)} runs", "unique ids, no overlap, known values", PASS)
    except ValueError as err:
        r.add("3 log", "all", str(err).replace("\n", " "), "unique ids, no overlap, known values", FAIL)
    ordered = log.sort_values("start_ts")
    gaps = ordered.start_ts.to_numpy()[1:] - ordered.end_ts.to_numpy()[:-1]
    for (a, b), gap in zip(zip(ordered.run_id[:-1], ordered.run_id[1:]), gaps):
        if gap < config.VALIDATE_MIN_RUN_GAP_SECONDS:
            r.add("3 gap", f"{a} -> {b}", f"{gap} s", f">= {config.VALIDATE_MIN_RUN_GAP_SECONDS} s", FAIL)
    off = log[(log.start_ts % 60 != 0) & (labeling.run_kinds(log) != labeling.TEST)]
    for row in off.itertuples():
        r.add("3 start :00", row.run_id, f"second {row.start_ts % 60}", "second 0", WARN)


def check_runs(r: Report, capture: str, log: pd.DataFrame, attacker: pd.DataFrame) -> None:
    """Per attack run: timing, volume, hosts hit, protocol and port of its attacker flows.

    A run owns the attacker flows from just before its start until the flow timeout after its end,
    but never past the start of the next run, or a short gap would hand one run's flows to another.
    """
    timeout = config.CAPTURES[capture]["flow_timeout_s"]
    slack = config.VALIDATE_START_SLACK_SECONDS
    attack_runs = log[log.scenario.str.startswith("carpet") | (log.scenario == "focused")].sort_values("start_ts")
    next_start = np.r_[attack_runs.start_ts.to_numpy()[1:], np.iinfo(np.int64).max]
    for row, stop in zip(attack_runs.itertuples(), next_start):
        a = attacker[(attacker.ts >= row.start_ts - slack) & (attacker.ts <= min(row.end_ts + timeout, stop - slack))]
        if a.empty:
            r.add("4 timing", row.run_id, "no attacker flow", f"first within {slack} s of start", FAIL)
            r.add("5 targets", row.run_id, 0, int(row.dst), FAIL)
            continue
        first, last = int(a.ts.min() - row.start_ts), int(a.ts.max() - row.end_ts)
        r.add("4 timing", row.run_id, f"first {first:+d} s, last {last:+d} s after end",
              f"first within {slack} s, last <= {timeout} s", PASS if abs(first) <= slack and last <= timeout else FAIL)
        r.add("4 volume", row.run_id, f"{len(a)} flows, {int(a['Total Fwd Packet'].sum())} fwd packets", "-", PASS)
        hit = set(a["Dst IP"])
        r.add("5 targets", row.run_id, len(hit), int(row.dst), PASS if len(hit) == row.dst else FAIL)
        listed = read_targets(capture, row.run_id)
        if listed is not None:
            stray = sorted(hit - listed)
            r.add("5 target file", row.run_id, f"{len(listed)} listed, {len(stray)} hit outside the list",
                  "every hit host is listed", PASS if not stray else FAIL)
        proto = PROTOCOL_NUMBER.get(row.proto)
        if proto is not None:
            n = int((a.Protocol == proto).sum())
            r.add("5 protocol", row.run_id, f"{n} of {len(a)} flows are {row.proto}", "all", PASS if n == len(a) else FAIL)
        if row.dst_port and row.dst_port > 0:
            to_port = a["Dst Port"] == row.dst_port
            flipped = ~to_port & (a["Src Port"] == row.dst_port)
            n = int((to_port | flipped).sum())
            r.add("5 dst port", row.run_id, f"{n} of {len(a)} flows on port {int(row.dst_port)}", "all",
                  PASS if n == len(a) else FAIL)
            if flipped.any():
                r.add("5 flipped flows", row.run_id, f"{int(flipped.sum())} flows with the ports swapped",
                      "info: CICFlowMeter splits the echoed conversation", PASS)


def check_unlogged(r: Report, capture: str, log: pd.DataFrame, attacker: pd.DataFrame) -> None:
    """Attacker traffic in a minute that no attack run covers. Hard benign runs count as uncovered."""
    timeout = config.CAPTURES[capture]["flow_timeout_s"]
    attack_runs = log[log.scenario.str.startswith("carpet") | (log.scenario == "focused")]
    covered = np.zeros(len(attacker), bool)
    for row in attack_runs.itertuples():
        covered |= ((attacker.ts >= row.start_ts - 60) & (attacker.ts <= row.end_ts + timeout)).to_numpy()
    loose = attacker[~covered]
    per_window = loose.groupby(loose.ts // config.WINDOW_SECONDS * config.WINDOW_SECONDS).agg(
        flows=("ts", "size"), pkts=("Total Fwd Packet", "sum"))
    rule = f"<= {config.UNLOGGED_MIN_FLOWS} flows and <= {config.UNLOGGED_MIN_PKTS} packets"
    bad = per_window[(per_window.flows > config.UNLOGGED_MIN_FLOWS) | (per_window.pkts > config.UNLOGGED_MIN_PKTS)]
    r.add("6 unlogged", "outside attack runs", f"{len(bad)} windows", f"0 windows over the D28 rule",
          PASS if bad.empty else FAIL)
    for w, row in bad.iterrows():
        r.add("6 unlogged window", str(pd.Timestamp(int(w), unit="s")),
              f"{int(row.flows)} flows, {int(row.pkts)} packets", rule, FAIL)


def check_windows_and_gaps(r: Report, log: pd.DataFrame, per_minute: pd.Series) -> None:
    w = config.WINDOW_SECONDS
    for row in log[labeling.run_kinds(log) != labeling.TEST].itertuples():
        full = max(0, (row.end_ts // w * w - (-(-row.start_ts // w) * w)) // w)
        r.add("7 full windows", row.run_id, int(full), f">= {config.MIN_USABLE_WINDOWS_PER_RUN}",
              PASS if full >= config.MIN_USABLE_WINDOWS_PER_RUN else FAIL)
    minutes = np.arange(per_minute.index.min(), per_minute.index.max() + w, w)
    empty = np.setdiff1d(minutes, per_minute.index.to_numpy())
    r.add("8 capture gaps", "all", f"{len(empty)} empty minutes", "0", PASS if len(empty) == 0 else WARN)
    if len(empty):
        cut = np.flatnonzero(np.diff(empty) > w)
        for a, b in zip(empty[np.r_[0, cut + 1]], empty[np.r_[cut, len(empty) - 1]]):
            r.add("8 capture gap", "range", f"{pd.Timestamp(int(a), unit='s')} to {pd.Timestamp(int(b), unit='s')}",
                  "-", WARN)


def check_design(r: Report, log: pd.DataFrame) -> None:
    """PLAN_DATASET 3.4 minimum, only for a real session (10 or more non test runs)."""
    runs = log[labeling.run_kinds(log) != labeling.TEST]
    if len(runs) < 10:
        r.add("9 design", "all", f"{len(runs)} non test runs", "10 or more", SKIP)
        return
    carpet = runs[runs.scenario.str.startswith("carpet")]
    focused = runs[runs.scenario == "focused"]
    attack = pd.concat([carpet, focused])
    vector = lambda d: d.proto + " " + d.dst_port.fillna(-1).astype(int).astype(str)
    checks = {
        "carpet runs >= 10": len(carpet) >= 10,
        "focused runs >= 6": len(focused) >= 6,
        "hard benign runs >= 4": int(runs.scenario.str.startswith("benign-").sum()) >= 4,
        "carpet dst 4,6,8,12,16,32 each present": {4, 6, 8, 12, 16, 32} <= set(carpet.dst.dropna().astype(int)),
        "carpet with dst < 16 >= 4": int((carpet.dst < 16).sum()) >= 4,
        "skewed carpet >= 4": int((carpet.spread == "skewed").sum()) >= 4,
        "each vector >= 2 in carpet": (vector(carpet).value_counts() >= 2).sum() >= 4,
        "each vector >= 1 in focused": vector(focused).nunique() >= 4,
        "n_src 1 and multi each >= 40% of attacks": min((attack.n_src == "1").mean(), (attack.n_src == "multi").mean()) >= 0.4,
        "attacks with wide or flash background >= 3": int(attack.background.isin(["wide", "flash"]).sum()) >= 3,
        "subnet 2 share >= 20%": float((runs.subnet == "203.0.113.0/24").mean()) >= 0.2,
    }
    for name, ok in checks.items():
        r.add("9 design", name, ok, True, PASS if ok else FAIL)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, choices=sorted(set(config.CAPTURES) - {"S1"}))
    capture = parser.parse_args().capture
    settings = config.CAPTURES[capture]
    r = Report()
    log = io.read_capture_log(capture)
    scan = scan_flows(capture, settings)
    check_files(r, capture, scan)
    check_log(r, capture, log)
    check_runs(r, capture, log, scan["attacker"])
    check_unlogged(r, capture, log, scan["attacker"])
    check_windows_and_gaps(r, log, scan["per_minute"])
    check_design(r, log)

    table = r.frame()
    out = config.REPORTS / "tables" / f"capture_validation_{capture}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(out, index=False)
    counts = table.result.value_counts().to_dict()
    print(f"capture {capture}: {sum(scan['rows'].values()):,} flows, {len(log)} runs, "
          f"{len(scan['attacker']):,} attacker flows -> {out}")
    print("  " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    with pd.option_context("display.width", 200, "display.max_colwidth", 90):
        shown = table[table.result.isin([FAIL, WARN])]
        if not shown.empty:
            print(shown.to_string(index=False))
    return 1 if counts.get(FAIL) else 0


if __name__ == "__main__":
    sys.exit(main())
