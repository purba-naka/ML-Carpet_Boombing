"""Flows to labeled windows. Labels come from the attack log (provenance), never from feature values."""
import numpy as np
import pandas as pd

from carpet import config
from carpet.config import Status, Subclass
from carpet.windows import KEY, window_keys

FLOW_COLUMNS = ["Src IP", "Dst IP", "Dst Port", "Protocol", "ts", "Flow Duration", "Total Fwd Packet"]
WINDOW_COLUMNS = ["subnet", "w", "window_start", "run_id", "group", "subclass", "label", "status",
                  "near_attack", "n_flows", "n_pkts", "attacker_flows"]
NO_RUN = "-"


def is_attacker(flows: pd.DataFrame) -> pd.Series:
    """The attacker host, or a spoofed source (outside the victim /24, DNS over UDP).

    Multi source runs spoof random IPs, so checking the attacker IP alone would miss
    about 1.2M attack flows. This is label side information, never a feature.
    """
    src = flows["Src IP"]
    spoofed = (~src.str.startswith(config.VICTIM_PREFIX) & (src != config.BENIGN_SRC_EXTRA)
               & (flows["Dst Port"] == config.DNS_PORT) & (flows["Protocol"] == config.UDP))
    return (src == config.ATTACKER_IP) | spoofed


def window_counts(flows: pd.DataFrame) -> pd.DataFrame:
    """Per (subnet, w) counts of one chunk. Sum chunks with combine_counts."""
    keyed = window_keys(flows).assign(
        n_flows=1, n_pkts=flows["Total Fwd Packet"], attacker_flows=is_attacker(flows).astype("int64"))
    return keyed.groupby(KEY, as_index=False).sum()


def combine_counts(parts: list[pd.DataFrame]) -> pd.DataFrame:
    out = pd.concat(parts).groupby(KEY, as_index=False).sum()
    return out.astype({"n_flows": "int64", "n_pkts": "int64", "attacker_flows": "int64"})


def _zone_mask(w: np.ndarray, seeds: np.ndarray) -> np.ndarray:
    """True for windows inside a cluster of seed windows, padded by the boundary buffer.

    Seeds closer than UNLOGGED_GAP_SECONDS form one cluster, so the quiet minutes
    between bursts of an unlogged test go too. Those minutes are not clean benign,
    a long flow from the burst can still be running.
    """
    if len(seeds) == 0:
        return np.zeros(len(w), bool)
    s = np.unique(seeds)
    cut = np.flatnonzero(np.diff(s) > config.UNLOGGED_GAP_SECONDS)
    starts = s[np.r_[0, cut + 1]] - config.BOUNDARY_BUFFER_SECONDS
    ends = np.maximum.accumulate(s[np.r_[cut, len(s) - 1]] + config.BOUNDARY_BUFFER_SECONDS)
    i = np.searchsorted(starts, w, side="right") - 1
    return (i >= 0) & (w <= ends[np.clip(i, 0, None)])


def _near_attack(w: np.ndarray, attack_times: np.ndarray) -> np.ndarray:
    """True when a window starts within NEAR_ATTACK_SECONDS of any attack time. Report only, not a label.

    Most of the capture (the last 7 hours) has no attack at all, so benign windows there are
    easy. Separating near from far lets the evaluation say how the model does on the hard ones.
    """
    if len(attack_times) == 0:
        return np.zeros(len(w), bool)
    t = np.sort(attack_times)
    i = np.searchsorted(t, w)
    left = np.abs(w - t[np.clip(i - 1, 0, len(t) - 1)])
    right = np.abs(w - t[np.clip(i, 0, len(t) - 1)])
    return np.minimum(left, right) <= config.NEAR_ATTACK_SECONDS


def label_windows(counts: pd.DataFrame, log: pd.DataFrame) -> pd.DataFrame:
    """Give every (subnet, w) a run, subclass, label and status. Rules in IMPLEMENTATION.md phase 3."""
    runs = log[log.run_id != config.TEST_RUN]
    unknown = runs[~runs.scenario.str.startswith("carpet") & (runs.scenario != "focused")]
    if len(unknown):
        raise ValueError(f"unknown scenarios in attack log: {unknown.scenario.unique().tolist()}")

    w = counts["w"].to_numpy()
    end = w + config.WINDOW_SECONDS
    attackers = counts["attacker_flows"].to_numpy()
    n = len(counts)
    test, partial, near, touched = (np.zeros(n, bool) for _ in range(4))
    run_id = np.full(n, NO_RUN, dtype=object)
    carpet = np.zeros(n, bool)
    buf = config.BOUNDARY_BUFFER_SECONDS
    for r in log.itertuples():
        overlap = (end > r.start_ts) & (w <= r.end_ts)
        touched |= overlap
        if r.run_id == config.TEST_RUN:
            test |= overlap
            continue
        inside = (w >= r.start_ts) & (end <= r.end_ts)
        run_id[inside] = r.run_id
        carpet[inside] = r.scenario.startswith("carpet")
        partial |= overlap & ~inside
        # A flow can start a little before or after the logged edges, so the neighbours go too.
        near |= ~overlap & (end > r.start_ts - buf) & (w <= r.end_ts + buf)

    in_run = run_id != NO_RUN
    outside = ~touched
    unlogged = outside & _zone_mask(w, w[outside & (attackers > config.UNLOGGED_MIN_FLOWS)])

    # First match wins. The order is the rule book, so it is written down once, here.
    status = np.select(
        [test, partial, in_run & (attackers == 0), in_run, unlogged, near],
        [Status.EXCLUDE_TEST, Status.EXCLUDE_BOUNDARY, Status.OK_WEAK, Status.OK,
         Status.EXCLUDE_UNLOGGED, Status.EXCLUDE_BOUNDARY],
        default=Status.OK).astype(str)
    usable_run = in_run & np.isin(status, list(config.USABLE_STATUSES))
    subclass = np.select(
        [usable_run & carpet, usable_run, status == Status.EXCLUDE_UNLOGGED],
        [Subclass.CARPET, Subclass.FOCUSED, Subclass.UNLOGGED], default=Subclass.BENIGN).astype(str)

    # Attack times: logged run edges, plus unlogged windows because an unlogged attack is still an attack.
    attack_times = np.r_[runs.start_ts.to_numpy(), runs.end_ts.to_numpy(), w[status == Status.EXCLUDE_UNLOGGED]]
    near_attack = (subclass == Subclass.BENIGN) & _near_attack(w, attack_times)

    block = "B" + (w // config.BENIGN_BLOCK_SECONDS).astype(str)
    out = counts.assign(
        window_start=pd.to_datetime(w, unit="s"),
        run_id=run_id.astype(str),
        group=np.where(in_run, run_id, block).astype(str),
        subclass=subclass,
        label=(subclass == Subclass.CARPET).astype("int8"),
        status=status,
        near_attack=near_attack,
    )
    return out[WINDOW_COLUMNS].sort_values(KEY, ignore_index=True)


def check_windows(windows: pd.DataFrame, log: pd.DataFrame) -> None:
    """Invariants on the real labeled windows. Raises with every broken rule listed."""
    problems = []
    if windows.duplicated(KEY).any():
        problems.append(f"{int(windows.duplicated(KEY).sum())} duplicate (subnet, w) keys")
    if ((windows.label == 1) != (windows.subclass == Subclass.CARPET)).any():
        problems.append("label 1 and subclass carpet disagree")
    usable = windows[windows.status.isin(list(config.USABLE_STATUSES))]
    per_run = usable.run_id.value_counts()
    runs = log.run_id[log.run_id != config.TEST_RUN]
    low = {r: int(per_run.get(r, 0)) for r in runs if per_run.get(r, 0) < config.MIN_USABLE_WINDOWS_PER_RUN}
    if low:
        problems.append(f"runs with fewer than {config.MIN_USABLE_WINDOWS_PER_RUN} usable windows: {low}")
    leaked = usable[(usable.run_id == NO_RUN) & (usable.attacker_flows > config.UNLOGGED_MIN_FLOWS)]
    if len(leaked):
        problems.append(f"{len(leaked)} usable benign windows carry attacker traffic")
    if problems:
        raise ValueError("labeled windows broken:\n  " + "\n  ".join(problems))
