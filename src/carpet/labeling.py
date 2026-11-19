"""Flows to labeled windows. Labels come from the attack log (provenance), never from feature values."""
import numpy as np
import pandas as pd

from carpet import config
from carpet.config import Status, Subclass
from carpet.windows import KEY, window_keys

FLOW_COLUMNS = ["Src IP", "Dst IP", "Dst Port", "Protocol", "ts", "capture", "Flow Duration", "Total Fwd Packet"]
RUN_FACTORS = ["scenario", "dst", "spread", "proto", "dst_port", "sport_mode", "background", "n_src"]
WINDOW_COLUMNS = ["subnet", "w", "window_start", "capture", "run_id", "group", "subclass", "label", "status",
                  "near_attack", "n_flows", "n_pkts", "attacker_flows", "attacker_pkts",
                  *(f"run_{f}" for f in RUN_FACTORS)]
NO_RUN = "-"
TEST, CARPET, FOCUSED, BENIGN_HARD = "test", "carpet", "focused", "benign_hard"


def is_attacker(flows: pd.DataFrame, settings: dict | None = None) -> pd.Series:
    """The attacker host, or a spoofed source: outside the capture's victim subnets and not a known benign host.

    Multi source runs spoof their sources, so checking the attacker IP alone would miss
    about 1.2M attack flows in S1. S1 keeps its old extra condition (`spoof_filter`, DNS over
    UDP) so its labels do not move. This is label side information, never a feature.
    `settings` defaults to the active captures; the capture validator passes its own.
    """
    settings = settings or config.CAPTURE_SETTINGS
    out = pd.Series(False, index=flows.index)
    src = flows["Src IP"]
    for capture in flows["capture"].unique():
        s = settings[capture]
        spoofed = ~src.str.startswith(tuple(s["victim_prefixes"])) & ~src.isin(s["benign_sources"])
        if s["spoof_filter"]:
            spoofed &= (flows["Dst Port"] == s["spoof_filter"]["dst_port"]) & (flows["Protocol"] == s["spoof_filter"]["proto"])
        out |= (flows["capture"] == capture) & (src.isin(s["attacker_ips"]) | spoofed)
    return out


def window_counts(flows: pd.DataFrame) -> pd.DataFrame:
    """Per (subnet, w) counts of one chunk, with the capture it came from. Sum chunks with combine_counts."""
    attacker = is_attacker(flows)
    keyed = window_keys(flows).assign(
        capture=flows["capture"].to_numpy(), n_flows=1, n_pkts=flows["Total Fwd Packet"],
        attacker_flows=attacker.astype("int64"), attacker_pkts=flows["Total Fwd Packet"].where(attacker, 0))
    return keyed.groupby([*KEY, "capture"], as_index=False).sum()


def combine_counts(parts: list[pd.DataFrame]) -> pd.DataFrame:
    """Sums the chunk counts. Refuses a (subnet, w) seen in two captures, its label would be ambiguous."""
    out = pd.concat(parts).groupby([*KEY, "capture"], as_index=False).sum()
    shared = out.duplicated(KEY, keep=False)
    if shared.any():
        raise ValueError(f"{int(shared.sum())} windows appear in more than one capture, "
                         f"e.g. {out.loc[shared, [*KEY, 'capture']].head(4).to_dict('records')}")
    return out.astype({"n_flows": "int64", "n_pkts": "int64", "attacker_flows": "int64", "attacker_pkts": "int64"})


def run_kinds(log: pd.DataFrame) -> pd.Series:
    """test, carpet, focused or benign_hard per log row. A test run is a test whatever its scenario says."""
    scenario = log.scenario.astype(str)
    is_test = log.run_id.astype(str).str.startswith(config.TEST_RUN_PREFIXES) | (scenario == "test")
    kind = np.select([is_test, scenario.str.startswith("carpet"), scenario == "focused",
                      scenario.str.startswith("benign-")],
                     [TEST, CARPET, FOCUSED, BENIGN_HARD], default="")
    unknown = scenario[kind == ""]
    if len(unknown):
        raise ValueError(f"unknown scenarios in attack log: {unknown.unique().tolist()}")
    return pd.Series(kind, index=log.index)


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
    """Give every (subnet, w) a run, subclass, label and status. Rules in IMPLEMENTATION.md phase 3.

    Hard benign runs (D26) are logged like attacks so their windows can be named, but they are
    negatives: subclass benign_hard, label 0, never weak, and they do not count as attack times.
    """
    kinds = run_kinds(log)
    w = counts["w"].to_numpy()
    end = w + config.WINDOW_SECONDS
    attackers = counts["attacker_flows"].to_numpy()
    loud = (attackers > config.UNLOGGED_MIN_FLOWS) | (counts["attacker_pkts"].to_numpy() > config.UNLOGGED_MIN_PKTS)
    n = len(counts)
    test, partial, near, touched = (np.zeros(n, bool) for _ in range(4))
    run_id = np.full(n, NO_RUN, dtype=object)
    kind = np.full(n, "", dtype=object)
    buf = config.BOUNDARY_BUFFER_SECONDS
    for r, k in zip(log.itertuples(), kinds):
        overlap = (end > r.start_ts) & (w <= r.end_ts)
        touched |= overlap
        if k == TEST:
            test |= overlap
            continue
        inside = (w >= r.start_ts) & (end <= r.end_ts)
        run_id[inside] = r.run_id
        kind[inside] = k
        partial |= overlap & ~inside
        # A flow can start a little before or after the logged edges, so the neighbours go too.
        near |= ~overlap & (end > r.start_ts - buf) & (w <= r.end_ts + buf)

    in_run = run_id != NO_RUN
    in_attack_run = np.isin(kind, [CARPET, FOCUSED])
    outside = ~touched
    unlogged = outside & _zone_mask(w, w[outside & loud])

    # First match wins. The order is the rule book, so it is written down once, here.
    status = np.select(
        [test, partial, in_attack_run & (attackers == 0), in_run, unlogged, near],
        [Status.EXCLUDE_TEST, Status.EXCLUDE_BOUNDARY, Status.OK_WEAK, Status.OK,
         Status.EXCLUDE_UNLOGGED, Status.EXCLUDE_BOUNDARY],
        default=Status.OK).astype(str)
    usable_run = in_run & np.isin(status, list(config.USABLE_STATUSES))
    subclass = np.select(
        [usable_run & (kind == CARPET), usable_run & (kind == FOCUSED), usable_run & (kind == BENIGN_HARD),
         status == Status.EXCLUDE_UNLOGGED],
        [Subclass.CARPET, Subclass.FOCUSED, Subclass.BENIGN_HARD, Subclass.UNLOGGED],
        default=Subclass.BENIGN).astype(str)

    # Attack times: logged run edges, plus unlogged windows because an unlogged attack is still an attack.
    attack_runs = log[np.isin(kinds, [CARPET, FOCUSED])]
    attack_times = np.r_[attack_runs.start_ts.to_numpy(), attack_runs.end_ts.to_numpy(),
                         w[status == Status.EXCLUDE_UNLOGGED]]
    near_attack = (subclass == Subclass.BENIGN) & _near_attack(w, attack_times)

    block = "B" + (w // config.BENIGN_BLOCK_SECONDS).astype(str)
    factors = log.set_index("run_id")[RUN_FACTORS]
    out = counts.assign(
        window_start=pd.to_datetime(w, unit="s"),
        run_id=run_id.astype(str),
        group=np.where(in_run, run_id, block).astype(str),
        subclass=subclass,
        label=(subclass == Subclass.CARPET).astype("int8"),
        status=status,
        near_attack=near_attack,
        **{f"run_{f}": pd.Series(run_id).map(factors[f]).to_numpy() for f in RUN_FACTORS},
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
    runs = log.run_id[run_kinds(log) != TEST]
    low = {r: int(per_run.get(r, 0)) for r in runs if per_run.get(r, 0) < config.MIN_USABLE_WINDOWS_PER_RUN}
    if low:
        problems.append(f"runs with fewer than {config.MIN_USABLE_WINDOWS_PER_RUN} usable windows: {low}")
    benign = usable.subclass.isin([Subclass.BENIGN, Subclass.BENIGN_HARD])
    loud = (usable.attacker_flows > config.UNLOGGED_MIN_FLOWS) | (usable.attacker_pkts > config.UNLOGGED_MIN_PKTS)
    leaked = usable[benign & loud]
    if len(leaked):
        problems.append(f"{len(leaked)} usable benign or benign_hard windows carry attacker traffic")
    if problems:
        raise ValueError("labeled windows broken:\n  " + "\n  ".join(problems))
