"""Single source of truth: paths, constants, enums. Nothing else in the repo retypes these values.

Captures (PL-8). `CAPTURES` registers every capture with plain values only, `CAPTURE_FILES` says where
its CSVs and attack log live, and `CARPET_CAPTURES` (comma list, default `S1`) picks the ones in use.
`spoof_filter` keeps the S1 rule, where a spoofed source only counted on DNS over UDP. New captures
have none: any source outside the victim subnets and outside `benign_sources` is the attacker.
`rows_expected` guards the ingest where the row count is known; None means count the CSV lines.
`TA` is the four run test capture of 2026-11-15 (`dataset2/`), there to exercise the code on the
new log format and vectors, never to train or judge a model. S1 alone keeps the v1 folders, so
every S1 result stays where it was; any other capture set gets its own folders.

Attack log (scheme v2 section 5). `LOG_DOMAINS` lists the allowed value per column, "-" means not
applicable. S1 has one test run called TEST, the new captures TEST1.. and RETEST1.., hence
`TEST_RUN_PREFIXES`.

Capture validator (DS-8, `scripts/validate_capture.py`). The first attacker flow of a run must
show up within `VALIDATE_START_SLACK_SECONDS` of `start_ts`, and runs must sit at least
`VALIDATE_MIN_RUN_GAP_SECONDS` apart (flow timeout 120 s plus the 60 s boundary buffer).

Unlogged attacks (D28). A window outside every run seeds an unlogged zone when it holds more than
`UNLOGGED_MIN_FLOWS` attacker flows or more than `UNLOGGED_MIN_PKTS` attacker packets. The packet
rule catches an unlogged send with a fixed source port: in the TA test capture 28 flows carried
45,000 packets in one minute and slipped past the flow rule. 300 is about ten times the most
attacker packets in any usable S1 benign window (31).
"""
import json
import os
from enum import StrEnum
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# D22: `spread` is the main method. A long flow is cut over every window it touches, because
# CICFlowMeter cuts flows at 120 s and under `start` (PDF 3.2.3.1, a flow belongs to the window it
# starts in) 63 of 64 weak windows were attack minutes with no attack flow starting in them.
# `start` still runs as the comparison. Folder names keep the v1 layout, so no old result moves:
# `start` writes to the plain folders, `spread` to the `_spread` ones.
WINDOW_ASSIGNMENT = os.environ.get("CARPET_WINDOW_ASSIGNMENT", "spread")
if WINDOW_ASSIGNMENT not in ("start", "spread"):
    raise ValueError(f"CARPET_WINDOW_ASSIGNMENT must be start or spread, got {WINDOW_ASSIGNMENT!r}")
_variant = "" if WINDOW_ASSIGNMENT == "start" else "_spread"

_NEW_SUBNETS = ["198.51.100.", "203.0.113."]
CAPTURES = {
    "S1": {"victim_prefixes": ["198.51.100."], "attacker_ips": ["192.168.1.65"],
           "benign_sources": ["8.6.0.1"], "spoof_filter": {"proto": 17, "dst_port": 53},
           "flow_timeout_s": 120, "rows_expected": {"1": 3_833_012, "2": 2_444_150, "3": 3_490_688}},
    "TA": {"victim_prefixes": _NEW_SUBNETS, "attacker_ips": ["192.168.1.65"], "benign_sources": [],
           "spoof_filter": None, "flow_timeout_s": 120, "rows_expected": None},
    "A": {"victim_prefixes": _NEW_SUBNETS, "attacker_ips": ["192.168.1.65"], "benign_sources": [],
          "spoof_filter": None, "flow_timeout_s": 120, "rows_expected": None},
    "B": {"victim_prefixes": _NEW_SUBNETS, "attacker_ips": ["192.168.1.65"], "benign_sources": [],
          "spoof_filter": None, "flow_timeout_s": 120, "rows_expected": None},
}
CAPTURE_FILES = {
    "S1": {"csvs": {str(s): ROOT / f"dataset/csv/sesi{s}_all.csv/sesi{s}_all.csv" for s in (1, 2, 3)},
           "attack_log": ROOT / "dataset/Attack_log-20261109T113913Z-1-001/Attack_log/attack_log.csv"},
    "TA": {"csvs": {"1": ROOT / "dataset2/sesiA_test_all.csv/sesiA_test_all.csv"},
           "attack_log": ROOT / "dataset2/attack_log.csv"},
    "A": {"csvs": {"1": ROOT / "dataset/sesiA/csv/sesiA_all.csv"}, "attack_log": ROOT / "dataset/sesiA/attack_log.csv"},
    "B": {"csvs": {"1": ROOT / "dataset/sesiB/csv/sesiB_all.csv"}, "attack_log": ROOT / "dataset/sesiB/attack_log.csv"},
}
ACTIVE_CAPTURES = tuple(os.environ.get("CARPET_CAPTURES", "S1").split(","))
_unknown_captures = set(ACTIVE_CAPTURES) - set(CAPTURES)
if _unknown_captures:
    raise ValueError(f"CARPET_CAPTURES names unknown captures: {sorted(_unknown_captures)}")
CAPTURE_SETTINGS = {c: CAPTURES[c] for c in ACTIVE_CAPTURES}

_captures = "" if ACTIVE_CAPTURES == ("S1",) else "_" + "+".join(ACTIVE_CAPTURES)
INTERIM = ROOT / f"data/interim{_captures}"
PROCESSED = ROOT / f"data/processed{_variant}{_captures}"
REPORTS = ROOT / "reports"
EXPERIMENTS = REPORTS / f"experiments{_variant}{_captures}"
FIGURES = REPORTS / f"figures{_variant}{_captures}"
MODELS = ROOT / "models"

FLOWS = INTERIM / "flows.parquet"
FLOWS_CLEAN = INTERIM / "flows_clean.parquet"
WINDOWS_LABELED = PROCESSED / "windows_labeled.parquet"
SPLIT = PROCESSED / "split.parquet"
FEATURES_AGG = PROCESSED / "features_agg.parquet"
FEATURES_FLOW = PROCESSED / "features_flow.parquet"
FEATURES_ARTIFACT = PROCESSED / "features_artifact.parquet"
TABLES = REPORTS / f"tables{_variant}{_captures}"

# Zero in every raw row (verified by run_clean). Kept in the flow table, never offered as features.
CONSTANT_COLUMNS = ("Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "URG Flag Count",
                    "CWR Flag Count", "ECE Flag Count", "Fwd Bytes/Bulk Avg",
                    "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg")

SEED = 42
WINDOW_SECONDS = 60
UDP = 17

TEST_RUN_PREFIXES = ("TEST", "RETEST")
VALIDATE_START_SLACK_SECONDS = 5
VALIDATE_MIN_RUN_GAP_SECONDS = 180

LOG_DOMAINS = {
    "scenario": ("carpet", "carpet-low", "carpet-mid", "carpet-stealth", "focused",
                 "benign-wide", "benign-flash", "benign-sweep", "test"),
    "rate_unit": ("pps", "us_interval"),
    "n_src": ("1", "multi", "-"),
    "proto": ("udp", "tcp", "-"),
    "spread": ("uniform", "skewed", "-"),
    "sport_mode": ("fixed", "random", "-"),
    "background": ("normal", "wide", "flash", "-"),
}
UNLOGGED_MIN_FLOWS = 50
UNLOGGED_MIN_PKTS = 300
UNLOGGED_GAP_SECONDS = 300
BOUNDARY_BUFFER_SECONDS = 60
BENIGN_BLOCK_SECONDS = 1800
NEAR_ATTACK_SECONDS = 600
MIN_USABLE_WINDOWS_PER_RUN = 10

# CSV Timestamp has no zone. Read as naive UTC it lines up with attack_log epochs (verified).
TIMESTAMP_FORMAT = "%d/%m/%Y %I:%M:%S %p"

HOLDOUT_RUNS = ("C10", "C11", "C9", "C12", "F2", "F6")
HOLDOUT_BENIGN_FRACTION = 0.2
CV_FOLDS = 5

# D23: randomized search over the PDF 3.2.4.4 parameters. RF max_features stops at 0.5: at 1.0 every
# split sees every feature and the forest is plain bagging. scale_pos_weight is not searched, it comes
# from the train fold (models.xgboost).
TUNE_COMBINATIONS = 30
TUNE_SPACE = {
    "rf": {"n_estimators": [100, 200, 300, 500], "max_depth": [4, 6, 8, 12, 20, None],
           "min_samples_split": [2, 5, 10], "min_samples_leaf": [1, 2, 3, 5],
           "max_features": ["sqrt", "log2", 0.3, 0.5], "class_weight": ["balanced", "balanced_subsample"]},
    "xgb": {"n_estimators": [100, 200, 300, 400], "max_depth": [3, 4, 5, 6],
            "learning_rate": [0.03, 0.05, 0.1, 0.2], "subsample": [0.7, 0.85, 1.0],
            "colsample_bytree": [0.7, 0.85, 1.0], "gamma": [0, 0.5, 1, 2], "reg_lambda": [0.5, 1, 2, 5]},
}
# Ablation and robustness reuse the agg_flow params, so only these two sets are searched.
TUNE_SETS = ("agg", "agg_flow")

# D24 (D3 revisited): train with and without weak windows only while there are enough of them to matter.
# Under `spread` one weak window is left in trainval, so the two runs would be the same experiment twice.
WEAK_IN_TRAIN_SETTINGS = (True, False) if WINDOW_ASSIGNMENT == "start" else (True,)

# Columns that define labels or identify rows. They must never reach a model.
FORBIDDEN_FEATURES = frozenset({
    "attacker_flows", "run_id", "group", "subclass", "status", "label", "near_attack",
    "w", "window_start", "subnet",
    "Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "Timestamp", "ts", "session", "capture",
    "run_scenario", "run_dst", "run_spread", "run_proto", "run_dst_port", "run_sport_mode", "run_background",
    "run_n_src",
})


AGG_FEATURES = ("n_unique_dst", "dst_entropy", "dst_entropy_norm", "concentration_ratio",
                "total_pkts", "total_bytes", "mean_pkts_per_dst", "max_pkts_per_dst",
                "n_unique_src", "n_src_dst_pairs", "udp_ratio", "n_flows")

# D15: PDF style flow columns (duration, lengths, inter-arrival time, rates), picked by EDA effect size,
# skipping any column that correlates above 0.9 with one already chosen. Bwd and TCP flag columns
# were left out on purpose, see reports/eda_findings.md.
FLOW_SUMMARY_COLUMNS = ("Flow IAT Std", "Fwd Packet Length Std", "Packet Length Std", "Flow Duration",
                        "Flow Packets/s", "Total Length of Fwd Packet", "Flow IAT Min", "Fwd Header Length",
                        "Down/Up Ratio", "Packet Length Mean", "Flow Bytes/s")
FLOW_STATS = ("mean", "std", "max")
FLOW_FEATURES = tuple(f"{c}__{s}" for c in FLOW_SUMMARY_COLUMNS for s in FLOW_STATS)

# D19: the artifact columns D15 left out on purpose, picked back up for the phase 9 ablation with
# the same rule (effect size order, Spearman above 0.9 dropped). If the model gets better with
# these, part of its score came from the testbed artifact, not from carpet bombing itself.
ARTIFACT_FLOW_COLUMNS = ("Bwd IAT Min", "Bwd IAT Mean", "SYN Flag Count", "Bwd Bulk Rate Avg",
                         "Bwd IAT Total", "Subflow Bwd Packets", "Bwd Packets/s", "Bwd IAT Std",
                         "Bwd Bytes/Bulk Avg")
ARTIFACT_FLOW_FEATURES = tuple(f"{c}__{s}" for c in ARTIFACT_FLOW_COLUMNS for s in FLOW_STATS)

# Feature groups, written down once. Ablation sets and grouped permutation importance both build on
# them, so the two can never disagree about what "the volume features" are. Together they are agg_flow.
FEATURE_GROUPS = {
    "dst_spread": ("dst_entropy", "dst_entropy_norm", "concentration_ratio"),
    # mean_pkts_per_dst is total over n_unique_dst, and on single source runs n_src_dst_pairs equals
    # n_unique_dst, so either one left in would let a tree count destinations again.
    "dst_count": ("n_unique_dst", "n_src_dst_pairs", "mean_pkts_per_dst"),
    "volume": ("total_pkts", "total_bytes", "n_flows", "max_pkts_per_dst"),
    "source": ("n_unique_src",),
    "protocol": ("udp_ratio",),
    "flow": FLOW_FEATURES,
}

# Every removal starts from agg_flow, the full set, so each row shows what losing that feature
# group costs. dst_only also drops n_src_dst_pairs: for multi source runs it is the source count
# under another name, and keeping it would fake the "destination spread only" claim.
_base = AGG_FEATURES + FLOW_FEATURES


def _without(*groups: str) -> tuple[str, ...]:
    gone = {f for g in groups for f in FEATURE_GROUPS[g]}
    return tuple(f for f in _base if f not in gone)


FEATURE_SETS = {
    "agg": AGG_FEATURES,
    "flow": FLOW_FEATURES,
    "agg_flow": _base,
    "agg_flow_no_src": tuple(f for f in _base if f != "n_unique_src"),
    "agg_flow_no_udp": tuple(f for f in _base if f != "udp_ratio"),
    "agg_flow_no_volume": tuple(f for f in _base if f not in ("total_pkts", "total_bytes", "n_flows")),
    "agg_flow_dst_only": tuple(f for f in _base if f not in
                               ("total_pkts", "total_bytes", "n_flows", "n_unique_src",
                                "n_src_dst_pairs", "udp_ratio")),
    # PDF 3.2.2.4 asks for exactly this pair: no destination count, then no count and no volume.
    "agg_flow_no_dst_count": _without("dst_count"),
    "agg_flow_no_dst_count_no_volume": _without("dst_count", "volume"),
    "agg_flow_no_entropy": _without("dst_spread"),
    "agg_flow_no_dst_spread": _without("dst_spread", "dst_count"),
    "agg_flow_artifact": _base + ARTIFACT_FLOW_FEATURES,
}

class Status(StrEnum):
    OK = "ok"
    OK_WEAK = "ok_weak"
    EXCLUDE_BOUNDARY = "exclude_boundary"
    EXCLUDE_UNLOGGED = "exclude_unlogged"
    EXCLUDE_TEST = "exclude_test"


class Subclass(StrEnum):
    BENIGN = "benign"
    BENIGN_HARD = "benign_hard"
    CARPET = "carpet"
    FOCUSED = "focused"
    UNLOGGED = "unlogged"


USABLE_STATUSES = frozenset({Status.OK, Status.OK_WEAK})

_leaked = {f for cols in FEATURE_SETS.values() for f in cols} & FORBIDDEN_FEATURES
if _leaked:
    raise ValueError(f"FEATURE_SETS contain forbidden columns: {sorted(_leaked)}")


_NOT_IN_SNAPSHOT = frozenset({"CAPTURE_FILES", "CAPTURES"})


def snapshot() -> dict:
    """Every UPPER_CASE constant except paths, as plain JSON values.

    `CAPTURE_FILES` holds paths. `CAPTURES` is the whole registry, and registering a new capture must
    not make the artifacts of other captures stale; the captures in use are recorded via CAPTURE_SETTINGS.

    Auto-collected on purpose: a hand-kept list would drift the first time
    someone adds a constant and forgets the list.
    """
    out = {}
    for name, v in globals().items():
        if not name.isupper() or isinstance(v, Path) or name in _NOT_IN_SNAPSHOT:
            continue
        out[name] = sorted(v) if isinstance(v, frozenset) else v
    # Round-trip through JSON so the live values compare equal to what a meta file
    # gives back (int dict keys become strings, tuples become lists).
    return json.loads(json.dumps(out))
