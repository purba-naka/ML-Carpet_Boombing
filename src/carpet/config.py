"""Single source of truth: paths, constants, enums. Nothing else in the repo retypes these values."""
import json
from enum import StrEnum
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW_FLOW_CSVS = {s: ROOT / f"dataset/csv/sesi{s}_all.csv/sesi{s}_all.csv" for s in (1, 2, 3)}
ATTACK_LOG = ROOT / "dataset/Attack_log-20261109T113913Z-1-001/Attack_log/attack_log.csv"
INTERIM = ROOT / "data/interim"
PROCESSED = ROOT / "data/processed"
REPORTS = ROOT / "reports"
MODELS = ROOT / "models"

FLOWS = INTERIM / "flows.parquet"
FLOWS_CLEAN = INTERIM / "flows_clean.parquet"
WINDOWS_LABELED = PROCESSED / "windows_labeled.parquet"
SPLIT = PROCESSED / "split.parquet"
FEATURES_AGG = PROCESSED / "features_agg.parquet"
FEATURES_FLOW = PROCESSED / "features_flow.parquet"
FEATURES_ARTIFACT = PROCESSED / "features_artifact.parquet"
TABLES = REPORTS / "tables"
RAW_ROWS_EXPECTED = {1: 3_833_012, 2: 2_444_150, 3: 3_490_688}

# Zero in every raw row (verified by run_clean). Kept in the flow table, never offered as features.
CONSTANT_COLUMNS = ("Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "URG Flag Count",
                    "CWR Flag Count", "ECE Flag Count", "Fwd Bytes/Bulk Avg",
                    "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg")

SEED = 42
WINDOW_SECONDS = 60
VICTIM_PREFIX = "198.51.100."
ATTACKER_IP = "192.168.1.65"
BENIGN_SRC_EXTRA = "8.6.0.1"
DNS_PORT = 53
UDP = 17

TEST_RUN = "TEST"
UNLOGGED_MIN_FLOWS = 50
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

# D16: randomized search, small on purpose (one threshold already ties the models on this data).
TUNE_COMBINATIONS = 10
TUNE_SPACE = {
    "rf": {"n_estimators": [100, 200, 300, 500], "max_depth": [4, 6, 8, 12, 20, None],
           "min_samples_leaf": [1, 2, 3, 5], "max_features": ["sqrt", 0.5, 1.0]},
    "xgb": {"n_estimators": [100, 200, 300, 400], "max_depth": [3, 4, 5, 6],
            "learning_rate": [0.03, 0.05, 0.1, 0.2], "subsample": [0.7, 0.85, 1.0],
            "colsample_bytree": [0.7, 0.85, 1.0]},
}

# Columns that define labels or identify rows. They must never reach a model.
FORBIDDEN_FEATURES = frozenset({
    "attacker_flows", "run_id", "group", "subclass", "status", "label", "near_attack",
    "w", "window_start", "subnet",
    "Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "Timestamp", "ts", "session",
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

# Every removal starts from agg_flow, the full set, so each row shows what losing that feature
# group costs. dst_only also drops n_src_dst_pairs: for multi source runs it is the source count
# under another name, and keeping it would fake the "destination spread only" claim.
_base = AGG_FEATURES + FLOW_FEATURES
FEATURE_SETS = {
    "agg": AGG_FEATURES,
    "agg_flow": _base,
    "agg_flow_no_src": tuple(f for f in _base if f != "n_unique_src"),
    "agg_flow_no_udp": tuple(f for f in _base if f != "udp_ratio"),
    "agg_flow_no_volume": tuple(f for f in _base if f not in ("total_pkts", "total_bytes", "n_flows")),
    "agg_flow_dst_only": tuple(f for f in _base if f not in
                               ("total_pkts", "total_bytes", "n_flows", "n_unique_src",
                                "n_src_dst_pairs", "udp_ratio")),
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
    CARPET = "carpet"
    FOCUSED = "focused"
    UNLOGGED = "unlogged"


USABLE_STATUSES = frozenset({Status.OK, Status.OK_WEAK})

_leaked = {f for cols in FEATURE_SETS.values() for f in cols} & FORBIDDEN_FEATURES
if _leaked:
    raise ValueError(f"FEATURE_SETS contain forbidden columns: {sorted(_leaked)}")


def snapshot() -> dict:
    """Every UPPER_CASE constant except paths, as plain JSON values.

    Auto-collected on purpose: a hand-kept list would drift the first time
    someone adds a constant and forgets the list.
    """
    out = {}
    for name, v in globals().items():
        if not name.isupper() or isinstance(v, Path) or name == "RAW_FLOW_CSVS":
            continue
        out[name] = sorted(v) if isinstance(v, frozenset) else v
    # Round-trip through JSON so the live values compare equal to what a meta file
    # gives back (int dict keys become strings, tuples become lists).
    return json.loads(json.dumps(out))
