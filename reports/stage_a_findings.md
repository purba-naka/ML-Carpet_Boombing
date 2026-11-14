# Stage A findings (PLAN_PIPELINE PL-1 to PL-7)

Setup: capture S1 only, `spread` window assignment (D22), trainval only (648 windows, 37 groups, 133 carpet),
5 group folds, weak windows in train (D24, one weak window left). Hold-out v1 not trained on, scored or plotted.
Numbers come from `reports/experiments_spread/` and `reports/tables_spread/`, logs in
`reports/experiments_spread/stage_a.log` and `stage_a2.log`.

## Results

| What | Number | Source |
|---|---|---|
| One threshold on `dst_entropy_norm` | recall 0.984, precision 1.000, PR-AUC 1.000 | `phase7_baselines` |
| One threshold on `n_unique_dst` | recall 0.992, precision 1.000, PR-AUC 0.995 | `phase7_baselines` |
| RF `agg_flow` | recall 0.992, precision 0.992, FPR 0.002, PR-AUC 0.997 | `phase7_baselines` |
| XGBoost `agg_flow` | recall 0.992, precision 1.000, FPR 0.000, PR-AUC 0.994 | `phase7_baselines` |
| Shuffled labels | ROC-AUC 0.52 to 0.55 | `phase7_baselines` |
| Tuning, 30 settings per model | range of mean PR-AUC across settings 0.000 to 0.003 | `phase8_tuning/run.log` |
| Seeds (5) | recall 0.992 on every seed, PR-AUC 0.994 to 0.997 | `phase9_robustness/seed_spread.csv` |
| Compute per window (busiest of 30) | features 674 ms, RF 19 ms, XGBoost 1 ms | `latency/summary.csv` |
| Worst detection delay | 60 s window + 120 s flow timeout + 0.7 s = 180.7 s | `latency/note.txt` |

Ablation (mean over folds, `tables_spread/ablation.csv`):

| Set | RF FPR | XGB FPR | RF PR-AUC | XGB PR-AUC |
|---|---|---|---|---|
| `agg_flow` (45) | 0.002 | 0.000 | 0.997 | 0.994 |
| `flow` only (33, defaults) | 0.031 | 0.033 | 0.992 | 0.992 |
| without destination count (PDF 3.2.2.4) | 0.002 | 0.000 | 0.994 | 0.994 |
| without destination count and volume (PDF 3.2.2.4) | 0.000 | 0.000 | 0.997 | 0.994 |
| without entropy group | 0.029 | 0.002 | 0.997 | 0.994 |
| without entropy and count (no destination spread at all) | 0.029 | 0.033 | 0.997 | 0.992 |

Recall stays 0.985 to 0.992 in every row.

Grouped permutation (PR-AUC drop when a whole group is shuffled, every fold as judge):
RF `dst_spread` 0.042, every other group 0.003 or less. XGBoost `dst_count` 0.355, every other group 0.000.

## What the numbers say

1. **Fixing the window assignment removes the recall ceiling.** CV recall goes from 0.860 (`start`, v1) to 0.992.
   The one window still missed is the last weak window (run C1).
2. **On S1 the models are not needed.** A single threshold on one feature reaches PR-AUC 1.000. RF and XGBoost
   tie it. This is a property of the data (carpet 16 to 64 destinations, benign at most 10), not of the code.
3. **Tuning has nothing to tune.** All 30 settings score the same within 0.003. The picked parameters are the
   simplest of the tie (`chosen_params.json`), and the search never ended below the defaults.
4. **Destination spread carries the decision, and the two spread groups stand in for each other.**
   Removing the destination count or the volume (the PDF 3.2.2.4 ablation) changes nothing, because entropy
   still tells the same story. Removing entropy lets false alarms rise for RF (0.002 to 0.029). XGBoost leans
   on `n_unique_dst` instead (permutation drop 0.355). Without any destination spread, FPR rises to about 0.03.
5. **Flow-level features alone also find carpet windows, but with ten times the false alarms**
   (FPR 0.031 against 0.002). This is the only measurable case for the aggregates on S1: they cut false alarms.
6. **Source count, UDP share and the artifact columns stay unused**, as in v1.
7. **Latency is set by the flow exporter, not the model.** Compute per window is under one second, the
   delay budget is dominated by the 60 s window and the 120 s CICFlowMeter timeout.

## Limits

- One capture, 37 trainval groups. Everything near 0.99 means the testbed is easy, not that the detector
  generalises. The new captures in `PLAN_DATASET.md` exist to change that.
- RF native importance spreads over correlated features, so single feature permutation is near zero for
  RF. Read the grouped table, not the single features.
- The `flow` only set uses default parameters, the others use the tuned `agg_flow` ones. Since tuning moved
  nothing (finding 3), this does not change the comparison.
- `run_final.py --rehearse` was checked mechanically on fold 0. `--final` was not run: hold-out v1 is burned,
  and the next real one is capture B (PL-12).
