# Phase 9 findings (ablation and robustness)

Setup: the phase 8 picked parameters on every run, 5 group folds on trainval, both weak settings. Hold-out untouched.
Two scripts: `scripts/run_ablation.py` (feature sets) and `scripts/run_robustness.py` (importance, seeds, bootstrap, per scenario recall). Full tables in `reports/experiments/phase9_ablation/` and `reports/experiments/phase9_robustness/`, summary also in `reports/tables/ablation.csv`.

## Ablation: feature sets (PR-AUC, mean over 5 folds; recall in brackets)

| set | features | RF weak1 | RF weak0 | XGB weak1 | XGB weak0 |
|---|---|---|---|---|---|
| agg | 12 | 0.913 [0.815] | 0.856 [0.815] | 0.917 [0.831] | 0.865 [0.807] |
| agg_flow | 45 | 0.951 [0.860] | 0.856 [0.815] | 0.961 [0.868] | 0.867 [0.807] |
| agg_flow_no_src | 44 | 0.951 [0.860] | 0.860 [0.815] | 0.961 [0.868] | 0.867 [0.807] |
| agg_flow_no_udp | 44 | 0.951 [0.860] | 0.860 [0.815] | 0.960 [0.868] | 0.867 [0.807] |
| agg_flow_no_volume | 42 | 0.951 [0.860] | 0.860 [0.815] | 0.961 [0.868] | 0.867 [0.807] |
| agg_flow_dst_only | 39 | 0.951 [0.860] | 0.862 [0.815] | 0.959 [0.868] | 0.875 [0.807] |
| agg_flow_artifact | 72 | 0.959 [0.853] | 0.856 [0.815] | 0.969 [0.853] | 0.867 [0.807] |

The artifact set adds the 27 D19 features (Bwd and TCP flag columns, 9 columns x mean/std/max). dst_only keeps only the 6 destination spread features plus the 33 flow features (it also drops `n_src_dst_pairs`, a source count under another name).

## Robustness

Feature importance (RF impurity and permutation on fold 0 as judge, XGB gain), top rows:

| feature | RF impurity | RF permutation (AUC drop) | XGB gain |
|---|---|---|---|
| dst_entropy_norm | 0.486 | 0.080 | 0.372 |
| dst_entropy | 0.195 | 0.008 | 0.092 |
| Flow Bytes/s__max | 0.038 | 0.022 | 0.031 |
| n_unique_dst | 0.034 | -0.002 | 0.084 |
| n_unique_src | 0.004 | 0.000 | 0.028 |

Seed stability (5 model seeds, spread min..max): RF weak1 recall 0.853..0.868, PR-AUC 0.950..0.955. XGB weak1 recall 0.868 on all five seeds. Weak0: recall constant (0.815 RF, 0.807 XGB).

Bootstrap over runs (1000 draws, 37 runs resampled with replacement):

| model | weak | recall q50 [q025, q975] | precision | FPR | PR-AUC |
|---|---|---|---|---|---|
| RF | yes | 0.863 [0.752, 0.957] | 0.900 [0.711, 0.985] | 0.024 [0.003, 0.058] | 0.941 [0.861, 0.985] |
| XGB | yes | 0.872 [0.759, 0.964] | 0.938 [0.823, 0.989] | 0.015 [0.003, 0.035] | 0.949 [0.878, 0.989] |
| RF | no | 0.818 [0.671, 0.952] | 1.000 [1.000, 1.000] | 0.000 | 0.864 [0.734, 0.968] |
| XGB | no | 0.814 [0.647, 0.945] | 1.000 [1.000, 1.000] | 0.000 | 0.894 [0.752, 0.975] |

Carpet recall by scenario and window status (weak in train, the honest setting):

| cut | value | RF recall | XGB recall |
|---|---|---|---|
| scenario | carpet-low | 0.889 | 0.907 |
| scenario | carpet-mid | 0.824 | 0.824 |
| scenario | carpet-stealth | 0.893 | 0.893 |
| n_src | 1 | 0.723 | 0.738 |
| n_src | multi | 1.000 | 1.000 |
| status | ok | 0.991 | 0.991 |
| status | ok_weak | 0.261 | 0.304 |

## What the numbers say

1. **agg_flow beats agg, so the PDF combination claim holds.** With weak windows in train, the flow features add 0.045 recall and 0.038 PR-AUC (RF), 0.037 and 0.044 (XGB). This is the largest ablation effect, and it survives the fold spread.
2. **The shortcuts were never used.** Removing `n_unique_src` (source count), `udp_ratio` (TCP artifact) or the volume features changes recall by 0.000 and PR-AUC by at most 0.002. Even the set with only destination spread plus flow features (`dst_only`, 39 of 45) scores the same. The worry from the analysis, that the model counts sources or smells UDP, does not survive the measurement.
3. **The artifact columns add nothing that matters.** Adding the 27 D19 features moves PR-AUC by +0.008 (RF) and +0.007 (XGB) and recall by -0.007 and -0.015, inside the fold spread (std 0.034 to 0.048). Leaving them out in D15 cost nothing.
4. **One feature does most of the work: `dst_entropy_norm`.** RF impurity 0.486, permutation AUC drop 0.080, XGB gain 0.372. The shortcut features sit near zero on all three measures (`n_unique_src` impurity 0.004, `udp_ratio` 0.002). This is the same story as finding 2, seen from inside the model.
5. **Model seed is not a factor.** Five seeds move recall by at most 0.015 and PR-AUC by at most 0.005, both far under the fold spread.
6. **Run level uncertainty is wide and honest.** Bootstrapping runs (not windows) gives recall 0.863 [0.752, 0.957] for RF weak1: with only 37 runs, single runs carry real weight. Window level numbers look steadier than they are.
7. **The recall gap is single source, not scenario.** Recall is flat across carpet-low, mid, stealth (0.82 to 0.91). The split is by source count: 1.00 for multi source windows, 0.72 to 0.74 for single source, and inside single source it is the weak windows (0.26) against ok windows (0.99). The ceiling from phase 7 is confirmed: weak windows are the whole story, not the attack type.

## What I did not do

- No re-tuning per ablation set. All rows share the phase 8 parameters, so they differ only in features (that is the point of the table).
- Permutation importance only for RF, as planned. XGB gets gain only, and gain is biased toward high cardinality features.
- `dst_only` keeps the 33 D15 flow features. Some of those may correlate with the artifact families, so "artifact free" is only fully tested by the `agg_flow_artifact` row, not by `dst_only`.
- No threshold tuning anywhere: 0.5 stays.

## For phase 10

- The candidate for the final model is RF or XGB on `agg_flow` (or `dst_only`, same score) with weak windows in train, phase 8 parameters, seed 42.
- The honest claim for the thesis: window level PR-AUC 0.95 to 0.96 on CV, run level recall around 0.86 to 0.87 with a wide interval, single source weak windows are the known blind spot.
