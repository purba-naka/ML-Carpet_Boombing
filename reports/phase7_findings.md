# Phase 7 findings (baselines and first models)

Setup: trainval only (648 windows, 37 groups), 5 group folds (D17), default parameters, no tuning. Hold-out untouched.
Numbers: `reports/experiments/phase7_baselines/`, made by `scripts/run_baselines.py`.
Positive class is carpet bombing. Each cell is the mean over 5 folds.

| model | features | weak in train | recall | precision | false positive rate | PR-AUC |
|---|---|---|---|---|---|---|
| predict all negative | - | - | 0.000 | 0.000 | 0.000 | 0.205 |
| one threshold, `dst_entropy_norm` | 1 | either | 0.807 | 0.984 to 1.000 | 0.000 to 0.004 | 0.896 |
| one threshold, `n_unique_dst` | 1 | either | 0.807 | 0.993 | 0.002 | 0.872 |
| Random Forest | agg (12) | yes | 0.838 | 0.832 | 0.046 | 0.917 |
| Random Forest | agg (12) | no | 0.815 | 1.000 | 0.000 | 0.856 |
| Random Forest | agg_flow (45) | yes | 0.815 | 0.952 | 0.012 | 0.964 |
| Random Forest | agg_flow (45) | no | 0.815 | 1.000 | 0.000 | 0.884 |
| XGBoost | agg (12) | yes | 0.831 | 0.895 | 0.029 | 0.906 |
| XGBoost | agg (12) | no | 0.807 | 1.000 | 0.000 | 0.867 |
| XGBoost | agg_flow (45) | yes | 0.875 | 0.883 | 0.038 | 0.962 |
| XGBoost | agg_flow (45) | no | 0.807 | 1.000 | 0.000 | 0.875 |

Leakage alarm (train labels shuffled): ROC-AUC 0.49 for all three models, PR-AUC 0.23 against a positive rate of 0.205. The pipeline falls to chance, so no sign of label leakage through features or folds.

## What the numbers say

1. **The recall of 0.81 is a data ceiling, not a model weakness.** 23 of 133 trainval carpet windows are weak (no attacker flow in the window), and all 23 are single-source. 110 / 133 = 0.827. On the 110 normal carpet windows every model gets recall 0.98 to 0.99. The weak windows are missed by every model that does not train on them (recall 0.000).
2. **A single threshold on one feature does about as well as the models.** `dst_entropy_norm` alone gives recall 0.807 and precision 0.98 to 1.0. Trained without weak windows, RF and XGBoost do not beat it in PR-AUC (0.856 to 0.884 against 0.896). This testbed separates carpet from benign and focused almost entirely by how evenly packets spread over destinations. That agrees with the PDF hypothesis, and it also means the data is easy.
3. **Training on weak windows buys a little recall and costs false alarms.** With weak windows in training, RF recall on weak windows rises to 0.13 (RF agg) and XGBoost agg_flow to 0.35, but false alarms appear on benign windows near an attack: 6 of 76 for RF agg_flow, 7 of 76 for RF agg. Far benign windows: 0 of 355 for the agg_flow models, but 15 of 355 for RF agg. The weak windows look like benign by design, so labelling them carpet teaches the model to flag benign-looking traffic. This is the label noise risk raised when the weak flag was introduced.
4. **`agg_flow` helps only when weak windows are in training**, and then mainly through PR-AUC (0.964 against 0.917 for RF). Without weak windows the two feature sets are within 0.03 of each other, inside the fold spread.
5. **Fold spread is large.** RF agg_flow recall per fold: 0.56, 0.96, 0.77, 0.79, 1.00. Fold 0 has C3, C14 which hold many weak windows. A single mean hides this, always show the spread.
6. **Focused (single target) attacks are never flagged.** 0 of 84 windows, with every model, for single-source and multi-source runs. The carpet vs focused part of the thesis question is solved on this data.

## Limits of these numbers

- Defaults only, no tuning, and the hold-out is not used. Do not quote them as final results.
- Trainval has 10 carpet runs and 6 focused runs. Fold standard deviations are over 5 folds of 2 to 4 runs each.
- Everything comes from one attacker, one victim subnet, DNS over UDP. Benign always has TCP and attacks never do (see EDA findings 7 and 10), so part of the benign vs carpet separation may be a testbed artifact. The ablation without `udp_ratio` is still to be run.
