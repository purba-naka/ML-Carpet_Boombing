# Phase 8 findings (tuning)

Setup (D16, cut at O12): 10 random settings per model, 5 group folds on trainval, score = PR-AUC of carpet, ties inside one fold standard deviation go to the simplest model. Hold-out untouched.
Made by `scripts/run_tune.py`. Full tables in `reports/experiments/phase8_tuning/`.

| model | features | weak in train | picked | best of 10 | default | range over 10 settings |
|---|---|---|---|---|---|---|
| RF | agg | yes | 0.913 ± 0.079 | 0.920 | 0.917 ± 0.075 | 0.009 |
| RF | agg | no | 0.856 ± 0.145 | 0.860 | 0.856 ± 0.145 | 0.003 |
| RF | agg_flow | yes | 0.951 ± 0.048 | 0.965 | 0.964 ± 0.035 | 0.014 |
| RF | agg_flow | no | 0.856 ± 0.145 | 0.890 | 0.884 ± 0.109 | 0.034 |
| XGBoost | agg | yes | 0.917 ± 0.072 | 0.917 | 0.906 ± 0.086 | 0.017 |
| XGBoost | agg | no | 0.865 ± 0.138 | 0.876 | 0.867 ± 0.132 | 0.021 |
| XGBoost | agg_flow | yes | 0.961 ± 0.035 | 0.964 | 0.962 ± 0.035 | 0.005 |
| XGBoost | agg_flow | no | 0.867 ± 0.134 | 0.885 | 0.875 ± 0.134 | 0.034 |

## What the numbers say

1. **Tuning changes nothing that matters.** The best setting beats the default by at most 0.012 PR-AUC (and by 0.001 or less in 5 of 8 cases), while the fold standard deviation is 0.035 to 0.145. All gains are inside the noise. The default parameters are as good as any of the 10 settings.
2. **The tie rule picks the same setting every time.** RF: 200 trees, depth 4, min leaf 5. XGBoost: 200 trees, depth 4, learning rate 0.03. This is a consequence of point 1, not a sign that these are the best parameters. They are the simplest of a set of equally good ones.
3. **One case is slightly worse when "picked".** RF agg_flow with weak windows: the simple setting scores 0.951, the default 0.964. The difference (0.013) is a third of one fold standard deviation. Not worth a rule exception.
4. **The weak windows effect from phase 7 stays larger than any tuning effect.** Weak in training raises PR-AUC by 0.06 to 0.09 (0.856 to 0.913 for RF agg), 5 to 10 times more than tuning ever gives. What goes into the training set matters more than the parameters.

## What I did not do

- No tuning of the decision threshold. Default 0.5 stays.
- No search over feature sets. The two sets from D9 are compared as they are.
- 10 settings is a small sample of a space with thousands of points. It tells us the model is not sensitive to these parameters, not that the optimum was found.

## For phase 9 and 10

Use the picked parameters (`chosen_params.json`) for both models, so that ablations differ only by features and by weak windows, not by parameters.
