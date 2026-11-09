# Hard carpet probe (stand-in for real hard runs)

Branch `experiment`, `CARPET_WINDOW_ASSIGNMENT=spread`, `scripts/run_hard_probe.py`. Trainval only, hold-out not read.

**What it is.** Every carpet window of trainval (133) is thinned to k of its destinations (k = 4, 6, 8, 12). The flows to the other destinations are dropped, the per destination rate stays, so total packets fall with k like a real narrower carpet. Features are recomputed from the thinned flows. Out of fold: a model never trains on the thinned windows, and the training folds hold the original data only. Negatives are untouched, so false alarms stay at the CV level.
**What it is not.** No real attacker with k targets, no uneven rates, no benign traffic crowding the same /24. It is a cheap stand-in, not a replacement for real hard runs.

## Recall of carpet windows by k (mean of 3 thinning seeds, seed 0 in the CSV)

| model | original | k=12 | k=8 | k=6 | k=4 |
|---|---|---|---|---|---|
| RF | 0.992 | 0.992 | 0.985 to 0.992 | 0.91 to 0.94 | 0.63 to 0.66 |
| XGBoost | 0.992 | 0.62 to 0.64 | 0.12 to 0.14 | 0.11 to 0.15 | 0.12 to 0.17 |
| threshold `n_unique_dst` (cut 15) | 0.992 | 0.000 | 0.000 | 0.000 | 0.000 |
| threshold `dst_entropy_norm` (cut 0.837) | 0.985 | 0.925 | 0.910 | 0.857 | 0.812 |

False alarm rate on the untouched negatives is 0.000 for every row, so none of this is bought with false alarms.

## What it says

1. **The three methods that look equal on the real data split apart as soon as the carpet gets narrower.** On the original windows all four score 0.985 to 0.992. At 8 destinations: RF 0.99, entropy threshold 0.91, XGBoost 0.13, destination count threshold 0.00.
2. **Only the count threshold is broken for a simple reason.** The cut it learned is 15 destinations, so anything with 12 or fewer is negative by construction. Real benign never exceeds 10 here, so the cut sits inside an empty gap and the data gave it no reason to move lower.
3. **XGBoost relies on `n_unique_dst` (gain 114 of about 160 total) and falls with it.** RF spreads its weight over `concentration_ratio`, `dst_entropy`, `dst_entropy_norm`, `n_unique_dst` (0.28, 0.26, 0.23, 0.22), so it survives. This is the first measurement where RF clearly beats XGBoost for a reason that is not noise, and it matches the PDF ranking RF as main model.
4. **Why the entropy threshold holds up.** Even k=4 carpet keeps entropy near 1.0 (traffic is spread evenly over the 4), while benign never goes above 0.52. A rate independent measure of spread survives thinning, a raw count does not.
5. **The training data is the limit, not the algorithm.** The smallest real carpet in trainval has 5 destinations in a window and the median is 31. The models never saw the 5 to 12 range, so the answer there is an extrapolation. This is the argument for real hard runs.

## Caveats

- The thinning keeps the per destination rate. A real 4 target carpet might also send faster per target. That would change `total_pkts` and the rate features, not the destination features that drive these results.
- Thinned windows have `concentration_ratio` and `total_pkts` outside the original carpet range (the diagnosis shows `n_unique_dst`, `dst_entropy`, `concentration_ratio` leave the 1 to 99 percentile range of the original carpet in 100 percent of k=8 rows). RF tolerates that, XGBoost does not. This is real model behaviour on shifted data, but it is shift made by me, so read the numbers as direction and size, not as a prediction.
- Three thinning seeds, one set of folds. Recall by k moves by at most 0.04 between seeds for RF and 0.05 for XGBoost.
- The one line rules are not "wrong": their cut came from a gap in the data that real narrow carpet would close. That is also why this probe is a stand-in for runs that fill the gap.
