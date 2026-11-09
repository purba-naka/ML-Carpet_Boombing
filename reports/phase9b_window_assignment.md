# Window assignment experiment (D21)

Branch `experiment`. Question: are the weak windows a measurement artifact of "a flow belongs to the window it starts in" (PDF 3.2.3.1)? Test: cut every flow over the windows it lasts through (`spread`), packets and bytes split by seconds spent in each window, then rerun CV. CV on trainval only, hold-out not read. Phase 8 params, `agg_flow`, same folds.
Made by `scripts/run_window_experiment.py` (run once per `CARPET_WINDOW_ASSIGNMENT`, then `--compare`). Artifacts: `data/processed_spread/`, `reports/experiments_spread/`.

## Numbers (CV, mean over 5 folds)

| assignment | model | weak in train | recall | precision | FPR | PR-AUC |
|---|---|---|---|---|---|---|
| start (PDF) | RF | yes | 0.860 | 0.908 | 0.026 | 0.951 |
| start (PDF) | XGB | yes | 0.868 | 0.945 | 0.015 | 0.961 |
| spread | RF | yes | 0.992 | 1.000 | 0.000 | 0.994 |
| spread | XGB | yes | 0.992 | 1.000 | 0.000 | 0.994 |

With `spread` weak windows are 1 of 186 carpet windows (was 33), and the weak-in-train switch no longer matters (identical rows). Carpet recall by status: `ok` 132/132, the one weak window (run C1) missed.

## What it says

1. **Weak windows were a measurement artifact.** 63 of 64 disappear. The one left (C1, 331 s into the run) has no spanning flow, unexplained.
2. **The recall ceiling of 0.81 was never the model.** Recall goes 0.860 to 0.992 with the same models, params and folds.
3. **The testbed is now trivially separable.** One threshold on `n_unique_dst` gives recall 0.992, precision 1.000, FPR 0.000. One threshold on `dst_entropy_norm` gives PR-AUC 1.000. A model with 45 features does not beat a one-line rule. This was visible in phase 7 (threshold tied the models) and `spread` makes it complete. The honest reading: on this testbed carpet bombing means "many destinations", and any destination-spread feature finds it.
4. **The earlier false alarms vanished too (0 in CV).** The F6-style confusion (XGB, 12 false alarms on hold-out) is not visible in CV, so this experiment says nothing new about it.

## What I did not do and what this does not prove

- Not a replacement for the PDF method. `start` stays the main method (PDF 3.2.3.1). `spread` is a measured ablation of window assignment.
- The even split assumes a constant packet rate over the flow. It is an approximation, never checked against the pcap.
- Flow-level columns (duration, rates) stay whole in every piece, so they describe the full flow, not the part inside the window.
- A flow now counts in every window it touches, so `n_flows` grows 0.07 percent (9,765,940 pieces from 9,758,984 flows). Tiny, but not zero.
- No hold-out result for `spread`. The hold-out was opened for `start`, so a `spread` number there would not be a clean test.
- It does not show the model generalises. It shows the testbed is easy once the measurement is fixed.

## Checks run

- `start` outputs identical to before the change (windows, aggregates, flow summary, `assert_frame_equal`).
- One former weak window (C11, w=1793628420) recomputed by hand from the raw flows: 32 destinations, 120,331 packets (pipeline 120,334, rounding), entropy 0.9835 both. `start` had 3 destinations, 257 packets.
- Hold-out groups identical in both assignments (same 11 groups, 183 windows).
- Shuffled-label alarm under `spread`: ROC-AUC 0.489.
- Packet and byte sums conserved over 500 random flows (`tests/test_windows.py`).
