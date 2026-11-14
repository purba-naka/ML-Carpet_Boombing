# Window assignment: `start` vs `spread` (PL-2, D22)

`start` is the proposal method (PDF 3.2.3.1): a flow lands in the window it starts in. `spread` cuts a flow
into one piece per window it touches, packets and bytes split by the seconds spent in each window.
Since D22 `spread` is the main method and `start` stays as the comparison.

Numbers from `scripts/run_label.py` and `scripts/run_split.py`, both assignments on the same clean flows.

| | start | spread |
|---|---|---|
| windows | 921 | 921 |
| flow rows counted (pieces) | 9,758,984 | 9,765,940 |
| packets over all windows | 19,602,588 | 19,602,588 |
| usable benign | 533 | 533 |
| usable carpet (weak) | 186 (33) | 186 (1) |
| usable focused (weak) | 112 (31) | 112 (0) |
| excluded boundary / unlogged | 60 / 30 | 60 / 30 |

What this says:

1. No packet is lost or made up: the packet total is identical.
2. Weak windows drop from 64 to 1. They were attack minutes where the attacker's long flow had started a
   minute earlier, so under `start` the window held no attack traffic at all while carrying the carpet label.
3. The split keeps the same runs in the same folds (seeded on groups, and groups did not change).
   Hold-out composition: 102 benign, 53 carpet (0 weak), 28 focused (0 weak).
4. The one weak window left sits in run C1 (fold 1).

The hold-out v1 rows were relabeled too, because labeling runs on all windows. They were not trained on,
scored or plotted.
