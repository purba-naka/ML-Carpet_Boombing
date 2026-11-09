# EDA findings (phase 5)

Data: 648 trainval windows, 37 groups. Hold-out is cut off at load time (`eda.load_trainval`), a check raises if a hold-out run slips in.
Numbers come from `scripts/run_eda.py` and the tables in `reports/tables/eda_*.csv`.

## Findings

1. **Balance.** benign 431, carpet 133 (23 weak), focused 84 (25 weak). Carpet is 20 percent of trainval windows.
2. **The PDF hypothesis holds.** Median `dst_entropy_norm`: carpet 0.99, focused 0.03, benign 0.22. Median `concentration_ratio`: carpet 0.03, focused 0.99, benign 0.94. Entropy alone separates carpet from focused with AUC 0.94.
3. **No shortcut at the 0.99 level.** Best single feature AUC is 0.93 (carpet vs rest). Alone, no feature is enough, so the model has to combine them, which is what the PDF argues.
4. **Weak carpet windows look like benign.** Median unique dst: 4 (weak) vs 31 (ok carpet). Median packets: 187 vs 74,930. Expect these 23 windows to be misses for any model. Confirms the D3 plan to report with and without them.
5. **Source count is a real shortcut, but only between sub-populations.** Multi-source runs have a median of 74,709 unique sources, single-source runs have 3 (same as benign). On multi-source runs entropy, unique dst and concentration reach AUC 1.0 against focused. On single-source runs they drop to 0.85, 0.76, 0.85. So most of the carpet-vs-focused signal on trainval comes from the 82 multi-source windows. The 135 single-source windows are the hard part. Report both.
6. **Single source carpet is thin on packets.** Median `total_pkts` single-source carpet 35,686, focused 17,432. Total packets alone gives AUC 0.535 for carpet vs focused on single-source runs. Volume features do not help there.
7. **`udp_ratio` separates mostly through volume dilution.** Median 0.40 for benign (every benign window has TCP), 0.998 for carpet, 0.996 for focused. Every carpet and focused window also has a little non-UDP traffic (ratio below 1), but attack packets drown it. Gives AUC 0.96 for carpet vs benign. Benign includes TCP and attacks are UDP DNS only by testbed design, so a model can learn "mostly UDP means attack", which says nothing about carpet bombing. Plan ablation without `udp_ratio`, and read a high importance of it as a testbed artifact.
8. **Correlated aggregate pairs (Spearman >= 0.95):** `dst_entropy` and `concentration_ratio` (-0.996), `total_pkts` and `max_pkts_per_dst` (0.985), `dst_entropy_norm` and `concentration_ratio` (-0.975), `dst_entropy` and `dst_entropy_norm` (0.957). Trees cope with this, but feature importance will split between the pairs. Read importances by group, not single feature.
9. **Flow-level columns.** 67 usable (76 minus constants and zero-variance). 65 pairs correlate above 0.98, so a small set is enough. Biggest effect sizes (Cohen d on log scale, carpet vs benign and vs focused) belong to the inter-arrival times (`Bwd IAT Min` 1.56, `Bwd IAT Mean`), `SYN Flag Count`, and `Packet Length Std`.
10. **Part of the flow-level signal is the same dilution effect.** `SYN Flag Count` window mean is 0.28 in benign and 0.27 in focused, against 0.002 in carpet, and correlates 0.535 (Spearman) with the TCP share of a window. Flow-level means are also dominated by the huge merged flows of single-source runs. Not yet measured: how much of each column's effect survives when `udp_ratio` and `n_flows` are controlled for.
11. **No NaN in window-level flow means.** The 4,065 blanked flow cells vanish inside window averages. Imputation only matters if a window has all cells blank, and none do.

## Risks found

- Hold-out has 3 multi-source runs (C10, C12, F6) and 3 single-source runs (C11, C9, F2). Multi-source windows are easy (finding 5), single-source ones are hard. Report both separately, a pooled number would hide it.
- Testbed artifact: TCP exists only in benign, so a model can learn "almost all UDP means attack". Ablation without `udp_ratio` and without flag columns is required before claiming anything about carpet bombing itself.
- 20 percent positives, 37 groups. CV fold spread will be large (see open decision O10).
- Single-source carpet windows with a few huge flows (finding 6) make flow-level means unreliable. Prefer max and std over mean for those columns.

## For the human: D15 flow-level columns (decision needed)

Proposed 12 columns, picked by effect size and with pairs above 0.9 Spearman removed: `Bwd IAT Min`, `Bwd IAT Mean`, `SYN Flag Count`, `Packet Length Std`, `Bwd Bulk Rate Avg`, `Bwd IAT Total`, `Subflow Bwd Packets`, `Bwd Packets/s`, `Bwd IAT Std`, `Bwd Bytes/Bulk Avg`, `Idle Min`, `Total Length of Fwd Packet`.

Concerns: eight of the twelve are Bwd (reply direction) columns. If attack flows mostly get no reply, these columns would be near zero for attacks by construction, another possible testbed artifact. This is a guess, not measured yet. `SYN Flag Count` is the TCP artifact. The PDF's own examples (flow duration, packet counts and lengths, inter-arrival time) are barely in the top list.
