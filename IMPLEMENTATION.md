# IMPLEMENTATION.md

Plan and live status for the carpet bombing detector. Read `AGENT.md` first (rules, environment, coding style). This file says **what to build, in which order, and how to prove each step works**.

Do one step at a time. After each step: run its acceptance checks, update the status table, report real numbers.

## 0. Decisions made by the human (current, changeable only by the human)

Closed means "do not reopen on your own", not "frozen forever". The human will run many experiments and change decisions. How changes work is in section 8 (change protocol). Short version: the human says change, the agent logs it, regenerates everything downstream, and never mixes results from two versions of a decision.

| # | Decision |
|---|---|
| D1 | Scope now: PNETLab data only. Code is shaped so another dataset (CIC-DDoS2019, MAWI) can be added later by writing one new reader in `io.py`. Do not implement those readers now. |
| D2 | Split: GroupKFold by `group` for model selection, plus whole runs held out as an untouched final test. Benign windows are grouped in 30 minute blocks. |
| D3 | Weak windows (`ok_weak`): every experiment is run twice, train with and without weak. Test side always includes weak. |
| D4 | Unlogged attacker traffic (about 09:34 to 10:22) is excluded, not labeled. Excluded by rule in `labeling.py`. |
| D5 | Labels are binary and come from provenance (`attack_log.csv`), never from feature thresholds. Negative class = benign + focused. |
| D6 | Window = tumbling 60 s, unit = (destination /24, window). Only one victim /24 exists, so `subnet` is constant for now but stays in the keys. |
| D7 | Code lives in package `src/carpet/` with thin scripts. venv + `requirements.txt`. |
| D8 | Git is on since 2026-11-09, remote `origin` = github.com/purba-naka/ML-Carpet_Boombing (public). Only commit or push when the human asks. Data, models and the proposal PDF stay out of the repo (`.gitignore`). |
| D9 | Features follow the PDF (sections 2.1.4.4, 3.2.3.2): the thesis claim is flow-level features **combined with** window aggregates. Two feature sets: `agg` (PDF aggregate list only) and `agg_flow` (agg + per-window summary of flow-level columns). Both are run, so the combination claim can be tested against agg alone. Which flow-level columns to summarize: see D15. |
| D10 | Exact duplicate rows (all columns equal): drop, as the PDF says (3.2.2.2). Measure first and log the count per run. Never dedupe by `Flow ID` alone. |
| D11 | Dirty values (inf, NaN, negative duration): keep the flow, set only the broken columns to NaN, impute with the train median inside the pipeline . |
| D18 | `near_attack` flag: benign windows within `NEAR_ATTACK_SECONDS` (600) of any attack edge or unlogged window. Report only, never a feature (in `FORBIDDEN_FEATURES`). The evaluation reports false positive rate for near and far benign windows separately. 88 of 533 benign windows are near. |
| D17 | CV folds are stratified by `subclass` (benign, carpet, focused), not by `label`, and each fold must contain all three. Groups still never split across folds (O10, answered). |
| D12 | Hold-out runs: `C10, C11, C9, C12, F2, F6` plus about 20 percent of benign blocks chosen with `SEED`. Lives in `config.HOLDOUT_RUNS` only. |
| D13 | Entropy and concentration volume = packets (`Total Fwd Packet`), not flows and not bytes. |
| D14 | Entropy is computed in two versions: raw Shannon `H` (PDF formula) and normalized `H / log2(N)`. EDA decides which one enters the models, or both. |
| D15 | Flow-level summary: 11 PDF style columns (duration, packet length, inter-arrival time, rates) picked by EDA effect size, with pairs above 0.9 Spearman removed. Mean, std, max per window, 33 features, in `config.FLOW_SUMMARY_COLUMNS`. Bwd and TCP flag columns were left out on purpose (testbed artifact risk, see `reports/eda_findings.md`) and come back as an ablation only. |
| D16 | Tuning: randomized search, 10 combinations each for RF and XGBoost (was 30, cut by the human at O12 because one threshold ties the models, so heavy tuning only moves numbers inside the fold spread), 5 group folds, score = PR-AUC of the carpet class. If differences between combinations are smaller than the spread between folds, pick the simplest. Search space: RF `n_estimators` 100-500, `max_depth` 4-20 or None, `min_samples_leaf` 1-5; XGBoost `max_depth` 3-6, `learning_rate` 0.03-0.2, `n_estimators` 100-400, `subsample` and `colsample_bytree` 0.7-1.0. Lives in `config.py`. |
| D19 | Phase 9 ablation: every removal starts from `agg_flow`. Removed one at a time: `n_unique_src`, `udp_ratio`, the volume features (`total_pkts`, `total_bytes`, `n_flows`), and all together as `agg_flow_dst_only` (which also drops `n_src_dst_pairs`, a source count under another name). Added back as `agg_flow_artifact`: the 9 artifact columns D15 left out (Bwd, TCP flag), picked with the same rule, in `data/processed/features_artifact.parquet`. |
| D20 | Phase 10 final: both models trained on all of trainval. Roles follow the proposal (PDF 3.2.4.1): **Random Forest is the main model, XGBoost the comparison**. Corrected on 2026-11-09: the first run declared XGBoost primary from CV numbers, which contradicted the PDF, and the run itself was one shot so only the labels in the report change, not a single number. Set `agg_flow`, weak windows in train, phase 8 picked params, seed 42, threshold 0.5. One shot on the hold-out, no iteration after. A `--rehearse` mode runs the same code path on trainval fold 0 so mechanical bugs burn a fold, not the hold-out. |

## 1. Open decisions (ask the human before the phase that needs them)

When a new important choice appears, add a row here: `ID | phase | question | recommendation`, and ask.

| ID | Phase | Question | Recommendation |
|---|---|---|---|



## 2. Status table (update after each step)

Status values: `todo`, `doing`, `done`, `blocked`.

| Phase | Step | Status | Note |
|---|---|---|---|
| 0 | Environment, package skeleton, config | done | venv ok, 6 tests pass. `config.snapshot()` + artifact meta give stale detection (inputs' keys inherited) |
| 1 | Ingest raw flows to typed parquet | done | 9,767,850 rows, 84 cols, 394 MB, 63 s, peak RAM 1.1 GB. Features float64 (exact), ports int32 |
| 2 | Data quality profile + cleaning | done | 9,758,984 rows (only the 8,866 out-of-subnet dropped). 4,065 flows with a blanked cell. 0 exact duplicates, so D10 has nothing to drop |
| 3 | Labeling (migrate `scripts/label.py`) | done | 921 windows, reproduces legacy row by row (only `group` of the 30 excluded unlogged windows differs, unused). 20 tests |
| 4 | Split definition | done | 831 usable windows, holdout 183, 5 folds stratified by subclass (D17): every fold has 3 or 4 focused runs worth of windows, 8 to 17 each |
| 5 | EDA (train and dev only) | done | `reports/eda_findings.md`, tables `eda_*.csv`, 3 figures. Hold-out cut off at load. Needs a rerun against the new feature tables (still valid, trainval cut did not move) |
| 6 | Feature engineering | done | `features_agg.parquet` (12 features) and `features_flow.parquet` (33 features), 921 windows, hand checked on 5 windows. `config.FEATURE_SETS` = `agg` (12) and `agg_flow` (45) |
| 7 | Baselines and first models | done | `reports/phase7_findings.md`. Shuffle alarm passes (AUC 0.49). One threshold on `dst_entropy_norm` ties the models. Recall ceiling 0.827 from weak windows. Tuning budget cut to 10 (D16) |
| 8 | CV, tuning | done | `reports/phase8_findings.md`. Best of 10 beats the default by at most 0.012 PR-AUC, all inside fold noise. Picked: RF 200 trees depth 4 leaf 5, XGBoost 200 trees depth 4 lr 0.03 |
| 9 | Ablation and robustness | done | `reports/phase9_findings.md`. Shortcuts never used (removal changes recall by 0.000), artifact columns add nothing (+0.008 PR-AUC), `dst_entropy_norm` carries half the impurity, seeds move recall by at most 0.015, bootstrap over runs gives recall 0.863 [0.752, 0.957] (RF, weak in train). New artifact: `features_artifact.parquet` |
| 10 | Final evaluation on hold-out | done | One shot, declared before the run (D20). Both models: recall 0.811 (43/53), ROC-AUC 0.964, the 10 missed are all weak windows (C11, C9). RF (main, PDF 3.2.4.1): precision 0.977, FPR 0.008 (1 benign false alarm). XGB (comparison): precision 0.782, FPR 0.092 (12 false alarms, all F6 focused windows). `reports/experiments/phase10_final/`, `reports/tables/final_metrics.csv`, `models/final_*.joblib` |
| 11 | Report material for the thesis | todo | |

## 3. Pipeline and artifacts

```
raw CSV (read only)
  -> [1 ingest]   data/interim/flows.parquet
  -> [2 clean]    data/interim/flows_clean.parquet     (+ reports/tables/dq_*.csv)
  -> [3 label]    data/processed/windows_labeled.parquet   one row per (subnet, window), no features yet
  -> [4 split]    data/processed/split.parquet          window key -> partition (train/dev/holdout) + cv fold
  -> [5 EDA]      reports/figures, reports/tables       (train+dev only)
  -> [6 features] data/processed/features.parquet       keys + meta + feature columns
  -> [7-9 model]  models/*.joblib, reports/tables/cv_*.csv, reports/tables/ablation.csv
  -> [10 eval]    reports/tables/final_*.csv, reports/figures/final_*.png
```

Each parquet has a `.meta.json` sibling (AGENT.md section 9). A phase must refuse to run if its input artifact or meta is missing, with a clear message.

Window key = `(subnet, w)` where `w` is the window start in epoch seconds (multiple of 60). Keep `w` as `int64`. Do not use strings for keys.

## 4. Phase details

### Phase 0: Environment, skeleton, config

Goal: a clean place to work.

Steps:
1. Create venv: `C:/Users/ggnpg/AppData/Local/Programs/Python/Python312/python.exe -m venv .venv`.
2. `requirements.txt`: pandas, numpy, scipy, scikit-learn, xgboost, pyarrow, matplotlib, seaborn, pytest, joblib. Install, then pin the versions actually installed (`pip freeze` for these names). sklearn must be >= 1.4.
3. Create `src/carpet/` modules as empty files with a module docstring each, `tests/`, `scripts/`, `data/interim`, `data/processed`, `reports/figures`, `reports/tables`, `models`. Add `.gitignore` (`data/`, `models/`, `.venv/`, `dataset/`, `*.parquet`, `__pycache__/`), harmless even without git.
4. `config.py` holds, and only it: paths, `SEED = 42`, `WINDOW_SECONDS = 60`, `VICTIM_PREFIX = "198.51.100."`, `ATTACKER_IP = "192.168.1.65"`, `BENIGN_SRC_EXTRA = "8.6.0.1"`, `UNLOGGED_MIN_FLOWS = 50`, `UNLOGGED_GAP_SECONDS = 300`, `BOUNDARY_BUFFER_SECONDS = 60`, `BENIGN_BLOCK_SECONDS = 1800`, `TIMESTAMP_FORMAT`, `FORBIDDEN_FEATURES`, the `Status` enum (`OK`, `OK_WEAK`, `EXCLUDE_BOUNDARY`, `EXCLUDE_UNLOGGED`, `EXCLUDE_TEST`), `Subclass` enum (`BENIGN`, `CARPET`, `FOCUSED`, `UNLOGGED`), and `HOLDOUT_RUNS` (D12).
5. `io.py`: `read_raw_flows(columns, dtypes)`, `read_attack_log()`, `write_artifact(df, path, meta)`, `read_artifact(path)` (checks meta exists).

Acceptance:
- `pytest -q` runs (zero tests is fine here, no import errors).
- `python -c "import carpet"` works with `PYTHONPATH=src` (or an editable install).
- Print versions of pandas, sklearn, xgboost.

Pitfall: do not scatter constants. If a number is needed in two places it is in `config.py`.

### Phase 1: Ingest raw flows

Goal: one typed, compact table of all flows, and nothing else changed.

Steps:
1. Read the 3 CSVs with `chunksize=500_000`, `usecols` = needed columns only, explicit `dtype`. Keep: `Flow ID` (debug only), `Src IP`, `Src Port`, `Dst IP`, `Dst Port`, `Protocol`, `Timestamp`, all numeric flow features. Drop `Label` (always `NeedManualLabel`).
2. Parse `Timestamp` with `TIMESTAMP_FORMAT` to `datetime64[s]`, then derive `ts` = epoch seconds `int64`. Add `session` (1, 2, 3) as `int8`.
3. Cast IPs to `category` or keep a compact `string[pyarrow]` (decide by memory, measure). Floats to `float32` where the values allow, but keep `Total Fwd Packet`, `Total Bwd packets` as `int32`.
4. Write `data/interim/flows.parquet` plus meta.

Acceptance (print each):
- Row count per session equals CSV lines minus header: sesi1 3,833,012, sesi2 2,444,150, sesi3 3,490,688 (total 9,767,850). If different, stop and find out why.
- Zero unparsable timestamps.
- Time range 2026-11-02 09:02:04 to 2026-11-03 00:30:08.
- Peak memory of the script stays under about 6 GB (check with a quick measure, do not guess).

Pitfall: `float32` loses precision on huge values (`Flow IAT`, `Flow Duration` can be 1e8). Keep durations and IAT as `float64` or `int64`. Check max values before downcasting.

### Phase 2: Data quality profile and cleaning

Goal: know exactly how dirty the data is, fix it in a way that loses no rows silently.

Steps:
1. Profile on raw flows, write `reports/tables/dq_*.csv`: NaN and inf count per column, negative values per column, constant columns, exact duplicate rows (all columns), repeated `Flow ID`, protocol distribution, flows per session, flows outside `VICTIM_PREFIX`.
2. Cleaning rules, each one logged with row count before and after (a function returns `(df, log_row)`):
   - Drop flows whose `Dst IP` is outside the victim /24. Expected 8,866 rows. This is the only row drop that is decided now.
   - `inf` and `-inf` to NaN.
   - Negative `Flow Duration` and its derived rates: set the broken columns to NaN (D11).
   - Drop the 9 constant columns from the feature candidate list (not from the flow table, just record them in `config.CONSTANT_COLUMNS` after verifying they are still constant).
   - Exact duplicates (all columns equal): drop (D10). Log the count, and the count per run (needs a later join with labels, so just keep a `ts`-based count here and the per-run breakdown goes to the Phase 3 report).
3. Do not dedupe by `Flow ID`. Repeats come from timeout splits.
4. Write `data/interim/flows_clean.parquet` plus meta that lists every rule and its row effect.

Acceptance:
- Rows removed = exactly the out-of-subnet rows (about 8,866). Anything else is a bug.
- After cleaning: no `inf`; NaN only in the documented rate columns.
- The log table sums up: `rows_in - rows_dropped == rows_out`.
- Test (tiny frame): inf becomes NaN, negative duration becomes NaN, out-of-subnet row is dropped, in-subnet row is kept.

Pitfall: replacing NaN by 0 hides the problem and invents data. Use NaN, impute later inside the train fold only.

### Phase 3: Labeling

Goal: one row per (subnet, window) with a provenance label. Migrate `scripts/label.py` into `src/carpet/labeling.py`, same rules, cleaner design.

Rules (priority order):
1. Run `TEST`: windows overlapping it are `EXCLUDE_TEST`.
2. Window only partly inside a logged run: `EXCLUDE_BOUNDARY`.
3. Window fully inside a logged run: subclass `CARPET` (label 1) if scenario starts with `carpet`, `FOCUSED` (label 0) if `focused`. If it has zero attacker flows, status `OK_WEAK`, else `OK`.
4. Window outside all runs: if attacker flows > `UNLOGGED_MIN_FLOWS`, `EXCLUDE_UNLOGGED`, and so is every window within `BOUNDARY_BUFFER_SECONDS` of such a window and any gap between two unlogged windows shorter than `UNLOGGED_GAP_SECONDS`.
5. Windows within `BOUNDARY_BUFFER_SECONDS` of a logged run edge (outside the run): `EXCLUDE_BOUNDARY`.
6. Everything else: `BENIGN`, label 0, `OK`.

Attacker flow definition (used only for status, never as a feature): `Src IP == ATTACKER_IP`, or source outside the victim /24 and not `8.6.0.1`, destination port 53, UDP (spoofed sources).

Design requirements:
- Pure function `label_windows(flows, log) -> windows` that takes data and returns a table. No file paths inside.
- Vectorized interval logic (use `numpy.searchsorted` or `pandas.IntervalIndex`) instead of a Python loop per run per window. 23 runs is small, so a loop over runs is acceptable, a loop over windows is not.
- Use the `Status` and `Subclass` enums from `config.py`, not raw strings.
- Output columns (fixed schema): `subnet, w, window_start, run_id, group, subclass, label, status, n_flows, n_pkts, attacker_flows`. `group` = `run_id` for run windows, `B<block>` for benign (block = `w // BENIGN_BLOCK_SECONDS`).
- Windows with no flows at all do not appear (no row). Note this in the meta. A window with zero traffic during an attack run is not representable here; mention it in the report.

Acceptance:
- Reproduces the legacy result exactly: 921 windows; benign 533, carpet 186 (33 weak), focused 112 (31 weak); 60 boundary, 30 unlogged; label 1 = 186, label 0 = 645. Compare to `label_report.txt`. If different, diff and explain before moving on.
- Invariants asserted in code: key `(subnet, w)` unique; `label == 1` only where `subclass == CARPET`; every run in the log has at least 10 usable windows (except `TEST`); no usable window has `attacker_flows > UNLOGGED_MIN_FLOWS` outside a run.
- Tests (tiny frames): fully-inside carpet window gets label 1; edge-crossing window excluded; unlogged burst excluded together with its buffer; focused window label 0; zero-attacker window inside a run is `OK_WEAK`.
- Window 09:18 is correct as `EXCLUDE_BOUNDARY` (run C1 starts at 09:18:29). Do not investigate it again.

Pitfall: `attacker_flows` and `status` are label-side information. They must never appear in features. The forbidden list enforces this.

### Phase 4: Split definition

Goal: fix the partitions once, before looking at any model result or doing EDA on labeled data.

Uses D12.

Design:
- Usable windows = status in (`OK`, `OK_WEAK`).
- Partitions: `holdout` = windows whose `group` is in `config.HOLDOUT_RUNS` plus the chosen benign blocks; `trainval` = the rest.
- Inside `trainval`, CV folds: `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)` on `group`, stratified by label. Store the fold id in `split.parquet`. Two columns: `partition`, `fold` (`-1` for holdout).
- Weak handling is not part of the split. The split is the same for the with-weak and without-weak experiments. Weak removal for training is a filter applied later on the train side only.

Acceptance:
- No `group` appears in more than one of (holdout, each CV fold).
- Holdout has both classes, with at least a few carpet and a few focused runs.
- Print window counts per partition and per class and per `subclass`. Show the human.
- Test: a synthetic frame gives disjoint groups across folds and both classes in every fold.

Pitfall: with 22 runs, 5 folds leave about 4 runs per fold. A fold can end without a rare scenario. Print per-fold composition. If a fold has no positives, stop and ask.

### Phase 5: EDA (train and dev only)

Rule: **never load or plot hold-out rows.** The EDA function takes the table already filtered to `trainval`.

Questions to answer with a figure or table each (save under `reports/`):
1. Class balance: windows per label, per `subclass`, per run.
2. Traffic over time: flows and packets per window across the whole timeline, with the run intervals marked. Check the 09:34 to 10:22 exclusion looks right (this uses all windows for data quality only, with labels hidden, and is the one allowed exception, limited to the excluded zone and no hold-out label shown).
3. Candidate aggregate features per window (compute a quick version here for exploration): unique dst, dst entropy, concentration ratio, packets, bytes, unique src, UDP ratio. Distribution by `subclass` (violin or box, log scale where needed).
4. Is carpet separable from focused by dst features? (PDF hypothesis: high entropy and low concentration for carpet.)
5. Is carpet separable from benign, and **only because of `n_unique_src` or volume?** Plot each candidate feature alone vs label, compute single-feature ROC-AUC on train. Any feature with AUC above 0.99 gets flagged as shortcut risk.
6. Weak windows: how do they look compared to benign? (Expected: look like benign.)
7. Correlation matrix among candidate features, list pairs above 0.95.
8. Single-source vs multi-source runs: feature distributions side by side.
9. Flow-level columns: which have zero variance or are near duplicates of each other. Which differ most between classes (effect size)?
10. Missing and dirty values after cleaning: where they concentrate.

Acceptance:
- Each question has an output file and a 1 to 3 line plain finding written into `reports/eda_findings.md`.
- A short "risks found" list at the end (shortcuts, tiny runs, weird windows).
- End with D15 column list to the human: which flow-level columns to summarize. Give a recommendation backed by the effect sizes.

Pitfall: EDA with label-aware choices (cutting thresholds to separate classes) on all data is leakage. Everything here uses `trainval` only.

### Phase 6: Feature engineering

Goal: `features.parquet`, one row per usable window.

Uses D13, D14, D15.

Aggregate features per (subnet, window), from the PDF section 3.2.3.2:
- `n_unique_dst`, `dst_entropy` (Shannon over packet share per dst, D13 and D14), `concentration_ratio` (max share), `total_pkts`, `total_bytes`, `mean_pkts_per_dst`, `max_pkts_per_dst`, `n_unique_src`, `n_unique_src_dst_pairs`, `udp_ratio`, `n_flows`.
- Flow-level summary (mean, std, max of the D15 columns per window) for the `agg_flow` set. The `agg` set has none.

Design:
- One function `build_features(flows_clean, window_keys) -> DataFrame` that groups once. Vectorized `groupby`. Entropy through a helper that takes the per-(window, dst) packet table, not a Python loop.
- Entropy: `p = pkts_dst / pkts_total`, `H = -sum(p log2 p)`, with `0 log 0 = 0`. Define behaviour for a window with zero packets (not expected, but assert).
- Output: key and meta columns kept apart from feature columns. `config.FEATURE_SETS` is a dict `name -> list[str]` that is the **only** place that says which columns are model inputs. `assert not set(FEATURE_SETS[x]) & FORBIDDEN_FEATURES`.

Acceptance:
- Row count equals usable windows from phase 3; keys match exactly.
- No NaN in aggregate features. NaN only in documented flow-level summary columns.
- Tests: entropy of uniform spread over n hosts = `log2(n)`; one host = 0; concentration ratio 1 for one host and `1/n` for uniform; `n_unique_dst` counts correctly.
- Cross-check: recompute 3 random windows by hand with pandas in the check script and compare.
- Leakage check script: assert no forbidden column in any feature set.

Pitfall: a flow belongs to the window of its start time. A long flow contributes all its packets to one window. Write this in the thesis limitations and in the code once as a short comment.

### Phase 7: Baselines and first models

Steps:
1. Baseline A: predict all negative. Baseline B: one feature threshold (`dst_entropy` or `n_unique_dst`), threshold picked on train folds only. Report all metrics.
2. Random Forest (`class_weight="balanced"`, defaults otherwise) and XGBoost (`scale_pos_weight = n_neg / n_pos` computed on the train fold). Use sklearn `Pipeline` so imputers and any scaler are fit inside each fold.
3. Evaluate with the CV folds from phase 4 (never the holdout). Run both weak settings (D3).
4. One function `run_cv(model_factory, feature_set, weak_in_train) -> metrics table` that all experiments call. No copy-pasted loops.

Acceptance:
- Metrics table: per fold and mean ± std for recall, precision, F1, FPR, PR-AUC, ROC-AUC, per-run recall for carpet runs.
- Models beat baseline B, or the finding is reported honestly.
- Sanity: shuffle labels in train (seeded), score must fall to chance. If it does not, there is leakage.
- If any mean recall or F1 on CV is above 0.99, stop and run the leakage audit before celebrating.

### Phase 8: CV and tuning

Uses D16.
- Randomized search inside the CV folds with the PDF grids (RF: `n_estimators, max_depth, min_samples_split, min_samples_leaf, max_features, class_weight`; XGBoost: `n_estimators, learning_rate, max_depth, subsample, colsample_bytree, gamma, reg_lambda, scale_pos_weight`).
- Scoring: PR-AUC or F1 of the positive class (decide with the human if unsure, it is a metric decision). Not accuracy.
- Group-aware CV only (the same fold ids).
- Save best params and the full search table.

Acceptance: best params are written to a json with the CV score and seed; rerunning with the same seed gives the same result.

### Phase 9: Ablation and robustness

Experiments (each is one call of `run_cv`, one row in a table):
1. Feature sets: `agg` vs `agg_flow` (D9). If `agg_flow` does not beat `agg`, report it honestly.
2. Remove `n_unique_src` (shortcut test from the analysis).
3. Remove volume features (`total_pkts`, `total_bytes`, `n_flows`) per the PDF.
4. Remove both 2 and 3 (the model must still use dst-distribution features).
5. With and without weak windows in train (D3).
6. Feature importance: RF impurity and permutation importance (computed on a validation fold, not on train), XGBoost gain.
7. Per-scenario recall: carpet-low, mid, stealth, single vs multi source.
8. Seed stability: 5 seeds for model randomness, report the spread.
9. Uncertainty: bootstrap over runs (resample runs, not windows) for the main metrics.

Acceptance: one summary table `reports/tables/ablation.csv`, plus a short list of findings written as measured facts.

### Phase 10: Final evaluation (one shot)

- Fit the final model on all of `trainval` with the chosen params. Predict the holdout once.
- Report: confusion matrix, recall, precision, F1, FPR, PR-AUC, ROC-AUC, inference time per window, per-run recall on holdout runs, which windows were missed and which false alarms (list their keys and run ids).
- Do not iterate after seeing this. If something is wrong, tell the human and agree on what to do. Any re-tuning means the holdout is burned, say so in the thesis.
- Save: `models/final_xgb.joblib` and `models/final_rf.joblib` (each a dict of model, features, params, role), `reports/tables/final_*.csv`, figures (confusion matrix, ROC, PR, importance).

### Phase 11: Thesis material

- A methods summary matching what was actually run (numbers from the meta files).
- A limitations list: one attacker host, one victim /24, one day, mostly DNS, single-source flows merged by CICFlowMeter, flow-start-time window assignment, 22 runs, MAWI and CIC-DDoS2019 not yet tested.
- A mapping table from each PDF claim to the experiment that supports or contradicts it. Claims that were not measured are marked as such.

## 5. Standing checklist for every phase

- [ ] Input artifact and meta exist, schema asserted right after load.
- [ ] Row counts printed before and after every filter.
- [ ] No hold-out row used (except Phase 10).
- [ ] Output written with meta.
- [ ] `pytest -q` green. Tests are small, synthetic, behaviour based.
- [ ] Re-running gives identical output (seeded).
- [ ] Status table updated. Odd findings reported to the human.

## 6. Quick reference for the metrics code

- Positive class = carpet. `recall = TP / (TP + FN)`, `precision = TP / (TP + FP)`, `FPR = FP / (FP + TN)`.
- Use `average_precision_score` for PR-AUC and `roc_auc_score` for ROC-AUC on predicted probabilities, not on labels.
- Threshold: default 0.5 first. If you tune a threshold, tune it on CV predictions only and say so.
- Per-run recall for a carpet run = fraction of its usable windows predicted positive. For focused and benign groups report the false alarm rate the same way.
- Inference time: time `predict` over the holdout windows, divide by window count, repeat 5 times, report the median. This number lives in a report only, never in a test.

## 7. What not to build (YAGNI)

- No deep learning, no LLM, no GNN (out of scope in the PDF).
- No real-time streaming service, no dashboard, no mitigation.
- No CIC-DDoS2019 or MAWI loaders now (D1).
- No config file format, CLI framework, experiment tracker or database. Plain Python, parquet, json, csv.
- No sliding windows and no multi-window (5 s, 30 s) now. Add only after the main results exist, as an ablation (PDF 3.2.3.1).
- No SMOTE unless CV shows `class_weight` is not enough, and then only inside the train fold.

## 8. Change protocol (experiments will change decisions)

The human experiments a lot. Decisions D1 to D16 are the current best guess, not law. Rules so changes stay safe and results stay honest:

1. **Only the human changes a decision.** The agent may suggest a change with evidence, never apply it alone.
2. **One place per decision.** Every decision maps to one thing in `config.py` (or one function). Changing a decision = editing that one place. If the code has the same decision hard-coded elsewhere, that is a bug: fix the design.
3. **Log it.** Append a line to the change log below: date, decision id, old, new, reason, who asked. Then update the decision table in place so it always shows the current truth. Never leave the old value in the table.
4. **Know what is downstream.** Use the table below to find which phases must be re-run. Re-run all of them, in order. Never mix artifacts from before and after the change.
5. **Artifacts carry their config.** The `.meta.json` of each artifact stores the config values it was built with (a hash plus the values). A phase refuses to read an input whose config hash does not match the current config, and tells the human which phase to re-run.
6. **Experiments get names.** Each experiment run writes to `reports/experiments/<name>/` with its own config snapshot, metrics, and a one line note of what was changed versus the baseline. Results are never overwritten. Compare experiments by reading these folders.
7. **The hold-out is special.** Changing D12 (hold-out runs) after any model result was seen means the old hold-out is burned. Say it plainly in the report and in the change log. Same for changing D4, D5, D6 (they change the data itself): all earlier results become obsolete, mark them as such.
8. **The thesis follows the code.** After a change, the report material (phase 11) is regenerated from the new meta files, not edited by hand.

### Impact map: what to re-run when a decision changes

| Decision changed | Re-run from phase | Notes |
|---|---|---|
| D4, D5 (labels, exclusions) | 3 | Then 4 to 10. Hold-out burned if results were seen. |
| D6 (window size, unit) | 3 | Everything changes. Write a new experiment name. |
| D10, D11 (cleaning) | 2 | Then 3 to 10. |
| D12 (hold-out runs) | 4 | Then 5 to 10. Hold-out burned if results were seen. |
| D13, D14 (entropy definition) | 6 | Then 7 to 10. |
| D9, D15 (feature sets, flow columns) | 6 | Then 7 to 10. |
| D16 (tuning setup) | 8 | Then 9 and 10. |
| Cross-validation folds or seed | 4 | Then 5 to 10. |
| Model choice (add a model, drop XGBoost) | 7 | Then 8 to 10. |
| D1 (new dataset added) | 1 | A new reader in `io.py`, then run the whole chain per dataset. Datasets are never mixed in one split without a decision. |

### Change log

| Date | Decision | Old | New | Reason | Asked by |
|---|---|---|---|---|---|
| 2026-11-09 | D1 to D16 | - | initial values | first plan, agreed with the human | human |
| 2026-11-09 | D15 | about 12 columns, chosen after EDA | 11 PDF style columns, no Bwd and no TCP flag | EDA top columns looked like testbed artifacts | human chose option A |
| 2026-11-09 | D16 | 30 combinations per model | 10 combinations per model | one threshold ties the models, so tuning gains stay inside the fold spread | human approved |
| 2026-11-09 | D18 (new) | - | near_attack report flag | 7 attack free hours make far benign windows easy | human approved |
| 2026-11-09 | D17 (new) | CV stratified by label | CV stratified by subclass | fold 0 had zero focused windows | human approved |
| 2026-11-09 | D19 (new) | - | ablation sets + 9 artifact columns, `agg_flow` as base, `dst_only` also drops `n_src_dst_pairs` | phase 9 needs the artifact columns D15 left out; same D15 pick rule applied to the Bwd and TCP flag families | agent proposed, human to confirm |
| 2026-11-09 | D20 (new) | - | one final model | both models, XGBoost primary RF comparison, agg_flow, weak in train, declared before the run | user chose "both models" when asked; rehearsal mode added so bugs burn a fold, not the hold-out | human chose, agent declared roles before the run |
| 2026-11-09 | D20 (roles) | XGBoost primary, RF comparison | RF main, XGBoost comparison | PDF 3.2.4.1 names RF as the main model; the agent had not checked the PDF. No number changed: the hold-out run was never repeated, only the reporting order | PDF mismatch found by the agent, human asked for code fully based on the PDF |
| 2026-11-09 | D8 | no git | git on, public repo | human asked to push | human |
