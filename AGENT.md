# AGENT.md

Rules for any AI agent working in this repo. The human swaps models often, so this file must be enough on its own. Read it fully before touching anything. Then read `IMPLEMENTATION.md` (the plan and the current status).

## 1. What this project is

Undergraduate thesis (skripsi): detect **DDoS carpet bombing** with machine learning.

- Carpet bombing = attack traffic spread thinly over many hosts of one /24 subnet, so per-host rules miss it.
- Unit of analysis = one **(destination /24 subnet, 60 second window)**. One row = one window.
- Label (binary): `1` = carpet bombing, `0` = everything else (benign and single-target "focused" DDoS).
- Models: Random Forest (main), XGBoost (comparison). Tree models only. No deep learning.
- Data now: our own PNETLab captures from 2 Nov 2026. CIC-DDoS2019 and MAWI come later, not now.
- The thesis text is `Final Report Pre Thesis (1).pdf` (Indonesian). It is the spec. If code and PDF disagree, stop and ask.

## 2. Hard rules (never break, no exceptions)

1. **Never decide important things alone.** If a choice changes the data, the label, the split, the metrics or the thesis claims, ask the human. List the options and give a recommendation. See section 12.
2. **Never use a test or hold-out row for any decision.** No EDA, no feature choice, no threshold, no tuning on it. Touch it once, at the final evaluation.
3. **Never fit anything on all data.** Scalers, imputers, resamplers (SMOTE), feature selectors: fit on the training fold only.
4. **Never split windows randomly.** Neighbour windows of one run look alike. Always split by `group` (see `IMPLEMENTATION.md` phase 6).
5. **Never put label-defining or identity columns into features.** The forbidden list lives in `config.py` (`FORBIDDEN_FEATURES`). Includes `attacker_flows`, `run_id`, `group`, `subclass`, `status`, `w`, `window_start`, raw IPs and ports.
6. **Never invent numbers.** Every number in a report comes from code that you ran in this session. If you did not run it, write "not measured".
7. **Never delete or overwrite raw data** (`dataset/`, `flows_csv-*/`, `pcap_dataset-*/`, the PDF). They are read only.
8. **Never claim success without running the check.** "Should work" is not a result. Run it, paste the real output.
9. **Never silently drop rows.** Every filter logs how many rows it removed and why.
10. **Never commit, push, or run git write commands** unless the human asks. The repo is live (origin = github.com/purba-naka/ML-Carpet_Boombing), so a push is public. Data, models and the proposal PDF never go in.

## 2b. Decisions change, and that is normal

The human runs many experiments and will change decisions (labels, split, features, models, windows). The decision tables in `IMPLEMENTATION.md` hold the **current** values. Rules:

- Do not argue with a changed decision or "restore" an old one. The newest instruction from the human wins.
- Do not apply a change on your own. Suggest it with evidence and wait.
- When the human changes a decision: update the table and the change log in `IMPLEMENTATION.md` section 8, edit the single place in `config.py`, and re-run every downstream phase from the impact map. Say which phases you re-ran.
- Never mix artifacts built under different configs. Each artifact stores its config hash in its `.meta.json`. If the hash is stale, rebuild, do not patch.
- Experiments go to `reports/experiments/<name>/`. Never overwrite an old result, add a new folder.
- If a change burns the hold-out (changes data or labels after results were seen, or changes the hold-out runs), say so plainly before running.
- If AGENT.md or the PDF now conflict with a changed decision, tell the human, do not choose.

## 3. Working protocol (follow for every task)

1. Read `IMPLEMENTATION.md`. Find the phase and step you are asked to do. If the task is not in the plan, ask.
2. Say in 2 lines what you will change and which files. Keep the change small (one phase step at a time).
3. Look at the data or code first (head, shape, dtypes, a few rows). Do not assume column names. Print them.
4. Write the smallest code that meets the step's acceptance checks.
5. Run it. Run the acceptance checks listed in the step. Run `pytest -q`.
6. Update the status table in `IMPLEMENTATION.md` (only the status and a one line note).
7. Report: what changed, what you ran, real numbers, anything odd you saw. Odd findings go to the human, do not bury them.

Large steps: split into several small runs. A weak model does better with 5 small verified steps than 1 big one.

## 4. Environment (Windows, gotchas)

- Shell is git-bash. Use forward slashes in commands.
- Plain `python` is broken (Windows Store stub). Use the venv: `.venv/Scripts/python.exe`. Run scripts with `PYTHONPATH=src` (pytest already has it via `pyproject.toml`).
- venv has: pandas 3.1.1, numpy 2.5.4, scipy 1.18.1, scikit-learn 1.9.1, xgboost 3.4.1, pyarrow 26.0.1, matplotlib, seaborn, pytest, joblib. Pinned in `requirements.txt`. The old global Python has only pandas 2.3.3, do not use it for the project. pandas 3 has copy-on-write and a new default string dtype: do not rely on in-place chained edits.
- The three big CSVs are 0.9 to 1.5 GB each (9.77 million flow rows total). Loading all columns as float64 already ran out of memory once. Always: `usecols=`, explicit `dtype=` (float32 / int32 where safe), `chunksize=`, and write intermediate results as parquet.
- Do not open big files with a plain file read tool. Use pandas with `nrows=` to peek.
- The PDF text: `pdftotext -layout "Final Report Pre Thesis (1).pdf" <tmp file outside the repo>`. Read with `errors="ignore"` (non-UTF-8 bytes). Delete the tmp file after.
- A junk file named `nul` sits in the repo root. Ignore it. Do not use it.
- Subshell time zones: the CSV `Timestamp` has no time zone. `attack_log.csv` `start_ts` / `end_ts` are epoch seconds. They match when the CSV timestamp is read as naive UTC. This was verified. Do not "fix" it.
- CSV timestamp format: `%d/%m/%Y %I:%M:%S %p` (e.g. `02/11/2026 09:02:05 AM`).

## 5. Repo layout and single source of truth

Target layout (build it step by step, see the plan):

```
AGENT.md  IMPLEMENTATION.md  requirements.txt  pyproject.toml(optional, only for pytest config)
src/carpet/            # the package. All logic lives here.
  config.py            # ONLY place for paths, constants, column names, seeds, thresholds
  io.py                # read raw CSV / log, read and write artifacts
  labeling.py          # flows -> labeled windows
  clean.py             # flow cleaning
  features.py          # windows -> feature table
  split.py             # train / dev / hold-out, CV folds
  models.py            # build RF / XGBoost, fit, predict
  evaluate.py          # metrics, plots, tables
scripts/               # thin entry points: parse args, call src, write artifacts. No logic.
  run_label.py  run_clean.py  run_eda.py  run_features.py  run_train.py  run_eval.py
tests/                 # few, behaviour tests, small synthetic frames
data/interim/          # generated, gitignored
data/processed/        # generated, gitignored
reports/figures/  reports/tables/
dataset/ ...           # RAW, read only, never edited
```

Single source of truth rules:

- A constant (path, threshold, column list, seed) is defined once in `config.py` and imported. Never retype it.
- Label logic exists once, in `labeling.py`. Features never recompute labels.
- Every phase reads the previous phase's artifact from disk and writes its own. No phase re-reads raw data except phase 3.
- Every artifact has a sibling `*.meta.json` (see section 9) so a result can be traced. It stores the config values and a config hash. A phase refuses to run on an input artifact whose hash does not match the current `config.py`.
- `scripts/check1.py` to `check5.py` are one-off audit scripts from the first data check. Legacy, do not extend, do not import. The old `scripts/label.py` was migrated to `src/carpet/labeling.py` (reproduced row by row) and removed.

## 6. Coding standards

Priority order: **correct, simple, easy to fix at 2am in a year.**

- KISS, DRY, SRP. One function does one thing. If you need "and" to describe it, split it.
- Minimize state. No globals except constants. No hidden mutation: functions take a DataFrame and return a new one. Do not mutate arguments.
- Make bad states impossible instead of checking for them later. Examples: a `Status` enum instead of free strings, one `FEATURES` list instead of copies, a function that returns a frame with a fixed column schema.
- Fail loud at boundaries. Validate input schema and invariants right after reading (columns exist, no duplicate keys, no NaN in required columns). Raise `ValueError` with a message that says what, where, how many. Do not validate deep inside loops.
- No dead code, no "for later" parameters, no config for values that never change, no class with one method (use a function), no base class with one child.
- Prefer pandas / numpy / sklearn built-ins to hand-written loops. Vectorize. A Python loop over millions of rows is a bug.
- Type hints on public functions. Names say what the thing is: `n_unique_dst`, not `x1`.
- Determinism: all randomness takes the seed from `config.SEED`. Same input must give byte-identical output.
- Files stay small. Over about 250 lines means split by responsibility.
- Print progress and row counts for slow steps. Never leave a long step silent.

Eliminate bug classes, not bugs. When you fix a bug, ask "what design would make this kind of bug impossible?" and do that instead of a one-line patch. Typical examples here: leakage (solved by group split + forbidden list + fit only on train), silent row loss (solved by logged filters + invariants), unit mix-ups (solved by one place that defines units).

## 7. Comments and docstrings

- Default is no comment. Good names replace most comments.
- Keep a comment only when it explains **why** something non obvious is done, or a trap a future reader would fall into. Never explain **what** the code already says.
- Tone: down to earth, warm, short, simple English that non native speakers can read. Tell the small story behind the odd decision. No em-dashes. Must not read like AI wrote it.
- Mark deliberate simplifications: `# ponytail: <ceiling>, upgrade by <path>`.
- Good: `# CICFlowMeter merges same 5-tuple packets, so a slow single-source attack shows up as a few huge flows. Count packets, not flows.`
- Bad: `# loop over windows`, `# increment counter`, `# this function computes entropy`.
- Public functions: one line docstring max, unless the contract is subtle.

## 8. Tests

- Use `pytest`. Plain `assert`. No mocking frameworks, no sleeps, no timing, no network, no dependence on the big dataset.
- Tests build tiny synthetic frames (5 to 30 rows) that show one behaviour each.
- Test **behaviour and invariants**, not implementation. Examples worth having:
  - labeling: a window fully inside a carpet run gets label 1; a window crossing a run edge is excluded; unlogged attacker traffic is excluded.
  - features: entropy of an even spread over n hosts equals `log2(n)`; one host gives 0; concentration ratio is 1 for one host.
  - split: no `group` appears in two partitions; every partition has both classes.
  - leakage: no column of `FORBIDDEN_FEATURES` is in the training matrix.
- One test file per module. Delete tests that only repeat the implementation. If a test breaks when you rename an internal variable, it is a bad test: rewrite it.
- Big-data checks (row counts, invariants on real artifacts) are **acceptance checks in scripts**, not unit tests.

## 9. ML rules (the part weak models get wrong)

- **Positive class is carpet (`label == 1`).** Report recall and precision for that class. Accuracy alone is forbidden as a headline.
- **Metrics to report always:** recall, precision, F1, false positive rate, PR-AUC, ROC-AUC, confusion matrix, inference time per window. Also per run recall (this dataset has 22 runs, a single average hides weak scenarios).
- **Baselines first.** Before RF: (a) predict-all-negative, (b) a single-feature threshold chosen on train only. A model that does not beat (b) is a finding, report it.
- **Imbalance:** about 186 positive vs 645 negative. Use `class_weight="balanced"` (RF) and `scale_pos_weight` (XGBoost) first. Resample only if it clearly helps on CV, and only inside the training fold.
- **Weak windows** (`status == ok_weak`): run every experiment twice, train with and without weak. The test side always contains weak windows, so recall stays honest.
- **Ablation** is part of the thesis: without `n_unique_src`, without volume features, without the aggregate set. Multi-source attacks have tens of thousands of unique sources, benign has about 3. That is a shortcut. Always check the model still works without it.
- **Small data warning:** 22 runs is small. Report uncertainty (bootstrap over runs, or per fold spread). Never say "model generalizes". Say what was measured on which runs.
- **Provenance labels only.** Labels come from `attack_log.csv` and design, never from thresholds on features (PDF section 3.2.2.4).
- **Metadata columns** (`w`, `window_start`, `run_id`, `group`, `subclass`, `status`, `attacker_flows`) travel with the data for splitting and analysis but never enter `X`.
- Every artifact `foo.parquet` has `foo.meta.json`: producing script, `config` values used, input file names and row counts, output row count, seed, package versions, time stamp.

## 10. Known data facts (verified, do not re-discover, do re-check if code disagrees)

- Raw flows: `dataset/csv/sesi{1,2,3}_all.csv/sesi{1,2,3}_all.csv` (a folder with the same name as the file, yes). 84 columns, CICFlowMeter format. Column `Label` is always `NeedManualLabel` (useless).
- Time span 2026-11-02 09:02 to 2026-11-03 00:30. Capture gaps (no flows): 12:23 to 12:27, 13:58 to 13:59, 00:22.
- Attack log: `dataset/Attack_log-*/Attack_log/attack_log.csv`. 23 runs: `TEST` (ignore, produced no attacker flows), `C1..C14` carpet (`carpet-low/mid/stealth`), `F1..F8` focused. Attacker host `192.168.1.65`. Victim subnet `198.51.100.0/24`. `n_src=multi` means spoofed random source IPs.
- Almost all traffic is UDP port 53 (DNS). No TCP flood, no NTP, no SYN. Benign is also mostly DNS to `.10 .11 .12`, so benign diversity is low.
- Unlogged attacker traffic exists between about 09:34 and 10:22 (not in the log, source unknown, a friend collected it). Decision by the human: **do not use that time range.** `labeling.py` excludes it automatically by rule (attacker flows above 50 outside any logged run), plus a 60 second buffer.
- Single-source runs produce a few giant flows (thousands of packets each) because CICFlowMeter merges same 5-tuple packets. Flow counts mislead there. Packet counts do not.
- Many runs use `payload=0`, so byte columns can be 0. Check before trusting byte features.
- A flow is assigned to the window of its **start** `Timestamp`. A long flow therefore lands all its packets in one window. Known limitation, keep it in the thesis limitations section.
- Dirty values (measured by `scripts/run_clean.py` on the victim /24 flows, see `reports/tables/dq_columns.csv`): 180 inf (`Flow Bytes/s`, `Flow Packets/s`), 30 NaN before cleaning, 3,998 negative cells, almost all in `Flow IAT Min` (3,960). 4,065 flows got a cell blanked. Exact duplicate rows: 0. 9 constant columns, listed in `config.CONSTANT_COLUMNS`. 316k repeated `Flow ID` are legit timeout splits, never dedupe by `Flow ID`. Most of the inf and NaN seen in the first audit sat in the out-of-subnet flows that cleaning drops.
- Flows to destinations outside `198.51.100.0/24`: 8,866 (0.09%). Dropped.
- Legacy folders `flows_csv-20261109...` and `pcap_dataset-20261109...` (16 Oct 2026) are not in the attack log and not labeled. Ignore them.
- Current labeling result (`label_report.txt`): 921 windows. benign 533, carpet 186 (33 weak), focused 112 (31 weak). 60 boundary windows and 30 unlogged windows excluded.

## 11. Review and verification protocols

Use these when the human asks for a review. "Change set" = the files you changed in this task (list them explicitly, or use `git status`).

**Simplify review.** Go over the change set and simplify: KISS, DRY, SRP, less bloat, remove unnecessary state (variables, fields, arguments), protect from state explosion. Steelman each change: write the best argument for keeping the old version, and only change if the simplification still wins. Never remove critical functionality.

**Test review.** Go over the tests in the change set. Consolidate, remove useless ones, make them robust against refactors and slow machines (no sleeps, no timing). Steelman each removal.

**Comment review.** Remove trivial comments. Rewrite kept ones to say WHY, concisely, in the tone from section 7.

**Robustness review (design).** Is this scalable, rigid, easy to maintain, easy to fix at 2am in a year, easy to add features to, simple to reason about? Aim for single source of truth. Remove whole classes of bugs by better design, not by patching one bug. Fix every issue you find. If reviewing a plan, edit the plan in place.

**Parallel verification.** When asked to verify, run 3 independent subagents with different prompt styles, then merge their findings:
1. *Creative / adversarial explorer:* "Try to break this. Invent odd inputs, odd data shapes, odd orderings. What would surprise the author?"
2. *Scrutinizing line-by-line reviewer:* "Check every function against its contract, every filter for off-by-one, every merge for key duplication, every pandas call for silent dtype or NaN behaviour."
3. *ML validity and leakage auditor* (the most fitting third style for this repo): "Hunt for leakage, label contamination, split mistakes, fit-on-test, metric misuse, irreproducibility, claims not backed by numbers."
Each subagent gets the change set, the relevant plan section, and must report concrete file:line findings with a repro, not opinions. Merge, dedupe, fix, re-run the checks.

**Commit style (git is on, commit only when the human asks).** Same style as history. 2 to 5 sentences. Down to earth, concise, tell the story, include the non obvious reason. No em-dashes. Must not read like AI wrote it. Only commit when asked.

## 12. When to stop and ask the human

Stop and ask (do not guess) when:

- A decision is listed under "Open decisions" in `IMPLEMENTATION.md`, or a change to an existing decision seems useful.
- The step would change labels, drop more than 1% of rows, change the split, add or remove a metric, or change anything the PDF defines.
- A check fails and the fix is not obvious after one honest attempt.
- A number looks too good (recall or F1 above 0.99 on held-out runs is a leakage alarm until proven otherwise).
- The data does not match section 10.
- You are about to delete or overwrite something that is not generated by this repo's own scripts.

How to ask: one short message. State the situation in 1 or 2 lines, give 2 to 3 options with one recommended, and say what you will do after the answer. Ask the important ones together, not one by one.

## 13. Definition of done (per step)

- Code runs end to end from a clean start.
- Acceptance checks from the plan step were run and passed. Real output shown.
- `pytest -q` is green.
- Artifacts and their `.meta.json` written.
- Status table updated.
- No new constants outside `config.py`. No dead code. No trivial comments.
- Report to the human lists oddities and open questions.
