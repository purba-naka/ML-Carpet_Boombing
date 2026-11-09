import pandas as pd
import pytest

from carpet import config, split


def _windows(n_carpet_runs=8, n_focused_runs=4, n_blocks=10, per_group=6):
    rows = []
    groups = ([(f"C{i}", "carpet", 1) for i in range(1, n_carpet_runs + 1)]
              + [(f"F{i}", "focused", 0) for i in range(1, n_focused_runs + 1)]
              + [(f"B{i}", "benign", 0) for i in range(n_blocks)])
    w = 0
    for g, sub, label in groups:
        for _ in range(per_group):
            rows.append(dict(subnet="s", w=w, group=g, run_id=g, subclass=sub, label=label, status="ok"))
            w += 60
    return pd.DataFrame(rows)


@pytest.fixture
def holdout(monkeypatch):
    monkeypatch.setattr(config, "HOLDOUT_RUNS", ("C1", "F1"))
    monkeypatch.setattr(config, "CV_FOLDS", 3)


def test_split_keeps_groups_whole_and_both_classes_everywhere(holdout):
    windows = _windows()
    s = split.make_split(windows)
    split.check_split(s, windows)
    held = s.merge(windows, on=["subnet", "w"]).query("partition == 'holdout'")
    assert {"C1", "F1"} <= set(held.group) and (held.fold == split.NO_FOLD).all()


def test_split_is_reproducible(holdout):
    windows = _windows()
    pd.testing.assert_frame_equal(split.make_split(windows), split.make_split(windows))


def test_excluded_windows_never_enter_the_split(holdout):
    windows = _windows()
    windows.loc[0, "status"] = config.Status.EXCLUDE_BOUNDARY
    assert windows.loc[0, "w"] not in set(split.make_split(windows).w)


def test_missing_holdout_run_is_refused(monkeypatch):
    monkeypatch.setattr(config, "HOLDOUT_RUNS", ("C99",))
    with pytest.raises(ValueError, match="C99"):
        split.make_split(_windows())


def test_check_split_catches_a_group_cut_in_two(holdout):
    windows = _windows()
    s = split.make_split(windows)
    tv = s.index[s.partition == split.TRAINVAL]
    s.loc[tv[0], "fold"] = (s.loc[tv[0], "fold"] + 1) % config.CV_FOLDS
    with pytest.raises(ValueError, match="more than one bucket"):
        split.check_split(s, windows)


def test_every_cv_fold_gets_each_subclass(holdout):
    windows = _windows(n_carpet_runs=8, n_focused_runs=6, n_blocks=12)
    s = split.make_split(windows)
    tv = s[s.partition == split.TRAINVAL].merge(windows, on=["subnet", "w"])
    assert (tv.groupby("fold").subclass.nunique() == 3).all()


def test_check_split_catches_a_fold_without_focused(holdout):
    windows = _windows()
    s = split.make_split(windows)
    tv = s.merge(windows, on=["subnet", "w"]).query("partition == 'trainval'")
    windows = windows.copy()
    focused_fold = tv[tv.subclass == "focused"].fold.iloc[0]
    only_there = windows.merge(tv[tv.fold == focused_fold][["subnet", "w"]], on=["subnet", "w"])
    windows.loc[windows.subclass.eq("focused") & ~windows.w.isin(only_there.w), "subclass"] = "benign"
    with pytest.raises(ValueError, match="missing a subclass"):
        split.check_split(s, windows)
