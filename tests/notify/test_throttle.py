from snorty.notify.throttle import Decision, Throttle

NO = Decision(False, 0, 0)


def test_first_alert_shows_and_repeat_inside_window_is_suppressed() -> None:
    t = Throttle(window=300)
    assert t.decide(1, 0) == Decision(True, 0, 0)
    assert t.decide(1, 10) == NO
    assert t.decide(2, 10) == Decision(True, 0, 0)  # another SID is independent


def test_a_released_toast_lets_the_sid_try_again_and_keeps_its_counts() -> None:
    t = Throttle(window=300)
    t.decide(1, 0)
    for now in (10, 20, 30):
        t.decide(1, now)
    shown = t.decide(1, 301)
    assert shown == Decision(True, 3, 0)
    t.release(1, shown)  # the toast failed
    assert t.decide(1, 302) == Decision(True, 3, 0)  # tried again at once, still reports 3


def test_releasing_a_first_toast_forgets_the_sid() -> None:
    t = Throttle(window=300)
    shown = t.decide(1, 0)
    t.release(1, shown)
    assert t.tracked == 0 and t.decide(1, 1) == Decision(True, 0, 0)


def test_release_gives_back_the_dropped_count_but_keeps_the_cap_slot() -> None:
    t = Throttle(window=300, cap=1, cap_window=60)
    t.decide(1, 0)
    assert t.decide(2, 1) == NO  # dropped by the cap: counted
    shown = t.decide(3, 61)
    assert shown == Decision(True, 0, 1)
    t.release(3, shown)
    assert t.decide(4, 62) == NO  # the failed attempt still used the slot: no retry storm
    assert t.decide(5, 122) == Decision(True, 0, 2)  # both drops are reported


def test_window_boundary_is_inclusive_of_the_end() -> None:
    t = Throttle(window=300)
    t.decide(1, 0)
    assert not t.decide(1, 299.9).show
    assert t.decide(1, 300).show


def test_suppressed_alerts_do_not_extend_the_window() -> None:
    t = Throttle(window=300)
    t.decide(1, 0)
    for now in (100, 200, 299):
        assert not t.decide(1, now).show
    assert t.decide(1, 300) == Decision(True, 3, 0)


def test_burst_of_500_gives_one_toast_then_a_summary() -> None:
    t = Throttle(window=300)
    shown = [t.decide(7, i * 0.1).show for i in range(500)]
    assert shown.count(True) == 1
    assert t.decide(7, 400) == Decision(True, 499, 0)
    assert t.decide(7, 401) == NO  # counters were reset and a new window started


def test_global_cap_drops_and_counts_other_alerts() -> None:
    t = Throttle(cap=6, cap_window=60)
    assert [t.decide(sid, 0).show for sid in range(6)] == [True] * 6
    assert t.decide(100, 1) == NO
    assert t.decide(101, 2) == NO
    assert t.decide(102, 61) == Decision(True, 0, 2)  # cap window passed; tally reported once
    assert t.decide(103, 61) == Decision(True, 0, 0)


def test_cap_blocked_alert_is_not_throttled_by_its_own_window() -> None:
    t = Throttle(cap=1, cap_window=60, window=300)
    t.decide(1, 0)
    assert not t.decide(2, 10).show  # blocked by the cap, SID 2 never showed
    assert t.decide(2, 61).show  # no SID window runs against it


def test_cap_blocked_alert_keeps_the_sids_suppressed_count() -> None:
    t = Throttle(cap=1, cap_window=60, window=10)
    t.decide(1, 0)
    t.decide(1, 5)  # suppressed by the SID window: count 1
    t.decide(2, 20)  # shown at 20 would exceed cap? cap window still open: blocked
    assert t.decide(1, 61) == Decision(True, 1, 1)  # SID 1's own count and SID 2's tally


def test_tracked_sids_are_bounded_and_oldest_are_dropped() -> None:
    t = Throttle(cap=10_000, max_sids=1000, window=1e9)  # huge window: only max_sids evicts
    for sid in range(1500):
        assert t.decide(sid, float(sid)).show
    assert t.tracked == 1000
    assert t.decide(0, 1500.0).show  # evicted long ago, and its window passed anyway
    assert not t.decide(1499, 1501.0).show  # newest are still remembered


def test_entries_with_nothing_to_report_expire_but_counts_are_kept() -> None:
    t = Throttle(cap=10_000, window=300)
    for sid in range(10):
        t.decide(sid, 0)
    t.decide(0, 10)  # SID 0 now has one suppressed alert
    t.decide(99, 400)  # a show triggers the sweep
    assert t.tracked == 2  # SID 99 and SID 0 (it still has a count to report)
    assert t.decide(0, 401) == Decision(True, 1, 0)
