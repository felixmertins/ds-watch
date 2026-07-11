import pytest

from ds_watch.diff import (
    DS_ADDED,
    DS_CHANGED,
    DS_REMOVED,
    QuarantineError,
    diff_states,
    sanity_check,
)
from ds_watch.store import StateMeta

RR_A = (12345, 8, 2, "aa" * 32)
RR_B = (54321, 13, 2, "bb" * 32)
RR_C = (11111, 13, 2, "cc" * 32)


def test_diff_added_removed_changed():
    prev = [
        ("gone.org", RR_A),
        ("rollover.org", RR_A),
        ("stable.org", RR_C),
    ]
    curr = [
        ("new.org", RR_B),
        ("rollover.org", RR_B),
        ("stable.org", RR_C),
    ]
    events = {e.domain: e for e in diff_states(iter(prev), iter(curr))}

    assert set(events) == {"gone.org", "new.org", "rollover.org"}
    assert events["gone.org"].event == DS_REMOVED
    assert events["gone.org"].before == [RR_A]
    assert events["new.org"].event == DS_ADDED
    assert events["new.org"].after == [RR_B]
    assert events["rollover.org"].event == DS_CHANGED
    assert (events["rollover.org"].before, events["rollover.org"].after) == ([RR_A], [RR_B])


def test_diff_multi_rr_rrset_compares_as_set():
    # Delegation with two DS RRs: one stays, one is added → ds_changed
    prev = [("multi.org", RR_A)]
    curr = [("multi.org", RR_A), ("multi.org", RR_B)]
    events = list(diff_states(iter(prev), iter(curr)))
    assert len(events) == 1
    assert events[0].event == DS_CHANGED
    assert events[0].after == [RR_A, RR_B]


def test_diff_empty_states():
    assert list(diff_states(iter([]), iter([]))) == []
    added = list(diff_states(iter([]), iter([("a.org", RR_A)])))
    assert [e.event for e in added] == [DS_ADDED]


def _meta(ds_rrs: int) -> StateMeta:
    return StateMeta(
        tld="org", date="2026-07-04", downloaded_at="2026-07-04T06:30:00+00:00",
        last_modified=None, soa_serial="1", zone_lines=50_000_000,
        ds_rrs=ds_rrs, ds_domains=ds_rrs, malformed=0, state_sha256="0" * 64,
    )


def test_sanity_gate_blocks_ds_collapse():
    with pytest.raises(QuarantineError, match="DS collapse"):
        sanity_check(_meta(100_000), curr_ds_rrs=50_000, curr_zone_lines=50_000_000,
                     min_ratio=0.7, min_zone_lines=10_000)


def test_sanity_gate_blocks_tiny_zone():
    with pytest.raises(QuarantineError, match="small"):
        sanity_check(_meta(100_000), curr_ds_rrs=100_000, curr_zone_lines=500,
                     min_ratio=0.7, min_zone_lines=10_000)


def test_sanity_gate_passes_normal_churn():
    sanity_check(_meta(100_000), curr_ds_rrs=99_000, curr_zone_lines=50_000_000,
                 min_ratio=0.7, min_zone_lines=10_000)
