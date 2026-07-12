"""Diff two DS states into events, plus a sanity gate against broken runs."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import groupby
from operator import itemgetter
from typing import Iterable, Iterator

from .store import Rdata, StateMeta

DS_ADDED = "ds_added"  # no DS → DS: DNSSEC bootstrap
DS_REMOVED = "ds_removed"  # DS → no DS: delegation goes insecure (the most important signal)
DS_CHANGED = "ds_changed"  # RRset differs: KSK/algorithm rollover or key replacement


class QuarantineError(Exception):
    """New snapshot is suspicious — do not diff, do not publish."""


@dataclass
class Event:
    domain: str
    event: str
    before: list[Rdata]
    after: list[Rdata]


def sanity_check(prev: StateMeta, curr_ds_rrs: int, curr_zone_lines: int,
                 min_ratio: float, min_zone_lines: int) -> None:
    """Truncated/empty zones would otherwise produce mass `ds_removed` events."""
    if curr_zone_lines < min_zone_lines:
        raise QuarantineError(
            f"Zone suspiciously small: {curr_zone_lines} lines (< {min_zone_lines})"
        )
    if prev.ds_rrs > 0 and curr_ds_rrs < prev.ds_rrs * min_ratio:
        raise QuarantineError(
            f"DS collapse: {curr_ds_rrs} RRs vs. {prev.ds_rrs} the day before "
            f"(< factor {min_ratio})"
        )


def _by_domain(state: Iterable[tuple[str, Rdata]]) -> Iterator[tuple[str, list[Rdata]]]:
    for domain, group in groupby(state, key=itemgetter(0)):
        yield domain, [rr for _, rr in group]


def diff_states(
    prev: Iterable[tuple[str, Rdata]], curr: Iterable[tuple[str, Rdata]]
) -> Iterator[Event]:
    """Merge-diff two domain-sorted states, comparing the RRset per delegation."""
    prev_groups = _by_domain(prev)
    curr_groups = _by_domain(curr)
    a = next(prev_groups, None)
    b = next(curr_groups, None)
    while a is not None or b is not None:
        if b is None or (a is not None and a[0] < b[0]):
            yield Event(a[0], DS_REMOVED, before=a[1], after=[])
            a = next(prev_groups, None)
        elif a is None or b[0] < a[0]:
            yield Event(b[0], DS_ADDED, before=[], after=b[1])
            b = next(curr_groups, None)
        else:
            if a[1] != b[1]:
                yield Event(a[0], DS_CHANGED, before=a[1], after=b[1])
            a = next(prev_groups, None)
            b = next(curr_groups, None)
