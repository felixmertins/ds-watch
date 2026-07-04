"""Diff zweier DS-States → Events, plus Sanity-Gate gegen kaputte Läufe."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import groupby
from operator import itemgetter
from typing import Iterable, Iterator

from .store import Rdata, StateMeta

DS_ADDED = "ds_added"  # kein DS → DS: DNSSEC-Bootstrap
DS_REMOVED = "ds_removed"  # DS → kein DS: Delegation geht insecure (wichtigstes Signal)
DS_CHANGED = "ds_changed"  # RRset differiert: KSK-/Algorithmus-Rollover oder Schlüsseltausch


class QuarantineError(Exception):
    """Neuer Snapshot ist verdächtig — nicht diffen, nicht publizieren."""


@dataclass
class Event:
    domain: str
    event: str
    before: list[Rdata]
    after: list[Rdata]


def sanity_check(prev: StateMeta, curr_ds_rrs: int, curr_zone_lines: int,
                 min_ratio: float, min_zone_lines: int) -> None:
    """Abgeschnittene/leere Zonen erzeugen sonst Massen-`ds_removed`-Events."""
    if curr_zone_lines < min_zone_lines:
        raise QuarantineError(
            f"Zone verdächtig klein: {curr_zone_lines} Zeilen (< {min_zone_lines})"
        )
    if prev.ds_rrs > 0 and curr_ds_rrs < prev.ds_rrs * min_ratio:
        raise QuarantineError(
            f"DS-Einbruch: {curr_ds_rrs} RRs vs. {prev.ds_rrs} am Vortag "
            f"(< Faktor {min_ratio})"
        )


def _by_domain(state: Iterable[tuple[str, Rdata]]) -> Iterator[tuple[str, list[Rdata]]]:
    for domain, group in groupby(state, key=itemgetter(0)):
        yield domain, [rr for _, rr in group]


def diff_states(
    prev: Iterable[tuple[str, Rdata]], curr: Iterable[tuple[str, Rdata]]
) -> Iterator[Event]:
    """Merge-Diff zweier domain-sortierter States, RRset-Vergleich pro Delegation."""
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
