"""Publikation: Event-JSONL, Tages-Aggregate mit Hash-Kette, Git-Commit.

Publiziert (committet) werden NUR Diffs und Aggregate — nie volle Snapshots
oder Roh-Zonendaten (CZDS ToU §1.6, „value-added"-Ausnahme).
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from pathlib import Path
from typing import Iterable

from .diff import Event
from .store import Rdata

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1


def _rdata_json(rr: Rdata) -> dict:
    key_tag, algorithm, digest_type, digest = rr
    return {
        "key_tag": key_tag,
        "algorithm": algorithm,
        "digest_type": digest_type,
        "digest": digest,
    }


def event_json(
    e: Event, *, date: str, tld: str, gap_days: int, run_id: str,
    rrsig_before: list[str] | None = None, rrsig_after: list[str] | None = None,
) -> dict:
    out = {
        "v": SCHEMA_VERSION,
        "date": date,
        "tld": tld,
        "domain": e.domain,
        "event": e.event,
        "before": [_rdata_json(rr) for rr in e.before],
        "after": [_rdata_json(rr) for rr in e.after],
        "gap_days": gap_days,
        "source": "czds",
        "run_id": run_id,
    }
    # RRSIG-Evidenz (v0.2): von der Registry signierte Belege für das RRset —
    # optional, weil Alt-States (v0.1) noch keine Proofs tragen
    if rrsig_before:
        out["rrsig_before"] = rrsig_before
    if rrsig_after:
        out["rrsig_after"] = rrsig_after
    return out


def write_events(
    events_dir: Path, tld: str, date: str, events: Iterable[dict]
) -> Path | None:
    """Events als JSONL nach events/<tld>/<jahr>/<datum>.jsonl; None wenn leer."""
    events = list(events)
    if not events:
        return None
    year = date[:4]
    path = events_dir / tld / year / f"{date}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".part")
    with tmp.open("w", encoding="ascii") as f:
        for e in events:
            f.write(json.dumps(e, sort_keys=True) + "\n")
    tmp.replace(path)
    return path


def write_dnskey(events_dir: Path, tld: str, date: str,
                 dnskey_rrset: list[str], dnskey_rrsigs: list[str],
                 soa_serial: str | None) -> Path | None:
    """Tages-DNSKEY-Paket der Elternzone für die Langzeit-Verifikation der RRSIGs.

    Wenige KB pro Tag; ohne den damaligen DNSKEY ließe sich eine alte RRSIG(DS)
    später nicht mehr prüfen.
    """
    if not dnskey_rrset:
        return None
    path = events_dir / tld / "dnskey" / f"{date}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".part")
    tmp.write_text(json.dumps({
        "v": SCHEMA_VERSION,
        "tld": tld,
        "date": date,
        "soa_serial": soa_serial,
        "dnskey": dnskey_rrset,
        "rrsig": dnskey_rrsigs,
    }, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)
    return path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _previous_stats(stats_dir: Path, tld: str, date: str) -> Path | None:
    d = stats_dir / tld
    if not d.is_dir():
        return None
    older = sorted(p for p in d.glob("*.json") if p.stem < date)
    return older[-1] if older else None


def write_stats(stats_dir: Path, tld: str, date: str, payload: dict) -> Path:
    """Tages-Aggregat schreiben; verkettet per SHA-256 mit dem Vortages-Aggregat."""
    prev = _previous_stats(stats_dir, tld, date)
    payload = {
        "v": SCHEMA_VERSION,
        "tld": tld,
        "date": date,
        **payload,
        "prev_stats": (
            {"file": f"{tld}/{prev.name}", "sha256": sha256_file(prev)} if prev else None
        ),
    }
    path = stats_dir / tld / f"{date}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".part")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)
    return path


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True
    )


def git_commit(root: Path, paths: list[Path], message: str, sign: str | bool) -> bool:
    """Events/Stats stagen und committen. True, wenn ein Commit entstand."""
    existing = [str(p) for p in paths if p.exists()]
    if not existing:
        return False
    add = _git(root, "add", "--", *existing)
    if add.returncode != 0:
        log.error("git add fehlgeschlagen: %s", add.stderr.strip())
        return False
    if _git(root, "diff", "--cached", "--quiet").returncode == 0:
        log.info("Keine Änderungen zu committen")
        return False

    if sign == "auto":
        sign = _git(root, "config", "--get", "user.signingkey").returncode == 0
    args = ["commit", "-m", message] + (["-S"] if sign else [])
    commit = _git(root, *args)
    if commit.returncode != 0:
        log.error("git commit fehlgeschlagen: %s", (commit.stderr or commit.stdout).strip())
        return False
    log.info("Commit erstellt%s: %s", " (signiert)" if sign else "", message)
    return True
