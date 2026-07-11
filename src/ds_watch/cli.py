"""CLI: ds-watch fetch|extract|diff|run|status.

Exit codes (for systemd/cron alerting):
  0 = OK, 1 = error, 2 = needs attention (quarantine, grant/ToU problem)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import date as date_t
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .alert import format_run_alert, send_alert
from .config import Config, ConfigError, load_config, load_credentials
from .czds_client import CzdsAccessError, CzdsClient, CzdsError, CzdsTermsError
from .diff import QuarantineError, diff_states, sanity_check
from .extract import ExtractResult, extract_ds_state
from .publish import event_json, git_commit, write_dnskey, write_events, write_stats
from .store import StateMeta, load_proofs_for, read_state, tld_paths

log = logging.getLogger("ds_watch")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ATTENTION = 2


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_client(cfg: Config) -> CzdsClient:
    username, password = load_credentials(cfg.credentials_file)
    return CzdsClient(
        auth_url=cfg.auth_url,
        api_base=cfg.api_base,
        username=username,
        password=password,
        user_agent=cfg.user_agent,
        token_cache=cfg.state_dir / "token.json",
    )


def _head_sidecar(cfg: Config, tld: str) -> Path:
    return cfg.state_dir / "work" / f"{tld}.head.json"


# -- fetch --------------------------------------------------------------------


def fetch_zone(cfg: Config, client: CzdsClient, tld: str, force: bool) -> str:
    """Fetch the zone if it is new and ToU-compliant (§1.8: max 1 download / 24 h)."""
    tp = tld_paths(cfg.state_dir, tld)
    meta = StateMeta.load(tp.current_meta) if tp.has_current() else None
    head = client.head(tld)

    if meta and not force:
        if head.last_modified and meta.last_modified == head.last_modified:
            log.info(".%s: zone unchanged (Last-Modified %s) — skipped",
                     tld, head.last_modified)
            return "unchanged"
        age_h = (_now() - datetime.fromisoformat(meta.downloaded_at)).total_seconds() / 3600
        if age_h < cfg.min_fetch_interval_hours:
            log.warning(
                ".%s: last download %.1f h ago (< %g h, ToU §1.8) — skipped "
                "(--force overrides)", tld, age_h, cfg.min_fetch_interval_hours,
            )
            return "too-recent"

    head = client.download(tld, tp.work_zone)
    _head_sidecar(cfg, tld).write_text(json.dumps({
        "last_modified": head.last_modified,
        "downloaded_at": _now().isoformat(timespec="seconds"),
    }))
    return "downloaded"


# -- extract ------------------------------------------------------------------


def extract_zone(cfg: Config, tld: str, date: str) -> tuple[StateMeta, "ExtractResult"]:
    """Work zone → new.state.gz + new.meta.json. Does NOT delete the raw zone."""
    tp = tld_paths(cfg.state_dir, tld)
    if not tp.work_zone.is_file():
        raise CzdsError(f".{tld}: no raw zone at {tp.work_zone} — run `fetch` first")
    sidecar = _head_sidecar(cfg, tld)
    head = json.loads(sidecar.read_text()) if sidecar.is_file() else {}

    result = extract_ds_state(tp.work_zone, tp.new_state, tld, proofs_out=tp.new_proofs)
    meta = StateMeta(
        tld=tld,
        date=date,
        downloaded_at=head.get("downloaded_at", _now().isoformat(timespec="seconds")),
        last_modified=head.get("last_modified"),
        soa_serial=result.soa_serial,
        zone_lines=result.zone_lines,
        ds_rrs=result.ds_rrs,
        ds_domains=result.ds_domains,
        malformed=result.malformed,
        state_sha256=result.state_sha256,
        rrsig_ds=result.rrsig_ds,
    )
    meta.save(tp.new_meta)
    return meta, result


# -- run ----------------------------------------------------------------------


def run_tld(cfg: Config, client: CzdsClient, tld: str, force: bool,
            date: str, run_id: str) -> dict:
    tp = tld_paths(cfg.state_dir, tld)

    status = fetch_zone(cfg, client, tld, force)
    if status != "downloaded":
        return {"tld": tld, "status": status}

    try:
        new_meta, result = extract_zone(cfg, tld, date)
    finally:
        # ToU §1.4: keep raw zone data only as long as necessary
        tp.work_zone.unlink(missing_ok=True)
        _head_sidecar(cfg, tld).unlink(missing_ok=True)

    baseline = not tp.has_current()
    events = []
    gap_days = 0
    if not baseline:
        prev_meta = StateMeta.load(tp.current_meta)
        try:
            sanity_check(prev_meta, new_meta.ds_rrs, new_meta.zone_lines,
                         cfg.sanity_min_ratio, cfg.sanity_min_zone_lines)
        except QuarantineError as e:
            qpath = tp.quarantine(date)
            log.error(".%s: QUARANTINE — %s (snapshot: %s)", tld, e, qpath)
            return {"tld": tld, "status": "quarantined", "reason": str(e)}
        gap_days = (date_t.fromisoformat(date) - date_t.fromisoformat(prev_meta.date)).days
        if gap_days > 1:
            log.warning(".%s: diff spans %d days", tld, gap_days)
        events = list(diff_states(read_state(tp.current_state), read_state(tp.new_state)))

    watchlist_hits = []
    for e in events:
        if e.domain in cfg.watchlist:
            log.warning(
                "WATCHLIST HIT: %s — %s (before=%s, after=%s)",
                e.domain, e.event, e.before, e.after,
            )
            watchlist_hits.append({
                "domain": e.domain,
                "event": e.event,
                "before": ", ".join(map(str, e.before)),
                "after": ", ".join(map(str, e.after)),
            })

    # RRSIG evidence: registry signatures for exactly the delegations with events
    proofs_before: dict[str, list[str]] = {}
    proofs_after: dict[str, list[str]] = {}
    if events:
        domains = {e.domain for e in events}
        proofs_before = load_proofs_for(tp.current_proofs, domains)
        proofs_after = load_proofs_for(tp.new_proofs, domains)

    counts = Counter(e.event for e in events)
    json_events = [
        event_json(e, date=date, tld=tld, gap_days=gap_days, run_id=run_id,
                   rrsig_before=proofs_before.get(e.domain),
                   rrsig_after=proofs_after.get(e.domain))
        for e in events
    ]
    ev_path = write_events(cfg.events_dir, tld, date, json_events)
    dk_path = write_dnskey(cfg.events_dir, tld, date,
                           result.dnskey_rrset, result.dnskey_rrsigs,
                           new_meta.soa_serial)
    st_path = write_stats(cfg.stats_dir, tld, date, {
        "baseline": baseline,
        "soa_serial": new_meta.soa_serial,
        "zone_lines": new_meta.zone_lines,
        "ds_rrs": new_meta.ds_rrs,
        "ds_domains": new_meta.ds_domains,
        "malformed": new_meta.malformed,
        "gap_days": gap_days,
        "events": {k: counts.get(k, 0) for k in ("ds_added", "ds_removed", "ds_changed")},
        "algorithms": dict(result.algorithms),
        "digest_types": dict(result.digest_types),
    })
    tp.rotate()

    return {
        "tld": tld,
        "status": "baseline" if baseline else "ok",
        "counts": counts,
        "ds_domains": new_meta.ds_domains,
        "paths": [p for p in (ev_path, st_path, dk_path) if p],
        "watchlist_hits": watchlist_hits,
    }


def _summary_line(r: dict) -> str:
    if r["status"] == "ok":
        c = r["counts"]
        return (f"{r['tld']} +{c.get('ds_added', 0)} "
                f"-{c.get('ds_removed', 0)} ~{c.get('ds_changed', 0)}")
    if r["status"] == "baseline":
        return f"{r['tld']} baseline ({r['ds_domains']} DS domains)"
    return f"{r['tld']} {r['status']}"


def cmd_run(cfg: Config, args: argparse.Namespace) -> int:
    client = _make_client(cfg)
    date = _now().date().isoformat()
    run_id = _now().strftime("%Y-%m-%dT%H:%MZ")
    results = []
    exit_code = EXIT_OK

    for tld in args.tlds:
        try:
            results.append(run_tld(cfg, client, tld, args.force, date, run_id))
        except (CzdsAccessError, CzdsTermsError) as e:
            log.error(".%s: %s", tld, e)
            results.append({"tld": tld, "status": "needs-attention"})
            exit_code = EXIT_ATTENTION
        except CzdsError as e:
            log.error(".%s: %s", tld, e)
            results.append({"tld": tld, "status": "error"})
            exit_code = max(exit_code, EXIT_ERROR)

    if any(r["status"] == "quarantined" for r in results):
        exit_code = EXIT_ATTENTION

    if cfg.git_commit and any(r.get("paths") for r in results):
        parts = [_summary_line(r) for r in results if r["status"] in ("ok", "baseline")]
        git_commit(
            cfg.root,
            [cfg.events_dir, cfg.stats_dir],
            f"run {date}: " + "; ".join(parts),
            cfg.git_sign,
        )

    hits = [h for r in results for h in r.get("watchlist_hits", [])]
    attention = [r for r in results if r["status"] in ("quarantined", "needs-attention", "error")]
    if cfg.alert.enabled and (hits or (attention and cfg.alert.on_attention)):
        send_alert(cfg.alert, *format_run_alert(date, hits, attention))

    for r in results:
        log.info("result: %s", _summary_line(r))
    return exit_code


# -- individual commands ----------------------------------------------------------


def cmd_fetch(cfg: Config, args: argparse.Namespace) -> int:
    client = _make_client(cfg)
    code = EXIT_OK
    for tld in args.tlds:
        try:
            fetch_zone(cfg, client, tld, args.force)
        except (CzdsAccessError, CzdsTermsError) as e:
            log.error(".%s: %s", tld, e)
            code = EXIT_ATTENTION
    return code


def cmd_extract(cfg: Config, args: argparse.Namespace) -> int:
    date = _now().date().isoformat()
    for tld in args.tlds:
        extract_zone(cfg, tld, date)
        log.info(".%s: state at %s (raw zone is kept for debugging — "
                 "`run` deletes it)", tld, tld_paths(cfg.state_dir, tld).new_state)
    return EXIT_OK


def cmd_diff(cfg: Config, args: argparse.Namespace) -> int:
    """Dry run: diff current vs. new, print events as JSONL to stdout, write nothing."""
    date = _now().date().isoformat()
    for tld in args.tlds:
        tp = tld_paths(cfg.state_dir, tld)
        if not tp.new_state.is_file():
            log.error(".%s: no new state (%s) — run `extract` first", tld, tp.new_state)
            return EXIT_ERROR
        if not tp.has_current():
            log.info(".%s: no previous-day state — diff would be a baseline", tld)
            continue
        for e in diff_states(read_state(tp.current_state), read_state(tp.new_state)):
            print(json.dumps(event_json(e, date=date, tld=tld, gap_days=0,
                                        run_id="dry-run"), sort_keys=True))
    return EXIT_OK


def cmd_status(cfg: Config, args: argparse.Namespace) -> int:
    for tld in args.tlds:
        tp = tld_paths(cfg.state_dir, tld)
        if not tp.has_current():
            print(f".{tld}: no state (no successful run yet)")
            continue
        m = StateMeta.load(tp.current_meta)
        quarantined = len(list(tp.quarantine_dir.glob("*.state.gz"))) \
            if tp.quarantine_dir.is_dir() else 0
        print(
            f".{tld}: as of {m.date} (SOA {m.soa_serial}), "
            f"{m.ds_rrs} DS RRs across {m.ds_domains} delegations, "
            f"zone {m.zone_lines} lines, quarantine: {quarantined}"
        )
    return EXIT_OK


# -- main -----------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ds-watch",
        description="DS record observatory over ICANN CZDS zone files",
    )
    parser.add_argument("-c", "--config", type=Path, default=Path("config.toml"),
                        help="path to config.toml (default: ./config.toml)")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=f"ds-watch {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, fn, doc in (
        ("fetch", cmd_fetch, "download zone files (with HEAD check and 24 h guard)"),
        ("extract", cmd_extract, "extract DS state from a downloaded raw zone"),
        ("diff", cmd_diff, "dry-run diff of current vs. new on stdout"),
        ("run", cmd_run, "full run: fetch → extract → diff → publish → rotate"),
        ("status", cmd_status, "state overview per TLD"),
    ):
        p = sub.add_parser(name, help=doc)
        p.set_defaults(fn=fn)
        p.add_argument("--tld", dest="tlds", action="append", metavar="TLD",
                       help="only this TLD (repeatable; default: all from config)")
        p.add_argument("--force", action="store_true",
                       help="bypass the HEAD/24 h guard (fetch/run)")

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        log.error("%s", e)
        return EXIT_ERROR

    args.tlds = [t.strip(".").lower() for t in (args.tlds or cfg.tlds)]

    try:
        return args.fn(cfg, args)
    except ConfigError as e:
        log.error("%s", e)
        return EXIT_ERROR
    except CzdsError as e:
        log.error("%s", e)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
