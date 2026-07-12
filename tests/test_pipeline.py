"""End-to-end test of the run pipeline with mocked fetch (no network)."""

import gzip
import json
import logging

import ds_watch.cli as cli
from ds_watch.config import load_config
from ds_watch.store import StateMeta, tld_paths

CONFIG = """
tlds = ["dev"]

[czds]
credentials_file = "unused"

[paths]
state_dir = "state"
events_dir = "events"
stats_dir = "stats"

[sanity]
min_ratio = 0.7
min_zone_lines = 3

[git]
commit = false

[watchlist]
domains = ["watched.dev"]
"""

def _rrsig_ds(label: str, tag: str) -> str:
    return (f"{label}.dev.\t86400\tin\trrsig\tds 13 2 86400 20260719000000 "
            f"20260704000000 999 dev. Sig{tag}")


DAY1 = [
    "dev.\t900\tin\tsoa\tns1.dev. hostmaster.dev. 100 1 1 1 1",
    "dev.\t86400\tin\tns\tns1.dev.",
    "dev.\t900\tin\tdnskey\t257 3 13 ApexKeyDay1",
    "dev.\t900\tin\trrsig\tdnskey 13 1 900 20260719000000 20260704000000 999 dev. ApexSigDay1",
    "stable.dev.\t86400\tin\tds\t1 8 2 " + "aa" * 32,
    _rrsig_ds("stable", "StableD1"),
    "gone.dev.\t86400\tin\tds\t2 8 2 " + "bb" * 32,
    _rrsig_ds("gone", "GoneD1"),
    "watched.dev.\t86400\tin\tds\t3 13 2 " + "cc" * 32,
    _rrsig_ds("watched", "WatchedD1"),
]
DAY2 = [
    "dev.\t900\tin\tsoa\tns1.dev. hostmaster.dev. 101 1 1 1 1",
    "dev.\t86400\tin\tns\tns1.dev.",
    "dev.\t900\tin\tdnskey\t257 3 13 ApexKeyDay2",
    "dev.\t900\tin\trrsig\tdnskey 13 1 900 20260719000000 20260704000000 999 dev. ApexSigDay2",
    "stable.dev.\t86400\tin\tds\t1 8 2 " + "aa" * 32,
    _rrsig_ds("stable", "StableD2"),
    "new.dev.\t86400\tin\tds\t4 13 2 " + "dd" * 32,
    _rrsig_ds("new", "NewD2"),
    "watched.dev.\t86400\tin\tds\t5 13 2 " + "ee" * 32,
    _rrsig_ds("watched", "WatchedD2"),
]
DAY3_TRUNCATED = [
    "dev.\t900\tin\tsoa\tns1.dev. hostmaster.dev. 102 1 1 1 1",
    "dev.\t86400\tin\tns\tns1.dev.",
    "stable.dev.\t86400\tin\tds\t1 8 2 " + "aa" * 32,
]


def _fake_fetch(zone_lines):
    def fetch(cfg, client, tld, force):
        tp = tld_paths(cfg.state_dir, tld)
        with gzip.open(tp.work_zone, "wt", encoding="ascii") as f:
            f.write("\n".join(zone_lines) + "\n")
        cli._head_sidecar(cfg, tld).write_text(json.dumps({
            "last_modified": "fake",
            "downloaded_at": "2026-07-04T06:30:00+00:00",
        }))
        return "downloaded"
    return fetch


def _setup(tmp_path):
    (tmp_path / "config.toml").write_text(CONFIG)
    return load_config(tmp_path / "config.toml")


def test_baseline_then_diff(tmp_path, monkeypatch, caplog):
    cfg = _setup(tmp_path)

    monkeypatch.setattr(cli, "fetch_zone", _fake_fetch(DAY1))
    r1 = cli.run_tld(cfg, None, "dev", False, "2026-07-04", "run1")
    assert r1["status"] == "baseline"
    stats1 = json.loads((tmp_path / "stats/dev/2026-07-04.json").read_text())
    assert stats1["baseline"] is True
    assert stats1["ds_domains"] == 3
    assert stats1["soa_serial"] == "100"
    assert stats1["prev_stats"] is None
    # Baseline produces no events (only the DNSKEY bundle under events/dev/dnskey/)
    assert not (tmp_path / "events/dev/2026").exists()
    assert not (tmp_path / "state/work/dev.zone.gz").exists()  # raw zone deleted

    monkeypatch.setattr(cli, "fetch_zone", _fake_fetch(DAY2))
    with caplog.at_level(logging.WARNING, logger="ds_watch"):
        r2 = cli.run_tld(cfg, None, "dev", False, "2026-07-05", "run2")
    assert r2["status"] == "ok"

    lines = (tmp_path / "events/dev/2026/2026-07-05.jsonl").read_text().splitlines()
    by = {e["domain"]: e for e in map(json.loads, lines)}
    assert by["gone.dev"]["event"] == "ds_removed"
    assert by["new.dev"]["event"] == "ds_added"
    assert by["watched.dev"]["event"] == "ds_changed"
    assert by["watched.dev"]["before"][0]["key_tag"] == 3
    assert by["watched.dev"]["after"][0]["key_tag"] == 5

    # RRSIG evidence: registry signatures for the before and after state
    assert by["watched.dev"]["rrsig_before"][0].endswith("dev. SigWatchedD1")
    assert by["watched.dev"]["rrsig_after"][0].endswith("dev. SigWatchedD2")
    assert by["gone.dev"]["rrsig_before"][0].endswith("dev. SigGoneD1")
    assert "rrsig_after" not in by["gone.dev"]  # RRset gone → no new signature
    assert by["new.dev"]["rrsig_after"][0].endswith("dev. SigNewD2")
    assert "rrsig_before" not in by["new.dev"]

    # Daily DNSKEY bundles for long-term verification
    dk1 = json.loads((tmp_path / "events/dev/dnskey/2026-07-04.json").read_text())
    assert dk1["dnskey"] == ["257 3 13 ApexKeyDay1"]
    dk2 = json.loads((tmp_path / "events/dev/dnskey/2026-07-05.json").read_text())
    assert dk2["rrsig"][0].endswith("dev. ApexSigDay2")

    assert (tmp_path / "state/dev/current.proofs.gz").is_file()  # rotated

    stats2 = json.loads((tmp_path / "stats/dev/2026-07-05.json").read_text())
    assert stats2["events"] == {"ds_added": 1, "ds_removed": 1, "ds_changed": 1}
    assert stats2["gap_days"] == 1
    assert stats2["prev_stats"]["file"] == "dev/2026-07-04.json"
    assert len(stats2["prev_stats"]["sha256"]) == 64

    assert any("WATCHLIST" in rec.message for rec in caplog.records)
    assert [h["domain"] for h in r2["watchlist_hits"]] == ["watched.dev"]

    meta = StateMeta.load(tmp_path / "state/dev/current.meta.json")
    assert meta.date == "2026-07-05"  # rotated


def test_truncated_zone_quarantined(tmp_path, monkeypatch):
    cfg = _setup(tmp_path)
    monkeypatch.setattr(cli, "fetch_zone", _fake_fetch(DAY1))
    cli.run_tld(cfg, None, "dev", False, "2026-07-04", "run1")

    # 3 DS RRs → 1 DS RR is a drop below min_ratio → quarantine
    monkeypatch.setattr(cli, "fetch_zone", _fake_fetch(DAY3_TRUNCATED))
    r = cli.run_tld(cfg, None, "dev", False, "2026-07-05", "run2")
    assert r["status"] == "quarantined"
    assert (tmp_path / "state/dev/quarantine/2026-07-05.state.gz").is_file()
    assert (tmp_path / "state/dev/quarantine/2026-07-05.proofs.gz").is_file()
    # current stays the last good state, nothing was published
    assert StateMeta.load(tmp_path / "state/dev/current.meta.json").date == "2026-07-04"
    assert not (tmp_path / "events/dev/2026").exists()
    assert not (tmp_path / "events/dev/dnskey/2026-07-05.json").exists()
    assert not (tmp_path / "stats/dev/2026-07-05.json").exists()
