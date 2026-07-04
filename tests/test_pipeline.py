"""End-to-End-Test der run-Pipeline mit gemocktem Fetch (kein Netzwerk)."""

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

DAY1 = [
    "dev.\t900\tin\tsoa\tns1.dev. hostmaster.dev. 100 1 1 1 1",
    "dev.\t86400\tin\tns\tns1.dev.",
    "stable.dev.\t86400\tin\tds\t1 8 2 " + "aa" * 32,
    "gone.dev.\t86400\tin\tds\t2 8 2 " + "bb" * 32,
    "watched.dev.\t86400\tin\tds\t3 13 2 " + "cc" * 32,
]
DAY2 = [
    "dev.\t900\tin\tsoa\tns1.dev. hostmaster.dev. 101 1 1 1 1",
    "dev.\t86400\tin\tns\tns1.dev.",
    "stable.dev.\t86400\tin\tds\t1 8 2 " + "aa" * 32,
    "new.dev.\t86400\tin\tds\t4 13 2 " + "dd" * 32,
    "watched.dev.\t86400\tin\tds\t5 13 2 " + "ee" * 32,
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
    assert not (tmp_path / "events/dev").exists()  # Baseline erzeugt keine Events
    assert not (tmp_path / "state/work/dev.zone.gz").exists()  # Roh-Zone gelöscht

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

    stats2 = json.loads((tmp_path / "stats/dev/2026-07-05.json").read_text())
    assert stats2["events"] == {"ds_added": 1, "ds_removed": 1, "ds_changed": 1}
    assert stats2["gap_days"] == 1
    assert stats2["prev_stats"]["file"] == "dev/2026-07-04.json"
    assert len(stats2["prev_stats"]["sha256"]) == 64

    assert any("WATCHLIST" in rec.message for rec in caplog.records)

    meta = StateMeta.load(tmp_path / "state/dev/current.meta.json")
    assert meta.date == "2026-07-05"  # rotiert


def test_truncated_zone_quarantined(tmp_path, monkeypatch):
    cfg = _setup(tmp_path)
    monkeypatch.setattr(cli, "fetch_zone", _fake_fetch(DAY1))
    cli.run_tld(cfg, None, "dev", False, "2026-07-04", "run1")

    # 3 DS-RRs → 1 DS-RR ist ein Einbruch unter min_ratio → Quarantäne
    monkeypatch.setattr(cli, "fetch_zone", _fake_fetch(DAY3_TRUNCATED))
    r = cli.run_tld(cfg, None, "dev", False, "2026-07-05", "run2")
    assert r["status"] == "quarantined"
    assert (tmp_path / "state/dev/quarantine/2026-07-05.state.gz").is_file()
    # current bleibt der letzte gute Stand, nichts wurde publiziert
    assert StateMeta.load(tmp_path / "state/dev/current.meta.json").date == "2026-07-04"
    assert not (tmp_path / "events/dev").exists()
    assert not (tmp_path / "stats/dev/2026-07-05.json").exists()
