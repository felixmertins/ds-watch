from pathlib import Path

import ds_watch.alert as alert_mod
from ds_watch.alert import format_run_alert, send_alert
from ds_watch.config import AlertConfig


def _cfg(**kw) -> AlertConfig:
    defaults = dict(to="ops@example.test", sender="ds-watch@example.test",
                    smtp_host="localhost", smtp_port=25, starttls=False,
                    credentials_file=None, on_attention=True)
    return AlertConfig(**{**defaults, **kw})


def test_disabled_without_recipient():
    assert send_alert(_cfg(to=""), "s", "b") is False


def test_send_via_smtp(monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["conn"] = (host, port)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self): sent["starttls"] = True
        def login(self, u, p): sent["login"] = (u, p)
        def send_message(self, msg): sent["msg"] = msg

    monkeypatch.setattr(alert_mod.smtplib, "SMTP", FakeSMTP)
    ok = send_alert(_cfg(), "[ds-watch] test", "body\n")
    assert ok is True
    assert sent["conn"] == ("localhost", 25)
    assert "starttls" not in sent and "login" not in sent
    assert sent["msg"]["To"] == "ops@example.test"
    assert sent["msg"]["Subject"] == "[ds-watch] test"
    assert sent["msg"]["Auto-Submitted"] == "auto-generated"


def test_send_failure_is_swallowed(monkeypatch):
    def boom(*a, **kw):
        raise OSError("connection refused")
    monkeypatch.setattr(alert_mod.smtplib, "SMTP", boom)
    assert send_alert(_cfg(), "s", "b") is False  # kein Raise — Lauf geht weiter


def test_format_run_alert():
    hits = [{"domain": "mertins.dev", "event": "ds_changed",
             "before": "(46661, 8, 2, 'aa')", "after": "(11111, 13, 2, 'bb')"}]
    attention = [{"tld": "org", "status": "quarantined", "reason": "DS-Einbruch"}]
    subject, body = format_run_alert("2026-07-06", hits, attention)
    assert "1 watchlist hit" in subject
    assert "1 zone(s) need attention" in subject
    assert "mertins.dev (ds_changed)" in body
    assert ".org: quarantined — DS-Einbruch" in body
    assert "Registrar" in body
