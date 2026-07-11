"""Email alerting: watchlist hits and operational issues (quarantine, grant/ToU).

Delivery via SMTP (default: localhost:25 — on the VPS a local MTA or msmtp
as a sendmail replacement is enough). Send failures never abort the run:
alerting is a secondary channel; the log warning remains the source of truth.
"""

from __future__ import annotations

import logging
import smtplib
import tomllib
from email.message import EmailMessage
from email.utils import formatdate

from .config import AlertConfig

log = logging.getLogger(__name__)


def send_alert(cfg: AlertConfig, subject: str, body: str) -> bool:
    """True if sent successfully; False (with log) on failure or when disabled."""
    if not cfg.enabled:
        return False
    msg = EmailMessage()
    msg["From"] = cfg.sender
    msg["To"] = cfg.to
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(body)

    try:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=30) as smtp:
            if cfg.starttls:
                smtp.starttls()
            if cfg.credentials_file:
                with cfg.credentials_file.open("rb") as f:
                    creds = tomllib.load(f)
                smtp.login(creds["smtp_user"], creds["smtp_password"])
            smtp.send_message(msg)
        log.info("Alert email sent to %s: %s", cfg.to, subject)
        return True
    except (OSError, smtplib.SMTPException, KeyError) as e:
        log.error("Alert email failed (%s) — content was:\n%s\n%s", e, subject, body)
        return False


def format_run_alert(date: str, watchlist_hits: list[dict], attention: list[dict]) -> tuple[str, str]:
    """(Subject, body) for a run's digest email."""
    parts_subject = []
    if watchlist_hits:
        parts_subject.append(f"{len(watchlist_hits)} watchlist hit(s)")
    if attention:
        parts_subject.append(f"{len(attention)} zone(s) need attention")
    subject = f"[ds-watch] {date}: " + ", ".join(parts_subject)

    lines = []
    if watchlist_hits:
        lines.append("WATCHLIST HITS")
        lines.append("=" * 14)
        for h in watchlist_hits:
            lines.append(f"{h['domain']} ({h['event']})")
            lines.append(f"  before: {h['before'] or '—'}")
            lines.append(f"  after:  {h['after'] or '—'}")
        lines.append("")
        lines.append("Didn't initiate this yourself? DS changes go through the registrar —")
        lines.append("check your account and contact the registrar/registry if needed.")
        lines.append("")
    if attention:
        lines.append("OPERATIONS")
        lines.append("=" * 10)
        for a in attention:
            lines.append(f".{a['tld']}: {a['status']}" + (f" — {a['reason']}" if a.get("reason") else ""))
        lines.append("")
        lines.append("Quarantine: inspect state/<tld>/quarantine/. 403/409: CZDS portal")
        lines.append("(renew the grant or accept the new terms).")
    return subject, "\n".join(lines).rstrip() + "\n"
