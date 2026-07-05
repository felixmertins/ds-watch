"""E-Mail-Alerting: Watchlist-Treffer und Betriebsprobleme (Quarantäne, Grant/ToU).

Versand per SMTP (Default: localhost:25 — auf dem VPS reicht ein lokaler MTA
oder msmtp als sendmail-Ersatz). Fehler beim Versand brechen den Lauf nie ab:
Alerting ist Zusatzkanal, die Log-Warnung bleibt die Quelle der Wahrheit.
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
    """True bei erfolgreichem Versand; False (mit Log) bei Fehler oder deaktiviert."""
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
        log.info("Alert-Mail an %s verschickt: %s", cfg.to, subject)
        return True
    except (OSError, smtplib.SMTPException, KeyError) as e:
        log.error("Alert-Mail fehlgeschlagen (%s) — Inhalt war:\n%s\n%s", e, subject, body)
        return False


def format_run_alert(date: str, watchlist_hits: list[dict], attention: list[dict]) -> tuple[str, str]:
    """(Subject, Body) für die Sammel-Mail eines Laufs."""
    parts_subject = []
    if watchlist_hits:
        parts_subject.append(f"{len(watchlist_hits)} watchlist hit(s)")
    if attention:
        parts_subject.append(f"{len(attention)} zone(s) need attention")
    subject = f"[ds-watch] {date}: " + ", ".join(parts_subject)

    lines = []
    if watchlist_hits:
        lines.append("WATCHLIST-TREFFER")
        lines.append("=" * 17)
        for h in watchlist_hits:
            lines.append(f"{h['domain']} ({h['event']})")
            lines.append(f"  before: {h['before'] or '—'}")
            lines.append(f"  after:  {h['after'] or '—'}")
        lines.append("")
        lines.append("Nicht selbst veranlasst? DS-Änderungen laufen über den Registrar —")
        lines.append("Account prüfen und ggf. Registrar/Registry kontaktieren.")
        lines.append("")
    if attention:
        lines.append("BETRIEB")
        lines.append("=" * 7)
        for a in attention:
            lines.append(f".{a['tld']}: {a['status']}" + (f" — {a['reason']}" if a.get("reason") else ""))
        lines.append("")
        lines.append("Quarantäne: state/<tld>/quarantine/ prüfen. 403/409: CZDS-Portal")
        lines.append("(Grant verlängern bzw. neue Terms akzeptieren).")
    return subject, "\n".join(lines).rstrip() + "\n"
