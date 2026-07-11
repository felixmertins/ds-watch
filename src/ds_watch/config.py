"""Config and credentials loading (TOML, stdlib tomllib)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class AlertConfig:
    to: str  # empty = alerting disabled
    sender: str
    smtp_host: str
    smtp_port: int
    starttls: bool
    credentials_file: Path | None  # optional: TOML with smtp_user/smtp_password
    on_attention: bool  # also mail on quarantine/403/409

    @property
    def enabled(self) -> bool:
        return bool(self.to)


@dataclass(frozen=True)
class Config:
    root: Path  # directory of config.toml = repo root
    tlds: list[str]
    credentials_file: Path
    auth_url: str
    api_base: str
    user_agent: str
    min_fetch_interval_hours: float
    state_dir: Path
    events_dir: Path
    stats_dir: Path
    sanity_min_ratio: float
    sanity_min_zone_lines: int
    git_commit: bool
    git_sign: str | bool
    watchlist: frozenset[str]
    alert: AlertConfig


def _resolve(root: Path, value: str) -> Path:
    p = Path(value).expanduser()
    return p if p.is_absolute() else root / p


def load_config(path: Path) -> Config:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise ConfigError(
            f"Config file missing: {path} — copy config.example.toml to config.toml"
        )
    with path.open("rb") as f:
        raw = tomllib.load(f)

    root = path.parent
    czds = raw.get("czds", {})
    paths = raw.get("paths", {})
    sanity = raw.get("sanity", {})
    git = raw.get("git", {})
    watchlist = raw.get("watchlist", {})
    alert = raw.get("alert", {})

    tlds = [t.strip(".").lower() for t in raw.get("tlds", [])]
    if not tlds:
        raise ConfigError("No TLDs configured (key `tlds`)")

    return Config(
        root=root,
        tlds=tlds,
        credentials_file=Path(
            czds.get("credentials_file", "~/.config/ds-watch/credentials")
        ).expanduser(),
        auth_url=czds.get("auth_url", "https://account-api.icann.org/api/authenticate"),
        api_base=czds.get("api_base", "https://czds-api.icann.org").rstrip("/"),
        user_agent=czds.get("user_agent", "ds-watch/0.2"),
        min_fetch_interval_hours=float(czds.get("min_fetch_interval_hours", 20)),
        state_dir=_resolve(root, paths.get("state_dir", "state")),
        events_dir=_resolve(root, paths.get("events_dir", "events")),
        stats_dir=_resolve(root, paths.get("stats_dir", "stats")),
        sanity_min_ratio=float(sanity.get("min_ratio", 0.7)),
        sanity_min_zone_lines=int(sanity.get("min_zone_lines", 10000)),
        git_commit=bool(git.get("commit", True)),
        git_sign=git.get("sign", "auto"),
        watchlist=frozenset(d.strip(".").lower() for d in watchlist.get("domains", [])),
        alert=AlertConfig(
            to=alert.get("to", ""),
            sender=alert.get("from", "ds-watch@localhost"),
            smtp_host=alert.get("smtp_host", "localhost"),
            smtp_port=int(alert.get("smtp_port", 25)),
            starttls=bool(alert.get("starttls", False)),
            credentials_file=(
                Path(alert["credentials_file"]).expanduser()
                if alert.get("credentials_file") else None
            ),
            on_attention=bool(alert.get("on_attention", True)),
        ),
    )


def load_credentials(path: Path) -> tuple[str, str]:
    if not path.is_file():
        raise ConfigError(
            f"Credentials file missing: {path}\n"
            'Expected format (TOML):\n  username = "..."\n  password = "..."\n'
            f"Create it with chmod 600."
        )
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise ConfigError(
            f"{path} is readable by group/others (mode {oct(mode)}) — please chmod 600"
        )
    with path.open("rb") as f:
        creds = tomllib.load(f)
    try:
        return creds["username"], creds["password"]
    except KeyError as e:
        raise ConfigError(f"Credentials file missing key {e}") from None
