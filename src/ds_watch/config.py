"""Konfigurations- und Credentials-Laden (TOML, stdlib tomllib)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    root: Path  # Verzeichnis der config.toml = Repo-Root
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


def _resolve(root: Path, value: str) -> Path:
    p = Path(value).expanduser()
    return p if p.is_absolute() else root / p


def load_config(path: Path) -> Config:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise ConfigError(
            f"Konfigurationsdatei fehlt: {path} — config.example.toml nach config.toml kopieren"
        )
    with path.open("rb") as f:
        raw = tomllib.load(f)

    root = path.parent
    czds = raw.get("czds", {})
    paths = raw.get("paths", {})
    sanity = raw.get("sanity", {})
    git = raw.get("git", {})
    watchlist = raw.get("watchlist", {})

    tlds = [t.strip(".").lower() for t in raw.get("tlds", [])]
    if not tlds:
        raise ConfigError("Keine TLDs konfiguriert (Schlüssel `tlds`)")

    return Config(
        root=root,
        tlds=tlds,
        credentials_file=Path(
            czds.get("credentials_file", "~/.config/ds-watch/credentials")
        ).expanduser(),
        auth_url=czds.get("auth_url", "https://account-api.icann.org/api/authenticate"),
        api_base=czds.get("api_base", "https://czds-api.icann.org").rstrip("/"),
        user_agent=czds.get("user_agent", "ds-watch/0.1"),
        min_fetch_interval_hours=float(czds.get("min_fetch_interval_hours", 20)),
        state_dir=_resolve(root, paths.get("state_dir", "state")),
        events_dir=_resolve(root, paths.get("events_dir", "events")),
        stats_dir=_resolve(root, paths.get("stats_dir", "stats")),
        sanity_min_ratio=float(sanity.get("min_ratio", 0.7)),
        sanity_min_zone_lines=int(sanity.get("min_zone_lines", 10000)),
        git_commit=bool(git.get("commit", True)),
        git_sign=git.get("sign", "auto"),
        watchlist=frozenset(d.strip(".").lower() for d in watchlist.get("domains", [])),
    )


def load_credentials(path: Path) -> tuple[str, str]:
    if not path.is_file():
        raise ConfigError(
            f"Credentials-Datei fehlt: {path}\n"
            'Erwartetes Format (TOML):\n  username = "..."\n  password = "..."\n'
            f"Anlegen mit chmod 600."
        )
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise ConfigError(
            f"{path} ist für Gruppe/Andere lesbar (Modus {oct(mode)}) — bitte chmod 600"
        )
    with path.open("rb") as f:
        creds = tomllib.load(f)
    try:
        return creds["username"], creds["password"]
    except KeyError as e:
        raise ConfigError(f"Credentials-Datei ohne Schlüssel {e}") from None
