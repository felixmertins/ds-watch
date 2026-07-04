"""ICANN-CZDS-API-Client: Auth (JWT, 24 h gültig), Zonen-Listing, HEAD, Download.

API-Randbedingungen (ICANN CZDS API Spec 2022-05-24, ToU v1.00):
- User-Agent-Header ist Pflicht, sonst Redirect auf eine Maintenance-Seite
- Auth-Rate-Limit: 8 Versuche / 5 min / IP → Token wird 23 h gecacht
- 401 = Token abgelaufen (einmalige Re-Auth), 403 = Grant fehlt/abgelaufen,
  409 = neue Terms & Conditions müssen im CZDS-Portal akzeptiert werden
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

import requests

log = logging.getLogger(__name__)

TOKEN_MAX_AGE_S = 23 * 3600  # JWT gilt 24 h; 1 h Sicherheitsmarge
DOWNLOAD_CHUNK = 1 << 20


class CzdsError(Exception):
    pass


class CzdsAuthError(CzdsError):
    pass


class CzdsAccessError(CzdsError):
    """HTTP 403: Zone nicht genehmigt oder Grant abgelaufen — Portal prüfen."""


class CzdsTermsError(CzdsError):
    """HTTP 409: neue Terms & Conditions müssen im CZDS-Portal akzeptiert werden."""


@dataclass
class ZoneHead:
    content_length: int | None
    last_modified: str | None


class CzdsClient:
    def __init__(
        self,
        auth_url: str,
        api_base: str,
        username: str,
        password: str,
        user_agent: str,
        token_cache: Path,
    ):
        self.auth_url = auth_url
        self.api_base = api_base
        self.username = username
        self.password = password
        self.user_agent = user_agent
        self.token_cache = token_cache
        self.session = requests.Session()
        self._links: list[str] | None = None

    # -- Auth ---------------------------------------------------------------

    def _authenticate(self) -> str:
        resp = self.session.post(
            self.auth_url,
            json={"username": self.username, "password": self.password},
            headers={
                "User-Agent": self.user_agent,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=60,
        )
        if resp.status_code == 429:
            raise CzdsAuthError(
                "Auth-Rate-Limit erreicht (8 Versuche / 5 min) — später erneut versuchen"
            )
        if resp.status_code != 200:
            raise CzdsAuthError(
                f"Authentifizierung fehlgeschlagen (HTTP {resp.status_code}): {resp.text[:200]}"
            )
        token = resp.json().get("accessToken")
        if not token:
            raise CzdsAuthError("Auth-Antwort ohne accessToken")
        self.token_cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.token_cache.with_suffix(".part")
        tmp.write_text(json.dumps({"token": token, "created": time.time()}))
        tmp.chmod(0o600)
        tmp.replace(self.token_cache)
        log.info("Neues CZDS-Token geholt")
        return token

    def _token(self, force_refresh: bool = False) -> str:
        if not force_refresh and self.token_cache.is_file():
            try:
                cached = json.loads(self.token_cache.read_text())
                if time.time() - cached["created"] < TOKEN_MAX_AGE_S:
                    return cached["token"]
            except (json.JSONDecodeError, KeyError):
                pass
        return self._authenticate()

    # -- HTTP ---------------------------------------------------------------

    def _request(
        self, method: str, url: str, *, stream: bool = False, _retry_auth: bool = True
    ) -> requests.Response:
        resp = self.session.request(
            method,
            url,
            headers={
                "Authorization": f"Bearer {self._token()}",
                "User-Agent": self.user_agent,
                "Accept": "*/*",
            },
            stream=stream,
            timeout=300,
        )
        if resp.status_code == 401 and _retry_auth:
            log.info("HTTP 401 — Token abgelaufen, einmalige Re-Authentifizierung")
            self._token(force_refresh=True)
            return self._request(method, url, stream=stream, _retry_auth=False)
        if resp.status_code == 401:
            raise CzdsAuthError(f"401 trotz frischem Token für {url}")
        if resp.status_code == 403:
            raise CzdsAccessError(
                f"Zugriff verweigert (403) für {url} — Grant abgelaufen oder Zone "
                "nicht genehmigt; im CZDS-Portal prüfen/verlängern"
            )
        if resp.status_code == 409:
            raise CzdsTermsError(
                "HTTP 409 — neue CZDS Terms & Conditions müssen im Portal "
                "(czds.icann.org) akzeptiert werden"
            )
        resp.raise_for_status()
        return resp

    # -- API ----------------------------------------------------------------

    def download_links(self) -> list[str]:
        if self._links is None:
            resp = self._request("GET", f"{self.api_base}/czds/downloads/links")
            self._links = resp.json()
            log.info("CZDS: %d genehmigte Zonen-Links", len(self._links))
        return self._links

    def zone_url(self, tld: str) -> str:
        suffix = f"/{tld}.zone"
        for link in self.download_links():
            if link.endswith(suffix):
                return link
        raise CzdsAccessError(
            f"Kein Download-Link für .{tld} — Zone nicht genehmigt? "
            f"Verfügbar: {', '.join(sorted(l.rsplit('/', 1)[-1] for l in self.download_links()))}"
        )

    @staticmethod
    def _head_of(resp: requests.Response) -> ZoneHead:
        length = resp.headers.get("Content-Length")
        return ZoneHead(
            content_length=int(length) if length else None,
            last_modified=resp.headers.get("Last-Modified"),
        )

    def head(self, tld: str) -> ZoneHead:
        return self._head_of(self._request("HEAD", self.zone_url(tld)))

    def download(self, tld: str, dest: Path) -> ZoneHead:
        """Zonefile (gzip) streamend und atomar nach `dest` laden.

        Wirft CzdsError bei Größen-Mismatch — abgeschnittene Downloads sind der
        klassische Fehlermodus und dürfen nie in die Diff-Pipeline gelangen.
        """
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        resp = self._request("GET", self.zone_url(tld), stream=True)
        head = self._head_of(resp)
        written = 0
        with tmp.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=DOWNLOAD_CHUNK):
                f.write(chunk)
                written += len(chunk)
        if head.content_length is not None and written != head.content_length:
            tmp.unlink(missing_ok=True)
            raise CzdsError(
                f".{tld}: Download unvollständig ({written} von {head.content_length} Bytes)"
            )
        tmp.replace(dest)
        log.info(".%s: %d Bytes heruntergeladen (Last-Modified: %s)", tld, written, head.last_modified)
        return head
