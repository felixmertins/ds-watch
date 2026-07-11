"""ICANN CZDS API client: auth (JWT, valid 24 h), zone listing, HEAD, download.

API constraints (ICANN CZDS API Spec 2022-05-24, ToU v1.00):
- User-Agent header is mandatory, otherwise redirect to a maintenance page
- Auth rate limit: 8 attempts / 5 min / IP → token is cached for 23 h
- 401 = token expired (single re-auth), 403 = grant missing/expired,
  409 = new Terms & Conditions must be accepted in the CZDS portal
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

import requests

log = logging.getLogger(__name__)

TOKEN_MAX_AGE_S = 23 * 3600  # JWT is valid for 24 h; 1 h safety margin
DOWNLOAD_CHUNK = 1 << 20


class CzdsError(Exception):
    pass


class CzdsAuthError(CzdsError):
    pass


class CzdsAccessError(CzdsError):
    """HTTP 403: zone not approved or grant expired — check the portal."""


class CzdsTermsError(CzdsError):
    """HTTP 409: new Terms & Conditions must be accepted in the CZDS portal."""


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
                "Auth rate limit reached (8 attempts / 5 min) — retry later"
            )
        if resp.status_code != 200:
            raise CzdsAuthError(
                f"Authentication failed (HTTP {resp.status_code}): {resp.text[:200]}"
            )
        token = resp.json().get("accessToken")
        if not token:
            raise CzdsAuthError("Auth response missing accessToken")
        self.token_cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.token_cache.with_suffix(".part")
        tmp.write_text(json.dumps({"token": token, "created": time.time()}))
        tmp.chmod(0o600)
        tmp.replace(self.token_cache)
        log.info("Fetched new CZDS token")
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
            log.info("HTTP 401 — token expired, re-authenticating once")
            self._token(force_refresh=True)
            return self._request(method, url, stream=stream, _retry_auth=False)
        if resp.status_code == 401:
            raise CzdsAuthError(f"401 despite fresh token for {url}")
        if resp.status_code == 403:
            raise CzdsAccessError(
                f"Access denied (403) for {url} — grant expired or zone "
                "not approved; check/renew in the CZDS portal"
            )
        if resp.status_code == 409:
            raise CzdsTermsError(
                "HTTP 409 — new CZDS Terms & Conditions must be accepted in the "
                "portal (czds.icann.org)"
            )
        resp.raise_for_status()
        return resp

    # -- API ----------------------------------------------------------------

    def download_links(self) -> list[str]:
        if self._links is None:
            resp = self._request("GET", f"{self.api_base}/czds/downloads/links")
            self._links = resp.json()
            log.info("CZDS: %d approved zone links", len(self._links))
        return self._links

    def zone_url(self, tld: str) -> str:
        suffix = f"/{tld}.zone"
        for link in self.download_links():
            if link.endswith(suffix):
                return link
        raise CzdsAccessError(
            f"No download link for .{tld} — zone not approved? "
            f"Available: {', '.join(sorted(l.rsplit('/', 1)[-1] for l in self.download_links()))}"
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
        """Stream the zone file (gzip) to `dest`, written atomically.

        Raises CzdsError on a size mismatch — truncated downloads are the
        classic failure mode and must never reach the diff pipeline.
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
                f".{tld}: incomplete download ({written} of {head.content_length} bytes)"
            )
        tmp.replace(dest)
        log.info(".%s: downloaded %d bytes (Last-Modified: %s)", tld, written, head.last_modified)
        return head
