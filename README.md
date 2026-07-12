# ds-watch

A DS record observatory built on ICANN CZDS zone files — a building block of
the DNSSEC transparency project ("CT for DNSSEC"). It watches the DS records
of entire gTLD zones daily and records every change per delegation in an
append-only event log: `ds_added` (DNSSEC bootstrap), `ds_removed`
(delegation goes insecure — the most security-relevant signal), and
`ds_changed` (KSK/algorithm rollover, or a silent key substitution).

## How it works

Daily run per TLD: **fetch** (CZDS download, only if the zone has changed
according to `Last-Modified`) → **extract** (streams the gzip, normalizes
DS RRs, sorted snapshot) → **diff** (merge diff against the previous day,
RRset comparison per delegation) → **publish** (event JSONL + daily
aggregate with a SHA-256 chain to the previous day, git commit) → **rotate**.

A sanity gate quarantines runs with a suspicious drop in DS count (the
classic failure mode: a truncated download) instead of emitting a flood of
`ds_removed` events.

## RRSIG evidence (v0.2)

Every event carries registry-signed evidence instead of bare claims: the
`RRSIG(DS)` records that the parent zone uses to sign its DS RRset are
archived per delegation (`rrsig_before`/`rrsig_after` on the event), plus a
daily snapshot of the apex DNSKEY RRset including `RRSIG(DNSKEY)` for
long-term verification (`events/<tld>/dnskey/<date>.json`). The verification
chain runs all the way to the root trust anchor and can be verified with
e.g. dnspython or `delv`.

Limitations (by design): an RRSIG proves existence within its validity
window; the day-level timing is an observation, not a proof. There is no
proof of absence for `ds_removed` (yet) — NSEC3 denial proofs with opt-out
are future work. Events derived from v0.1 states (baselines) do not have
`rrsig_before` yet.

## Alerting (v0.2)

`[alert]` in config.toml: email on watchlist hits and — if
`on_attention = true` — on quarantine, expired grants (403), and new terms
of use (409). Delivery via SMTP: by default localhost:25 (a local MTA or
msmtp is enough), or an authenticated submission account at any mail
provider — set `smtp_host`/`smtp_port`, `tls` (`"starttls"` for port 587,
`"ssl"` for port 465), and point `credentials_file` at a TOML file with
`smtp_user`/`smtp_password` (chmod 600). With an external account, delivery
does not depend on this host's DNS or IP reputation. Leave `to` empty to
disable. Delivery failures never abort a run; the log warning remains
authoritative.

## CZDS Terms of Use (important)

This tool is built to comply with the CZDS Terms of Use (v1.00):

- **§1.8**: at most one download per zone per 24 h — enforced via
  `Last-Modified` comparison and a minimum interval
  (`min_fetch_interval_hours`).
- **§1.4**: raw zone files are deleted immediately after extraction.
- **§1.6**: only derived diffs and aggregates are stored/committed
  ("value-added"), never full snapshots or raw zone data. The full
  snapshots under `state/` are gitignored and stay local.

### Notice for downstream users of the data (ToU §1.6 → §1.1)

The aggregates and the event log in this repository are data derived from
ICANN CZDS zone files. Using them contrary to CZDS ToU §1.1 is prohibited.
In particular, they may only be used for lawful purposes and under no
circumstances to (a) enable or support the transmission of unsolicited bulk
advertising (via email, telephone, or fax) or (b) send high-volume,
automated queries to the systems of registries or ICANN-accredited
registrars, except as reasonably necessary to register or manage domain
names. If you pass the data on, you must pass this obligation on as well.

HTTP 403 (grant expired — grants expire after ≥3 months!) and HTTP 409 (new
terms of use to accept in the portal) end the run with exit code 2 and
require manual action at <https://czds.icann.org>.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
cp config.example.toml config.toml   # adjust TLDs/watchlist

# Store CZDS credentials (portal login):
mkdir -p ~/.config/ds-watch
cat > ~/.config/ds-watch/credentials <<'EOF'
username = "your-czds-email"
password = "your-czds-password"
EOF
chmod 600 ~/.config/ds-watch/credentials
```

## Usage

```sh
.venv/bin/ds-watch run                 # full daily run over all TLDs from config.toml
.venv/bin/ds-watch run --tld dev       # a single zone only
.venv/bin/ds-watch fetch --tld dev     # download only
.venv/bin/ds-watch extract --tld dev   # build the DS state from a downloaded zone (debugging)
.venv/bin/ds-watch diff --tld dev      # dry-run diff to stdout, without publishing
.venv/bin/ds-watch status              # per-TLD status
```

Exit codes: `0` OK · `1` error · `2` needs attention
(quarantine, grant expired, new terms of use).

### Daily operation (systemd user timer)

```sh
mkdir -p ~/.config/systemd/user
cp contrib/ds-watch.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now ds-watch.timer
systemctl --user list-timers ds-watch.timer   # check
```

The timer fires at 06:30 UTC (after the CZDS regeneration window
00:00–06:00 UTC) with `Persistent=true` — missed runs are caught up, and the
guard in the client prevents duplicate downloads.

### Signed commits

`git.sign = "auto"` signs as soon as a signing key is configured, e.g. SSH
signing:

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
```

## Data layout

```
events/<tld>/<year>/<date>.jsonl    # one event per changed delegation (only on days with changes)
events/<tld>/dnskey/<date>.json     # daily DNSKEY bundle of the parent zone (for RRSIG verification)
stats/<tld>/<date>.json             # daily aggregate, chained to the previous day via SHA-256
state/                              # local (gitignored): snapshot + RRSIG proofs, quarantine, token cache
```

Example event:

```json
{"v":1,"date":"2026-07-05","tld":"org","domain":"example.org","event":"ds_changed",
 "before":[{"key_tag":12345,"algorithm":8,"digest_type":2,"digest":"ab…"}],
 "after":[{"key_tag":54321,"algorithm":13,"digest_type":2,"digest":"cd…"}],
 "rrsig_before":["ds 8 2 86400 20260712… 20260628… 4217 org. K7c…"],
 "rrsig_after":["ds 8 2 86400 20260719… 20260705… 4217 org. Kkm…"],
 "gap_days":1,"source":"czds","run_id":"2026-07-05T06:31Z"}
```

## Tests

```sh
.venv/bin/python -m pytest
```

## Status / Roadmap

v0.2, in production: daily runs over the `dev`, `info`, and `org` zones;
aggregates and charts are published at
<https://ds-watch.felixmertins.dev>. Next up: public watchlist self-service
("watch my domain"), a real Merkle tree log (Sigsum), NSEC3 denial proofs
for `ds_removed`.

## License

Felix Mertins Open Software License (FMOS) v1.0 — see [LICENSE](LICENSE).
A visible, current [Contributors.md](Contributors.md) ships with every
distribution (LICENSE §2.2).
