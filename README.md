# ds-watch

DS-Record-Observatory über ICANN-CZDS-Zonefiles — Baustein des
DNSSEC-Transparency-Projekts („CT für DNSSEC"). Beobachtet täglich die
DS-Records ganzer gTLD-Zonen und protokolliert jede Änderung pro Delegation
als append-only Event-Log: `ds_added` (DNSSEC-Bootstrap), `ds_removed`
(Delegation geht insecure — das sicherheitsrelevanteste Signal) und
`ds_changed` (KSK-/Algorithmus-Rollover oder stiller Schlüsseltausch).

## Funktionsweise

Täglicher Lauf pro TLD: **fetch** (CZDS-Download, nur wenn die Zone sich laut
`Last-Modified` geändert hat) → **extract** (Streaming über das gzip, DS-RRs
normalisieren, sortierter Snapshot) → **diff** (Merge-Diff gegen den Vortag,
RRset-Vergleich pro Delegation) → **publish** (Event-JSONL + Tages-Aggregat
mit SHA-256-Kette zum Vortag, Git-Commit) → **rotate**.

Ein Sanity-Gate quarantänisiert Läufe mit verdächtigem DS-Einbruch
(klassischer Fehlermodus: abgeschnittener Download), statt Massen-
`ds_removed`-Events zu erzeugen.

## RRSIG-Evidenz (v0.2)

Jedes Event trägt registry-signierte Beweise statt bloßer Behauptungen: Die
`RRSIG(DS)`-Records, mit denen die Elternzone ihr DS-RRset signiert, werden
pro Delegation mitarchiviert (`rrsig_before`/`rrsig_after` im Event), dazu
täglich das Apex-DNSKEY-RRset samt `RRSIG(DNSKEY)` für die Langzeit-
Verifikation (`events/<tld>/dnskey/<datum>.json`). Die Verifikationskette
läuft bis zum Root-Trust-Anchor — prüfbar z. B. mit dnspython oder `delv`.

Grenzen (bewusst): Die RRSIG beweist Existenz im Gültigkeitsfenster, die
Tagesgenauigkeit bleibt Beobachtung; für `ds_removed` gibt es (noch) keinen
Abwesenheits-Beweis — NSEC3-Denial-Proofs mit Opt-out sind Future Work.
Events aus v0.1-States (Baselines) haben noch kein `rrsig_before`.

## Alerting (v0.2)

`[alert]` in der config.toml: E-Mail bei Watchlist-Treffern und — sofern
`on_attention = true` — bei Quarantäne, Grant-Ablauf (403) und neuen ToU
(409). Versand per SMTP (Default localhost:25; auf dem VPS reicht ein
lokaler MTA oder msmtp). `to` leer lassen = aus. Versandfehler brechen den
Lauf nie ab, die Log-Warnung bleibt maßgeblich.

## CZDS-Nutzungsbedingungen (wichtig)

Dieses Tool ist so gebaut, dass es die CZDS Terms of Use (v1.00) einhält:

- **§1.8**: höchstens ein Download pro Zone pro 24 h — erzwungen per
  `Last-Modified`-Vergleich und Mindestabstand (`min_fetch_interval_hours`).
- **§1.4**: Roh-Zonefiles werden direkt nach der Extraktion gelöscht.
- **§1.6**: Es werden ausschließlich abgeleitete Diffs und Aggregate
  abgelegt/committet („value-added"), nie volle Snapshots oder Roh-Zonendaten.
  Die Voll-Snapshots unter `state/` sind gitignored und bleiben lokal.

### Hinweis für Nachnutzer der Daten (ToU §1.6 → §1.1)

Die Aggregate und das Event-Log in diesem Repository sind aus
ICANN-CZDS-Zonefiles abgeleitete Daten. Ihre Nutzung entgegen CZDS ToU §1.1
ist untersagt. Insbesondere dürfen sie nur für rechtmäßige Zwecke verwendet
werden und unter keinen Umständen dazu, (a) die Versendung unaufgeforderter
Massenwerbung (per E-Mail, Telefon oder Fax) zu ermöglichen oder zu
unterstützen oder (b) hochvolumige, automatisierte Abfragen an Systeme von
Registries oder ICANN-akkreditierten Registraren zu richten, außer soweit
zur Registrierung oder Verwaltung von Domainnamen erforderlich. Bei
Weitergabe der Daten ist diese Auflage weiterzureichen.

HTTP 403 (Grant abgelaufen — Grants laufen nach ≥3 Monaten aus!) und
HTTP 409 (neue ToU im Portal zu akzeptieren) beenden den Lauf mit
Exit-Code 2 und brauchen manuelle Aktion auf <https://czds.icann.org>.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
cp config.example.toml config.toml   # TLDs/Watchlist anpassen

# CZDS-Zugangsdaten (Portal-Login) hinterlegen:
mkdir -p ~/.config/ds-watch
cat > ~/.config/ds-watch/credentials <<'EOF'
username = "deine-czds-mailadresse"
password = "dein-czds-passwort"
EOF
chmod 600 ~/.config/ds-watch/credentials
```

## Nutzung

```sh
.venv/bin/ds-watch run                 # voller Tageslauf über alle TLDs aus config.toml
.venv/bin/ds-watch run --tld dev       # nur eine Zone
.venv/bin/ds-watch fetch --tld dev     # nur herunterladen
.venv/bin/ds-watch extract --tld dev   # DS-State aus geladener Zone bauen (Debug)
.venv/bin/ds-watch diff --tld dev      # Dry-Run-Diff auf stdout, ohne zu publizieren
.venv/bin/ds-watch status              # Stand pro TLD
```

Exit-Codes: `0` OK · `1` Fehler · `2` braucht Aufmerksamkeit
(Quarantäne, Grant abgelaufen, neue ToU).

### Täglicher Betrieb (systemd user timer)

```sh
mkdir -p ~/.config/systemd/user
cp contrib/ds-watch.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now ds-watch.timer
systemctl --user list-timers ds-watch.timer   # Kontrolle
```

Der Timer feuert 06:30 UTC (nach dem CZDS-Regenerationsfenster 00:00–06:00 UTC)
mit `Persistent=true` — verpasste Läufe werden nachgeholt, der Guard im Client
verhindert Doppel-Downloads.

### Signierte Commits

`git.sign = "auto"` signiert, sobald ein Signing-Key konfiguriert ist,
z. B. SSH-Signing:

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
```

## Datenlayout

```
events/<tld>/<jahr>/<datum>.jsonl   # ein Event pro geänderter Delegation (nur an Tagen mit Änderungen)
events/<tld>/dnskey/<datum>.json    # Tages-DNSKEY-Paket der Elternzone (für RRSIG-Verifikation)
stats/<tld>/<datum>.json            # Tages-Aggregat, per SHA-256 mit dem Vortag verkettet
state/                              # lokal (gitignored): Snapshot + RRSIG-Proofs, Quarantäne, Token-Cache
```

Event-Beispiel:

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

E-Mail-Alerting für die
Watchlist, echtes Merkle-Log (Sigsum)
## Lizenz

Apache-2.0
