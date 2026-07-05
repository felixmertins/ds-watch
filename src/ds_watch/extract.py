"""Streaming-Extraktion von DS-Records aus CZDS-Zonefiles.

CZDS-Format (Base Registry Agreement Spec 4 §2.1.4): eine RR pro Zeile,
`<fqdn> <ttl> <class> <type> <rdata>`, lowercase, FQDNs, kein $ORIGIN, keine
Fortsetzungszeilen. Trenner laut Spec ein Tab; wir splitten tolerant auf
beliebigen Whitespace (eingebettete Sonderzeichen in Labels sind als \\DDD
escaped und enthalten daher nie Whitespace). Owner bleiben in Presentation-
Form (inkl. Escapes) — nur lowercase + Trailing-Dot-Strip, damit die
Normalisierung verlustfrei und über Tage stabil vergleichbar ist.

DS-RDATA: `key_tag algorithm digest_type digest`; der Hex-Digest darf in
Presentation-Form Whitespace enthalten und wird zusammengefügt.
"""

from __future__ import annotations

import gzip
import hashlib
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_HEX = set("0123456789abcdef")


@dataclass
class ExtractResult:
    zone_lines: int = 0
    ds_rrs: int = 0
    ds_domains: int = 0
    malformed: int = 0
    soa_serial: str | None = None
    state_sha256: str = ""
    algorithms: Counter = field(default_factory=Counter)  # pro DS-RR
    digest_types: Counter = field(default_factory=Counter)
    rrsig_ds: int = 0  # archivierte RRSIG(DS) — die Registry-Signaturen
    dnskey_rrset: list[str] = field(default_factory=list)  # Apex-DNSKEYs (RDATA)
    dnskey_rrsigs: list[str] = field(default_factory=list)  # RRSIG(DNSKEY) am Apex


def extract_ds_state(
    zone_gz: Path, state_out: Path, tld: str, proofs_out: Path | None = None
) -> ExtractResult:
    """Zonefile streamen, DS-RRs normalisieren, sortierten State atomar schreiben.

    Nimmt zusätzlich die Evidenz mit (RRSIG-Evidenz v0.2): RRSIG(DS) pro
    Delegation → Proof-Datei (owner-sortiert, "owner\\t<rdata>"), plus das
    Apex-DNSKEY-RRset samt RRSIG(DNSKEY) für die spätere Verifikation. Die
    Proofs liegen für .org-Größenordnung einige 100 MB im RAM — auf
    Laptop/VPS unkritisch, aber der Grund, warum wir nichts davon doppelt halten.
    """
    res = ExtractResult()
    records: list[tuple[str, int, int, int, str]] = []
    proofs: list[tuple[str, str]] = []

    with gzip.open(zone_gz, "rt", encoding="ascii", errors="surrogateescape") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith(";"):
                continue
            res.zone_lines += 1
            fields = line.split()
            if len(fields) < 5:
                continue
            rtype = fields[3].lower()
            owner = fields[0].lower().rstrip(".")
            if rtype == "soa" and res.soa_serial is None:
                if owner == tld and len(fields) >= 7:
                    res.soa_serial = fields[6]
                continue
            if rtype == "dnskey" and owner == tld:
                res.dnskey_rrset.append(" ".join(fields[4:]))
                continue
            if rtype == "rrsig" and len(fields) >= 13:
                covered = fields[4].lower()
                if covered == "ds" and proofs_out is not None:
                    proofs.append((owner, " ".join(fields[4:])))
                elif covered == "dnskey" and owner == tld:
                    res.dnskey_rrsigs.append(" ".join(fields[4:]))
                continue
            if rtype != "ds":
                continue
            if len(fields) < 8:
                res.malformed += 1
                continue
            digest = "".join(fields[7:]).lower()
            try:
                key_tag = int(fields[4])
                algorithm = int(fields[5])
                digest_type = int(fields[6])
            except ValueError:
                res.malformed += 1
                continue
            if not digest or not set(digest) <= _HEX:
                res.malformed += 1
                continue
            records.append((owner, key_tag, algorithm, digest_type, digest))

    records.sort()
    res.ds_rrs = len(records)
    res.ds_domains = len({r[0] for r in records})

    sha = hashlib.sha256()
    state_out.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_out.with_suffix(".part")
    with gzip.open(tmp, "wt", encoding="ascii") as out:
        for owner, key_tag, algorithm, digest_type, digest in records:
            res.algorithms[str(algorithm)] += 1
            res.digest_types[str(digest_type)] += 1
            line = f"{owner}\t{key_tag}\t{algorithm}\t{digest_type}\t{digest}\n"
            sha.update(line.encode("ascii"))
            out.write(line)
    tmp.replace(state_out)
    res.state_sha256 = sha.hexdigest()

    if proofs_out is not None:
        proofs.sort()
        res.rrsig_ds = len(proofs)
        ptmp = proofs_out.with_suffix(".part")
        with gzip.open(ptmp, "wt", encoding="ascii") as out:
            for owner, rdata in proofs:
                out.write(f"{owner}\t{rdata}\n")
        ptmp.replace(proofs_out)

    if res.malformed:
        log.warning(".%s: %d nicht parsebare DS-Zeilen übersprungen", tld, res.malformed)
    log.info(
        ".%s: %d Zeilen → %d DS-RRs auf %d Delegationen (SOA-Serial %s)",
        tld, res.zone_lines, res.ds_rrs, res.ds_domains, res.soa_serial,
    )
    return res
