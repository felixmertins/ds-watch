"""Streaming extraction of DS records from CZDS zone files.

CZDS format (Base Registry Agreement Spec 4 §2.1.4): one RR per line,
`<fqdn> <ttl> <class> <type> <rdata>`, lowercase, FQDNs, no $ORIGIN, no
continuation lines. The spec mandates tab as the separator; we split
tolerantly on arbitrary whitespace (special characters embedded in labels
are escaped as \\DDD and therefore never contain whitespace). Owners stay in
presentation form (including escapes) — only lowercased plus trailing-dot
strip, so normalization is lossless and stably comparable across days.

DS RDATA: `key_tag algorithm digest_type digest`; in presentation form the
hex digest may contain whitespace and is joined back together.
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
    algorithms: Counter = field(default_factory=Counter)  # per DS RR
    digest_types: Counter = field(default_factory=Counter)
    rrsig_ds: int = 0  # archived RRSIG(DS) — the registry signatures
    dnskey_rrset: list[str] = field(default_factory=list)  # apex DNSKEYs (RDATA)
    dnskey_rrsigs: list[str] = field(default_factory=list)  # RRSIG(DNSKEY) at the apex


def extract_ds_state(
    zone_gz: Path, state_out: Path, tld: str, proofs_out: Path | None = None
) -> ExtractResult:
    """Stream the zone file, normalize DS RRs, write the sorted state atomically.

    Also collects the evidence along the way (RRSIG evidence v0.2): RRSIG(DS)
    per delegation → proof file (owner-sorted, "owner\\t<rdata>"), plus the
    apex DNSKEY RRset including RRSIG(DNSKEY) for later verification. At
    .org scale the proofs take a few hundred MB of RAM — fine on a
    laptop/VPS, but the reason we never hold any of it twice.
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
        log.warning(".%s: skipped %d unparseable DS lines", tld, res.malformed)
    log.info(
        ".%s: %d lines → %d DS RRs across %d delegations (SOA serial %s)",
        tld, res.zone_lines, res.ds_rrs, res.ds_domains, res.soa_serial,
    )
    return res
