"""State-Ablage: DS-Snapshots (sortiert, gzip) + Metadaten pro TLD.

Layout unter state_dir/ (gitignored, enthält CZDS-abgeleitete Voll-Snapshots):
  <tld>/current.state.gz    kanonisch: "domain\\tkey_tag\\talg\\tdigest_type\\tdigest\\n", sortiert
  <tld>/current.meta.json   Download-/Extraktions-Metadaten des Snapshots
  <tld>/quarantine/         Snapshots, die das Sanity-Gate nicht passiert haben
  work/<tld>.zone.gz        Roh-Zone, wird nach Extraktion gelöscht (ToU §1.4)
"""

from __future__ import annotations

import gzip
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator

# Ein DS-RR in State-Reihenfolge: (key_tag, algorithm, digest_type, digest)
Rdata = tuple[int, int, int, str]


@dataclass
class StateMeta:
    tld: str
    date: str  # ISO-Datum des Laufs (UTC)
    downloaded_at: str  # ISO-Zeitstempel (UTC)
    last_modified: str | None  # HTTP-Header der Zonendatei
    soa_serial: str | None
    zone_lines: int
    ds_rrs: int
    ds_domains: int
    malformed: int
    state_sha256: str  # über den unkomprimierten State-Inhalt
    rrsig_ds: int = 0  # Anzahl archivierter RRSIG(DS) (0 bei Alt-States aus v0.1)

    def save(self, path: Path) -> None:
        tmp = path.with_suffix(".part")
        tmp.write_text(json.dumps(asdict(self), indent=2) + "\n")
        tmp.replace(path)

    @classmethod
    def load(cls, path: Path) -> "StateMeta":
        return cls(**json.loads(path.read_text()))


@dataclass
class TldPaths:
    dir: Path
    current_state: Path
    current_meta: Path
    current_proofs: Path
    new_state: Path
    new_meta: Path
    new_proofs: Path
    quarantine_dir: Path
    work_zone: Path

    def has_current(self) -> bool:
        return self.current_state.is_file() and self.current_meta.is_file()

    def rotate(self) -> None:
        """new → current (atomar genug für unseren Ein-Prozess-Betrieb)."""
        self.new_state.replace(self.current_state)
        self.new_meta.replace(self.current_meta)
        if self.new_proofs.exists():
            self.new_proofs.replace(self.current_proofs)

    def quarantine(self, date: str) -> Path:
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        dest = self.quarantine_dir / f"{date}.state.gz"
        self.new_state.replace(dest)
        self.new_meta.replace(self.quarantine_dir / f"{date}.meta.json")
        if self.new_proofs.exists():
            self.new_proofs.replace(self.quarantine_dir / f"{date}.proofs.gz")
        return dest


def tld_paths(state_dir: Path, tld: str) -> TldPaths:
    d = state_dir / tld
    d.mkdir(parents=True, exist_ok=True)
    (state_dir / "work").mkdir(parents=True, exist_ok=True)
    return TldPaths(
        dir=d,
        current_state=d / "current.state.gz",
        current_meta=d / "current.meta.json",
        current_proofs=d / "current.proofs.gz",
        new_state=d / "new.state.gz",
        new_meta=d / "new.meta.json",
        new_proofs=d / "new.proofs.gz",
        quarantine_dir=d / "quarantine",
        work_zone=state_dir / "work" / f"{tld}.zone.gz",
    )


def read_state(path: Path) -> Iterator[tuple[str, Rdata]]:
    """State-Datei zeilenweise als (domain, rdata) — Datei ist domain-sortiert."""
    with gzip.open(path, "rt", encoding="ascii") as f:
        for line in f:
            domain, key_tag, alg, digest_type, digest = line.rstrip("\n").split("\t")
            yield domain, (int(key_tag), int(alg), int(digest_type), digest)


def load_proofs_for(path: Path, domains: set[str]) -> dict[str, list[str]]:
    """RRSIG(DS)-Zeilen für die gegebenen Delegationen aus einer Proof-Datei holen.

    Ein Scan über die Datei (Format: "owner\\t<rrsig-rdata>", owner-sortiert) —
    nur für die wenigen Event-Domains eines Tages, nie in den RAM als Ganzes.
    """
    if not domains or not path.is_file():
        return {}
    found: dict[str, list[str]] = {}
    with gzip.open(path, "rt", encoding="ascii") as f:
        for line in f:
            owner, rdata = line.rstrip("\n").split("\t", 1)
            if owner in domains:
                found.setdefault(owner, []).append(rdata)
    return found
