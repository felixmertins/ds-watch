import gzip

from ds_watch.extract import extract_ds_state
from ds_watch.store import load_proofs_for, read_state

ZONE = "\n".join([
    "; Kommentarzeile",
    "org.\t900\tin\tsoa\ta0.org.afilias-nst.info. hostmaster.donuts.email. 2026070500 1800 900 604800 86400",
    "org.\t86400\tin\tns\ta0.org.afilias-nst.info.",
    "beta.org.\t86400\tin\tds\t54321 13 2 CDEF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDD",
    # Digest in Presentation-Form mit Whitespace aufgeteilt
    "alpha.org.\t86400\tin\tds\t12345 8 2 AABBCCDD EEFF0011 22334455 66778899 AABBCCDD EEFF0011 22334455 66778899",
    # zweiter DS-RR derselben Delegation
    "alpha.org.\t86400\tin\tds\t12346 8 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
    # Space- statt Tab-getrennt (tolerantes Parsing)
    "gamma.org. 86400 in ds 11111 15 4 " + "ab" * 48,
    # Uppercase-Typ und Trailing-Dot-Handling
    "DELTA.ORG.\t86400\tIN\tDS\t22222 13 2 " + "cd" * 32,
    "alpha.org.\t86400\tin\tns\tns1.example.net.",
    # kaputte Zeilen → malformed
    "broken.org.\t86400\tin\tds\tnotanumber 8 2 aabb",
    "short.org.\t86400\tin\tds\t1 2",
    "nohex.org.\t86400\tin\tds\t1 8 2 zzzz",
    "",
])


def test_extract_normalizes_and_sorts(tmp_path):
    zone = tmp_path / "org.zone.gz"
    with gzip.open(zone, "wt", encoding="ascii") as f:
        f.write(ZONE)
    state = tmp_path / "state.gz"

    res = extract_ds_state(zone, state, "org")

    assert res.soa_serial == "2026070500"
    assert res.ds_rrs == 5
    assert res.ds_domains == 4
    assert res.malformed == 3
    assert res.algorithms == {"8": 2, "13": 2, "15": 1}
    assert res.digest_types == {"2": 4, "4": 1}
    assert len(res.state_sha256) == 64

    entries = list(read_state(state))
    domains = [d for d, _ in entries]
    assert domains == sorted(domains)
    assert domains == ["alpha.org", "alpha.org", "beta.org", "delta.org", "gamma.org"]
    # Whitespace-Digest zusammengefügt und lowercase
    assert entries[0][1] == (12345, 8, 2, "aabbccddeeff00112233445566778899" * 2)


PROOF_ZONE = "\n".join([
    "org.\t900\tin\tsoa\ta0.org.afilias-nst.info. hostmaster.donuts.email. 2026070500 1800 900 604800 86400",
    "org.\t900\tin\tdnskey\t257 3 8 AwEAAaApexKSK",
    "org.\t900\tin\tdnskey\t256 3 8 AwEAAaApexZSK",
    "org.\t900\tin\trrsig\tdnskey 8 1 900 20260719000000 20260705000000 1111 org. ApexSigA ApexSigB",
    "alpha.org.\t86400\tin\tds\t12345 8 2 " + "ab" * 32,
    # Signatur in Presentation-Form aufgeteilt → wird mit Spaces zusammengefügt
    "alpha.org.\t86400\tin\trrsig\tds 8 2 86400 20260719000000 20260705000000 2222 org. SigAlpha1 SigAlpha2",
    "beta.org.\t86400\tin\tds\t54321 13 2 " + "cd" * 32,
    "beta.org.\t86400\tin\trrsig\tds 8 2 86400 20260719000000 20260705000000 2222 org. SigBeta",
    # andere RRSIG-Typen werden ignoriert
    "alpha.org.\t86400\tin\trrsig\tnsec3 8 2 86400 20260719000000 20260705000000 2222 org. Zzz",
    "sub.other.org.\t300\tin\trrsig\ta 8 3 300 20260719000000 20260705000000 2222 other.org. Xx",
    "",
])


def test_extract_proofs_and_dnskey(tmp_path):
    zone = tmp_path / "org.zone.gz"
    with gzip.open(zone, "wt", encoding="ascii") as f:
        f.write(PROOF_ZONE)
    proofs = tmp_path / "proofs.gz"

    res = extract_ds_state(zone, tmp_path / "state.gz", "org", proofs_out=proofs)

    assert res.ds_rrs == 2
    assert res.rrsig_ds == 2
    assert res.dnskey_rrset == ["257 3 8 AwEAAaApexKSK", "256 3 8 AwEAAaApexZSK"]
    assert res.dnskey_rrsigs == ["dnskey 8 1 900 20260719000000 20260705000000 1111 org. ApexSigA ApexSigB"]

    got = load_proofs_for(proofs, {"alpha.org", "beta.org", "gibtsnicht.org"})
    assert got == {
        "alpha.org": ["ds 8 2 86400 20260719000000 20260705000000 2222 org. SigAlpha1 SigAlpha2"],
        "beta.org": ["ds 8 2 86400 20260719000000 20260705000000 2222 org. SigBeta"],
    }
    # ohne proofs_out: keine Proof-Verarbeitung, Rest identisch
    res2 = extract_ds_state(zone, tmp_path / "state2.gz", "org")
    assert res2.rrsig_ds == 0 and res2.ds_rrs == 2


def test_extract_is_deterministic(tmp_path):
    zone = tmp_path / "org.zone.gz"
    with gzip.open(zone, "wt", encoding="ascii") as f:
        f.write(ZONE)
    r1 = extract_ds_state(zone, tmp_path / "a.gz", "org")
    r2 = extract_ds_state(zone, tmp_path / "b.gz", "org")
    assert r1.state_sha256 == r2.state_sha256
