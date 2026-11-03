#!/usr/bin/env python3
# Tokens no real authority would make, for the checks real tokens can never exercise. A throwaway CA, used once: the files in fixtures/tsa are what the tests read.
#   python3 test/make-tsa-fixtures.py     (needs the `cryptography` package; nothing else does)
import datetime as dt, hashlib, json, os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = os.path.join(os.path.dirname(__file__), "fixtures/tsa")
TOKEN_TIME = dt.datetime(2026, 11, 3, 12, 0, 0, tzinfo=dt.timezone.utc)
DATA = b"log.333.eco/origin\n1\nforged fixtures\n"

def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def cert(cn, key, issuer_name, issuer_key, ca, eku=True, not_after=dt.datetime(2036, 1, 1, tzinfo=dt.timezone.utc)):
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)).not_valid_after(not_after)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if eku and not ca: b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    return b.sign(issuer_key, hashes.SHA256())
der = lambda c: c.public_bytes(serialization.Encoding.DER)

def enc(tag, *parts):
    v = b"".join(parts); n = len(v)
    l = bytes([n]) if n < 128 else (bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 255]))
    return bytes([tag]) + l + v
seq = lambda *p: enc(0x30, *p)
SET = lambda *p: enc(0x31, *sorted(p))
octet = lambda b: enc(0x04, b)
integer = lambda n: enc(0x02, n.to_bytes((n.bit_length() + 8) // 8 or 1, "big"))
def oid(s):
    a = [int(x) for x in s.split(".")]; out = bytes([a[0] * 40 + a[1]])
    for v in a[2:]:
        chunk = [v & 0x7f]; v >>= 7
        while v: chunk.insert(0, 0x80 | (v & 0x7f)); v >>= 7
        out += bytes(chunk)
    return enc(0x06, out)
SHA256 = seq(oid("2.16.840.1.101.3.4.2.1"), enc(0x05))
def token(data, leaf, leaf_key, chain):
    gen = TOKEN_TIME.strftime("%Y%m%d%H%M%SZ").encode()
    tst = seq(integer(1), oid("1.2.3.4"), seq(SHA256, octet(hashlib.sha256(data).digest())), integer(7), enc(0x18, gen))
    attrs = [seq(oid("1.2.840.113549.1.9.3"), SET(oid("1.2.840.113549.1.9.16.1.4"))), seq(oid("1.2.840.113549.1.9.4"), SET(octet(hashlib.sha256(tst).digest())))]
    as_set = SET(*attrs)
    sig = leaf_key.sign(as_set, ec.ECDSA(hashes.SHA256()))
    issuer_and_serial = seq(leaf.issuer.public_bytes(), integer(leaf.serial_number))
    si = seq(integer(1), issuer_and_serial, SHA256, enc(0xa0, as_set[2 if len(as_set) < 130 else 3:]), seq(oid("1.2.840.10045.4.3.2")), octet(sig))
    signed = seq(integer(3), SET(SHA256), seq(oid("1.2.840.113549.1.9.16.1.4"), enc(0xa0, octet(tst))), enc(0xa0, *[der(c) for c in chain]), SET(si))
    return seq(seq(integer(0)), seq(oid("1.2.840.113549.1.7.2"), enc(0xa0, signed)))

k = lambda: ec.generate_private_key(ec.SECP256R1())
root_key, ica_key, nonca_key, leaf_key = k(), k(), k(), k()
root = cert("Test Root", root_key, name("Test Root"), root_key, True)
ica = cert("Test Intermediate", ica_key, root.subject, root_key, True)
nonca = cert("Not a CA", nonca_key, root.subject, root_key, False)
good = cert("Test TSA", leaf_key, ica.subject, ica_key, False)
noeku = cert("Test No EKU", leaf_key, ica.subject, ica_key, False, eku=False)
expired = cert("Test Expired", leaf_key, ica.subject, ica_key, False, not_after=dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc))
under_nonca = cert("Test Under Not A CA", leaf_key, nonca.subject, nonca_key, False)
os.makedirs(OUT, exist_ok=True)
open(f"{OUT}/root.der", "wb").write(der(root))
open(f"{OUT}/data.txt", "wb").write(DATA)
for fn, tok in {
    "good": token(DATA, good, leaf_key, [good, ica]),
    "no-eku": token(DATA, noeku, leaf_key, [noeku, ica]),
    "expired-leaf": token(DATA, expired, leaf_key, [expired, ica]),
    "under-non-ca": token(DATA, under_nonca, leaf_key, [under_nonca, nonca]),
}.items(): open(f"{OUT}/{fn}.tsr", "wb").write(tok)
print("wrote", sorted(os.listdir(OUT)))
