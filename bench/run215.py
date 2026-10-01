#!/usr/bin/env python3
"""The AArch64 README tables: crypton 1.1.5, crypton 2.1.5 and OpenSSL, all
three alternated inside every repetition so that none of them gets the
quieter moment or the cooler machine, best of K for each cell.

    ./run215.py <bulk-115> <pk-115> <bulk-215> <pk-215> <openssl> [K]
"""
import subprocess, sys, re, os

BULK = [
    ("AES-128-GCM",       "aes128gcm",  "aes-128-gcm"),
    ("AES-256-GCM",       "aes256gcm",  "aes-256-gcm"),
    ("ChaCha20-Poly1305", "chachapoly", "chacha20-poly1305"),
    ("SHA-1",             "sha1",       "sha1"),
    ("SHA-256",           "sha256",     "sha256"),
    ("SHA-512",           "sha512",     "sha512"),
    ("SHA3-256",          "sha3-256",   "sha3-256"),
]

PK = [
    ("X25519",                  "x25519",            ("ecdhx25519", r"ecdh \(X25519\)", 1)),
    ("ECDH P-256",              "ecdh-p256",         ("ecdhp256",   r"ecdh \((prime256v1|nistp256)\)", 1)),
    ("ECDH P-384",              "ecdh-p384",         ("ecdhp384",   r"ecdh \((secp384r1|nistp384)\)", 1)),
    ("Ed25519 sign",            "ed25519-sign",      ("eddsa",      r"(EC|EdDSA) \(Ed25519\)", 2)),
    ("Ed25519 verify",          "ed25519-verify",    ("eddsa",      r"(EC|EdDSA) \(Ed25519\)", 1)),
    ("ECDSA P-256 sign",        "ecdsa-p256-sign",   ("ecdsap256",  r"(EC \(prime256v1\)|ecdsa \(nistp256\))", 2)),
    ("ECDSA P-256 verify",      "ecdsa-p256-verify", ("ecdsap256",  r"(EC \(prime256v1\)|ecdsa \(nistp256\))", 1)),
    ("ECDSA P-384 sign",        "ecdsa-p384-sign",   ("ecdsap384",  r"(EC \(secp384r1\)|ecdsa \(nistp384\))", 2)),
    ("ECDSA P-384 verify",      "ecdsa-p384-verify", ("ecdsap384",  r"(EC \(secp384r1\)|ecdsa \(nistp384\))", 1)),
    ("RSA-2048 sign/decrypt",   "rsa-sign",          ("rsa2048",    r"rsa2048.*s +[0-9.]+ +[0-9.]+ +[0-9.]+$", 2)),
    ("RSA-2048 verify/encrypt", "rsa-verify",        ("rsa2048",    r"rsa2048.*s +[0-9.]+ +[0-9.]+ +[0-9.]+$", 1)),
]

bulk1, pk1, bulk5, pk5, ossl = sys.argv[1:6]
K = int(sys.argv[6]) if len(sys.argv) > 6 else 5

prefix = ""
if ossl.endswith("apps/openssl"):
    libs = os.path.dirname(os.path.dirname(ossl))
    prefix = f"DYLD_LIBRARY_PATH={libs} LD_LIBRARY_PATH={libs} "

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

def ossl_bulk(name):
    out = sh(f"{prefix}{ossl} speed -elapsed -evp {name} -bytes 16384 -seconds 2 2>/dev/null")
    for line in out.splitlines():
        if re.match(r"^[A-Za-z0-9()-]+ +[0-9].*k$", line.rstrip()):
            return float(line.split()[-1].rstrip("k")) / 1000.0
    return None

def ossl_pk(sub, rx, field):
    out = sh(f"{prefix}{ossl} speed -seconds 2 {sub} 2>/dev/null")
    hit = None
    for line in out.splitlines():
        if re.search(rx, line):
            hit = line
    if hit is None:
        return None
    ops = float(hit.split()[-field])
    return 1e6 / ops if ops else None

def ours(binary, name):
    v = sh(f"{binary} {name}").strip()
    try:
        return float(v)
    except ValueError:
        return None

def race(fs, higher):
    """One repetition runs every column before any column runs twice."""
    out = [[] for _ in fs]
    for _ in range(K):
        for i, f in enumerate(fs):
            v = f()
            if v:
                out[i].append(v)
    pick = max if higher else min
    return [pick(c) if c else None for c in out]

def cell(v, fmt):
    return "-" if v is None else format(v, fmt)

print("### AArch64\n")
print("Throughput over 16 KiB in MB/s, **higher is better**:\n")
print("| | crypton 1.1.5 | crypton 2.1.5 | OpenSSL | 2.1.5 / OpenSSL |")
print("| --- | ---: | ---: | ---: | ---: |")
for label, name, oname in BULK:
    a, b, c = race([lambda: ours(bulk1, name),
                    lambda: ours(bulk5, name),
                    lambda: ossl_bulk(oname)], True)
    r = f"{b/c:.2f}" if b and c else "-"
    print(f"| {label} | {cell(a,'.0f')} | {cell(b,'.0f')} | {cell(c,'.0f')} | {r} |")
    sys.stdout.flush()

print("\nTime per operation in microseconds, **lower is better**:\n")
print("| | crypton 1.1.5 | crypton 2.1.5 | OpenSSL | OpenSSL / 2.1.5 |")
print("| --- | ---: | ---: | ---: | ---: |")
for label, name, (sub, rx, field) in PK:
    a, b, c = race([lambda: ours(pk1, name),
                    lambda: ours(pk5, name),
                    lambda: ossl_pk(sub, rx, field)], False)
    r = f"{c/b:.2f}" if b and c else "-"
    print(f"| {label} | {cell(a,'.4g')} | {cell(b,'.4g')} | {cell(c,'.4g')} | {r} |")
    sys.stdout.flush()
