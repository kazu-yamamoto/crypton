#!/usr/bin/env python3
"""One of the README's performance tables: every column from one run on one
machine, crypton and OpenSSL alternated so neither gets the quieter moment,
best of K for every cell.

Expects $BENCH_BIN to hold bulk-<version> and pk-bin-<version> for each
version in VERS.

    table.py <openssl-apps-binary> [K]
"""
import os, re, subprocess, sys

SP = os.environ.get("BENCH_BIN", "/tmp/bench")
VERS = ["1.1.5", "2.1.4"]

BULK = [("AES-128-GCM", "aes128gcm", "aes-128-gcm"),
        ("AES-256-GCM", "aes256gcm", "aes-256-gcm"),
        ("ChaCha20-Poly1305", "chachapoly", "chacha20-poly1305"),
        ("SHA-1", "sha1", "sha1"),
        ("SHA-256", "sha256", "sha256"),
        ("SHA-512", "sha512", "sha512"),
        ("SHA3-256", "sha3-256", "sha3-256")]

PK = [("X25519", "x25519", ("ecdhx25519", r"ecdh \(X25519\)", 1)),
      ("ECDH P-256", "ecdh-p256", ("ecdhp256", r"ecdh \((prime256v1|nistp256)\)", 1)),
      ("ECDH P-384", "ecdh-p384", ("ecdhp384", r"ecdh \((secp384r1|nistp384)\)", 1)),
      ("Ed25519 sign", "ed25519-sign", ("eddsa", r"(EC|EdDSA) \(Ed25519\)", 2)),
      ("Ed25519 verify", "ed25519-verify", ("eddsa", r"(EC|EdDSA) \(Ed25519\)", 1)),
      ("ECDSA P-256 sign", "ecdsa-p256-sign", ("ecdsap256", r"(EC \(prime256v1\)|ecdsa \(nistp256\))", 2)),
      ("ECDSA P-256 verify", "ecdsa-p256-verify", ("ecdsap256", r"(EC \(prime256v1\)|ecdsa \(nistp256\))", 1)),
      ("ECDSA P-384 sign", "ecdsa-p384-sign", ("ecdsap384", r"(EC \(secp384r1\)|ecdsa \(nistp384\))", 2)),
      ("ECDSA P-384 verify", "ecdsa-p384-verify", ("ecdsap384", r"(EC \(secp384r1\)|ecdsa \(nistp384\))", 1)),
      ("RSA-2048 sign/decrypt", "rsa-sign", ("rsa2048", r"rsa2048.*s +[0-9.]+ +[0-9.]+ +[0-9.]+$", 2)),
      ("RSA-2048 verify/encrypt", "rsa-verify", ("rsa2048", r"rsa2048.*s +[0-9.]+ +[0-9.]+ +[0-9.]+$", 1))]

ossl = sys.argv[1]
K = int(sys.argv[2]) if len(sys.argv) > 2 else 5

# macOS strips DYLD_* when it spawns /bin/sh, so an OpenSSL built in place
# has to be given its libraries by the shell that runs it rather than
# through the environment it inherits.
libs = os.path.dirname(os.path.dirname(ossl))
PREFIX = f"DYLD_LIBRARY_PATH={libs} LD_LIBRARY_PATH={libs} " \
    if ossl.endswith("apps/openssl") else ""

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True,
                          text=True).stdout

def ossl_bulk(name):
    out = sh(f"{PREFIX}{ossl} speed -evp {name} -bytes 16384 -seconds 2 2>/dev/null")
    for line in out.splitlines():
        if re.match(r"^[A-Za-z0-9()_-]+ +[0-9][0-9.]*k$", line.rstrip()):
            return float(line.split()[-1].rstrip("k")) / 1000.0
    return None

def ossl_pk(sub, rx, field):
    out = sh(f"{PREFIX}{ossl} speed -seconds 2 {sub} 2>/dev/null")
    hit = None
    for line in out.splitlines():
        if re.search(rx, line):
            hit = line          # RSA prints encaps/decaps first, signs after
    if hit is None:
        return None
    ops = float(hit.split()[-field])
    return 1e6 / ops if ops else None

def ours(binary, op):
    v = sh(f"{binary} {op}").strip()
    try:
        return float(v)
    except ValueError:
        return None

def best(f, higher):
    vals = [v for v in (f() for _ in range(K)) if v]
    if not vals:
        return None
    return max(vals) if higher else min(vals)

print("Throughput in MB/s, **higher is better**:\n")
head = " | ".join("crypton " + v for v in VERS)
print(f"| | {head} | OpenSSL | 2.1.4 / OpenSSL |")
print("| --- | " + "---: | " * (len(VERS) + 1) + "---: |")
for label, op, oname in BULK:
    ours_v = [best(lambda b=f"{SP}/bulk-{v}", o=op: ours(b, o), True) for v in VERS]
    t = best(lambda o=oname: ossl_bulk(o), True)
    cells = " | ".join(f"{x:.0f}" if x else "-" for x in ours_v)
    print(f"| {label} | {cells} | {t:.0f} | {ours_v[-1]/t:.2f} |")

print("\nTime per operation in microseconds, **lower is better**:\n")
print(f"| | {head} | OpenSSL | OpenSSL / 2.1.4 |")
print("| --- | " + "---: | " * (len(VERS) + 1) + "---: |")
for label, op, (sub, rx, field) in PK:
    ours_v = [best(lambda b=f"{SP}/pk-bin-{v}", o=op: ours(b, o), False) for v in VERS]
    t = best(lambda s=sub, r=rx, f=field: ossl_pk(s, r, f), False)
    cells = " | ".join(f"{x:.4g}" if x else "-" for x in ours_v)
    if t and ours_v[-1]:
        print(f"| {label} | {cells} | {t:.4g} | {t/ours_v[-1]:.2f} |")
    else:
        print(f"| {label} | {cells} | - | - |")
