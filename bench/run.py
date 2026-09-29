#!/usr/bin/env python3
"""crypton at main (2.1.3) against OpenSSL 4.0.2 on this machine, the two
alternated so neither gets the quieter moment, best of K for each cell.

    ./run213.py <bulk-binary> <pk-binary> <openssl> [K]
"""
import subprocess, sys, re, os

BULK = [  # label, our name, openssl -evp name
    ("AES-128-GCM",       "aes128gcm",  "aes-128-gcm"),
    ("AES-256-GCM",       "aes256gcm",  "aes-256-gcm"),
    ("ChaCha20-Poly1305", "chachapoly", "chacha20-poly1305"),
    ("SHA-1",             "sha1",       "sha1"),
    ("SHA-256",           "sha256",     "sha256"),
    ("SHA-512",           "sha512",     "sha512"),
    ("SHA3-256",          "sha3-256",   "sha3-256"),
]

# label, our op, (openssl subcommand, row regex, field from the end)
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

bulkbin, pkbin, ossl = sys.argv[1], sys.argv[2], sys.argv[3]
K = int(sys.argv[4]) if len(sys.argv) > 4 else 5
# macOS strips DYLD_* when it spawns /bin/sh, so the variable has to be set
# by the shell itself rather than inherited through the environment.
prefix = ""
if ossl.endswith("apps/openssl"):
    libs = os.path.dirname(os.path.dirname(ossl))
    prefix = f"DYLD_LIBRARY_PATH={libs} LD_LIBRARY_PATH={libs} "

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True,
                          text=True).stdout

def ossl_bulk(name):
    out = sh(f"{prefix}{ossl} speed -evp {name} -seconds 2 2>/dev/null")
    for line in out.splitlines():
        if re.match(r"^[A-Za-z0-9()-]+ +[0-9].*k$", line.rstrip()):
            v = line.split()[-1]
            return float(v.rstrip("k")) / 1000.0   # k/s -> MB/s
    return None

def ossl_pk(sub, rx, field):
    out = sh(f"{prefix}{ossl} speed -seconds 2 {sub} 2>/dev/null")
    hit = None
    for line in out.splitlines():
        if re.search(rx, line):
            hit = line   # RSA prints encaps/decaps first and signs/verify
                         # after it; the last row is the one wanted
    if hit is None:
        return None
    ops = float(hit.split()[-field])
    return 1e6 / ops if ops else None

def ours_bulk(name):
    v = sh(f"{bulkbin} {name}").strip()
    return float(v) if v else None

def ours_pk(op):
    v = sh(f"{pkbin} {op}").strip()
    return float(v) if v else None

def best(f, higher):
    vals = [v for v in (f() for _ in range(K)) if v]
    if not vals:
        return None
    return max(vals) if higher else min(vals)

print("## Throughput over 16 KiB, MB/s (higher is better)\n")
print(f"| | crypton 2.1.3 | {sys.argv[5] if len(sys.argv)>5 else 'OpenSSL'} | ratio |")
print("| --- | ---: | ---: | ---: |")
for label, ours, theirs in BULK:
    a = best(lambda: ours_bulk(ours), True)
    b = best(lambda: ossl_bulk(theirs), True)
    print(f"| {label} | {a:.0f} | {b:.0f} | {a/b:.2f} |")

print("\n## Time per operation, microseconds (lower is better)\n")
print(f"| | crypton 2.1.3 | {sys.argv[5] if len(sys.argv)>5 else 'OpenSSL'} | ratio |")
print("| --- | ---: | ---: | ---: |")
for label, ours, (sub, rx, field) in PK:
    a = best(lambda: ours_pk(ours), False)
    b = best(lambda: ossl_pk(sub, rx, field), False)
    if a is None or b is None:
        print(f"| {label} | {a} | {b} | - |")
    else:
        print(f"| {label} | {a:.4g} | {b:.4g} | {b/a:.2f} |")
