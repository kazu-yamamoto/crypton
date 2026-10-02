#!/usr/bin/env python3
"""ML-KEM and ML-DSA: mlkem-native / mldsa-native against OpenSSL.

    pqrun.py <openssl-apps-binary> <bin-dir> [rounds] [seconds]

<bin-dir> holds kem_{c,native}_{512,768,1024} and dsa_{c,native}_{44,65,87}.

One round runs every column before any column runs twice and the order
rotates, so no implementation always pays the cold start.  Every cell is a
mean over many operations -- ML-DSA signing uses rejection sampling, so a
best-of would report the luckiest draw -- and the minimum of those means is
taken across rounds, which drops interference from the machine without
touching the distribution being measured.  That is what `openssl speed`
reports too, so both sides are read the same way.

OpenSSL's per-operation seconds column is printed to 1 us, too coarse here,
so the ops/s column is inverted instead.
"""
import collections
import os
import re
import subprocess
import sys

ossl, bindir = sys.argv[1], sys.argv[2]
K = int(sys.argv[3]) if len(sys.argv) > 3 else 5
SECS = sys.argv[4] if len(sys.argv) > 4 else "1"

libs = os.path.dirname(os.path.dirname(ossl))
ENV = dict(os.environ, LD_LIBRARY_PATH=libs, DYLD_LIBRARY_PATH=libs)

KEM = (512, 768, 1024)
DSA = (44, 65, 87)
OPS = {"ML-KEM": ("keygen", "encap", "decap"),
       "ML-DSA": ("keygen", "sign", "verify")}

JOBS = []
for lvl in KEM:
    JOBS.append((f"ML-KEM-{lvl}", "OpenSSL",
                 [ossl, "speed", "-elapsed", "-seconds", SECS,
                  f"ML-KEM-{lvl}"], "ossl"))
    for v, tag in (("c", "portable C"), ("native", "native backend")):
        JOBS.append((f"ML-KEM-{lvl}", f"mlkem-native {tag}",
                     [f"{bindir}/kem_{v}_{lvl}", "2000"], "ours"))
for lvl in DSA:
    JOBS.append((f"ML-DSA-{lvl}", "OpenSSL",
                 [ossl, "speed", "-elapsed", "-seconds", SECS,
                  f"ML-DSA-{lvl}"], "ossl"))
    for v, tag in (("c", "portable C"), ("native", "native backend")):
        JOBS.append((f"ML-DSA-{lvl}", f"mldsa-native {tag}",
                     [f"{bindir}/dsa_{v}_{lvl}", "300"], "ours"))

ossl_row = re.compile(r"^\s*(ML-KEM-\d+|ML-DSA-\d+)\s+"
                      r"[0-9.]+s\s+[0-9.]+s\s+[0-9.]+s\s+"
                      r"([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s*$")
ours_row = re.compile(r"^(keygen|encap|decap|sign|verify)\s+([0-9.]+) us")

best = collections.defaultdict(lambda: 1e18)
for r in range(K):
    jobs = JOBS[r % len(JOBS):] + JOBS[:r % len(JOBS)]
    for alg, impl, cmd, kind in jobs:
        p = subprocess.run(cmd, capture_output=True, text=True, env=ENV)
        got = 0
        for ln in p.stdout.splitlines():
            if kind == "ossl":
                m = ossl_row.match(ln)
                if m and m.group(1) == alg:
                    got = 3
                    for i, op in enumerate(OPS[alg[:6]]):
                        v = float(m.group(2 + i))
                        if v > 0:
                            k = (alg, impl, op)
                            best[k] = min(best[k], 1e6 / v)
            else:
                m = ours_row.match(ln)
                if m:
                    got += 1
                    k = (alg, impl, m.group(1))
                    best[k] = min(best[k], float(m.group(2)))
        if got != 3:
            sys.exit(f"{alg} / {impl} gave {got} of 3 operations:\n"
                     f"{p.stdout}\n{p.stderr}")
    print(f"  round {r + 1}/{K} done", file=sys.stderr)


def table(fam, levels):
    ops = OPS[fam]
    pkg = "mlkem-native" if fam == "ML-KEM" else "mldsa-native"
    print(f"\n**{fam}**, microseconds per operation (lower is better):\n")
    print("| | " + " | ".join(ops) + " |")
    print("| --- |" + " ---: |" * len(ops))
    for lvl in levels:
        alg = f"{fam}-{lvl}"
        for impl in ("OpenSSL", f"{pkg} portable C", f"{pkg} native backend"):
            row = [best[(alg, impl, op)] for op in ops]
            print(f"| {alg}, {impl} | "
                  + " | ".join(f"{v:.2f}" for v in row) + " |")
        o = [best[(alg, "OpenSSL", op)] for op in ops]
        n = [best[(alg, f"{pkg} native backend", op)] for op in ops]
        print(f"| **{alg}, OpenSSL / native** | "
              + " | ".join(f"**{a / b:.1f}x**" for a, b in zip(o, n)) + " |")


table("ML-KEM", KEM)
table("ML-DSA", DSA)
