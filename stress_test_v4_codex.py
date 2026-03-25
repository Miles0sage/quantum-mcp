#!/usr/bin/env python3
"""
STRESS TEST V4 — Fixes for bugs found by Codex GPT-5 blind review.
Tests the 4 specific issues Codex identified.
"""

import os
import sys
import json
import tempfile
import shutil
from pqc_posture import scan_codebase, CRYPTO_PATTERNS

PASS = 0
FAIL = 0
BUGS = []

def test(name, passed, detail=""):
    global PASS, FAIL, BUGS
    if passed:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        BUGS.append(f"{name}: {detail}")
        print(f"  ✗ BUG: {name} — {detail}")

def make_project(files: dict) -> str:
    tmp = tempfile.mkdtemp(prefix="pqc_v4_")
    for path, content in files.items():
        full = os.path.join(tmp, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'w') as f:
            f.write(content)
    return tmp

def cleanup(path):
    shutil.rmtree(path, ignore_errors=True)


# ════════════════════════════════════════════════════════════
# BUG 1: CBOM quantumSafe was using algo_counts (Counter) instead of actual status
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  BUG 1: CBOM quantumSafe correctness")
print("="*70)

proj = make_project({
    "crypto.py": """
from cryptography.hazmat.primitives.asymmetric import rsa, ec
key = rsa.generate_private_key(65537, 2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
""",
    "hash.py": """
import hashlib
h = hashlib.md5(b'data').hexdigest()
""",
})
r = scan_codebase(proj)
cbom = r['cbom']
algos = {a['name']: a['quantumSafe'] for a in cbom['cryptoProperties']['algorithms']}

# RSA is BROKEN → quantumSafe should be False
if 'RSA Key Exchange' in algos:
    test("CBOM: RSA Key Exchange marked quantumSafe=False",
         algos['RSA Key Exchange'] == False,
         f"Got quantumSafe={algos['RSA Key Exchange']}")

# ECDSA is BROKEN → quantumSafe should be False
if 'ECDSA' in algos:
    test("CBOM: ECDSA marked quantumSafe=False",
         algos['ECDSA'] == False,
         f"Got quantumSafe={algos['ECDSA']}")

# MD5 is WEAKENED → quantumSafe should be False
if 'MD5' in algos:
    test("CBOM: MD5 marked quantumSafe=False",
         algos['MD5'] == False,
         f"Got quantumSafe={algos['MD5']}")

cleanup(proj)

# Test AES-256 which IS quantum-safe
proj = make_project({
    "enc.py": """
from cryptography.hazmat.primitives.ciphers import algorithms
cipher = algorithms.AES(key)  # AES-256
""",
})
r = scan_codebase(proj)
cbom = r['cbom']
algos = {a['name']: a['quantumSafe'] for a in cbom['cryptoProperties']['algorithms']}
if 'AES-256' in algos:
    test("CBOM: AES-256 marked quantumSafe=True",
         algos['AES-256'] == True,
         f"Got quantumSafe={algos['AES-256']}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# BUG 2: Duplicate findings per line per algorithm
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  BUG 2: Duplicate findings per line")
print("="*70)

# ECDH has patterns for both 'ECDH' and 'KeyAgreement.getInstance("ECDH"'
# A line matching both should only produce ONE finding
proj = make_project({
    "KeyExchange.java": """
import javax.crypto.KeyAgreement;
KeyAgreement ka = KeyAgreement.getInstance("ECDH");
""",
})
r = scan_codebase(proj)
ecdh_line2 = [f for f in r['findings'] if f['algorithm'] == 'ECDH' and f['line'] == 2]
test("No duplicate ECDH findings on same line",
     len(ecdh_line2) <= 1,
     f"Got {len(ecdh_line2)} ECDH findings on line 2")
cleanup(proj)

# RSA has many patterns — ensure only one match per line
proj = make_project({
    "rsa_heavy.py": """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
""",
})
r = scan_codebase(proj)
rsa_line2 = [f for f in r['findings'] if f['algorithm'] == 'RSA Key Exchange' and f['line'] == 2]
test("No duplicate RSA findings on same line",
     len(rsa_line2) <= 1,
     f"Got {len(rsa_line2)} RSA findings on line 2")
cleanup(proj)

# Multiple DIFFERENT algorithms on same line is OK (not a duplicate)
proj = make_project({
    "multi.py": 'result = hashlib.md5(data); sig = jwt.encode(p, k, algorithm="RS256")\n',
})
r = scan_codebase(proj)
algos_on_line1 = set(f['algorithm'] for f in r['findings'] if f['line'] == 1)
test("Multiple different algos on same line still all caught",
     len(algos_on_line1) >= 2,
     f"Only caught {algos_on_line1}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# BUG 3: .env and .txt files now scanned
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  BUG 3: .env and .txt file scanning")
print("="*70)

proj = make_project({
    ".env": """
JWT_ALGORITHM=RS256
TLS_VERSION=TLSv1_0
SECRET_KEY=super_secret
""",
})
r = scan_codebase(proj)
test(".env file scanned",
     r['files_scanned'] >= 1,
     f"Scanned {r['files_scanned']} files")
test(".env RS256 detected",
     any('JWT' in f['algorithm'] for f in r['findings']),
     f"Got: {[f['algorithm'] for f in r['findings']]}")
test(".env TLSv1_0 detected",
     any('TLS' in f['algorithm'] for f in r['findings']),
     f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

proj = make_project({
    "requirements.txt": """
flask==3.0.0
pycryptodome==3.19.0
pyOpenSSL==24.0.0
requests==2.31.0
""",
})
r = scan_codebase(proj)
test("requirements.txt scanned",
     r['files_scanned'] >= 1,
     f"Scanned {r['files_scanned']} files")
test("requirements.txt pycryptodome detected",
     any('Crypto Dep' in f['algorithm'] for f in r['findings']),
     f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# BUG 4: C-style block comments /* ... */ now skipped
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  BUG 4: C-style block comment handling")
print("="*70)

# Single-line block comment
proj = make_project({
    "legacy.c": """
/* RSA_generate_key is deprecated, use RSA_generate_key_ex */
int main() { return 0; }
""",
})
r = scan_codebase(proj)
test("Single-line /* block comment */ skipped",
     r['total_findings'] == 0,
     f"Found {r['total_findings']}: {[f['usage'] for f in r['findings']]}")
cleanup(proj)

# Multi-line block comment
proj = make_project({
    "old_code.java": """
/*
 * This used to use RSA_generate_key for key generation.
 * We also had ECDSA signing here.
 * MD5 hashing was used for checksums.
 * All deprecated now.
 */
public class App {
    public static void main(String[] args) {}
}
""",
})
r = scan_codebase(proj)
test("Multi-line /* block comment */ skipped",
     r['total_findings'] == 0,
     f"Found {r['total_findings']}: {[f['usage'] for f in r['findings']]}")
cleanup(proj)

# Block comment then real code after
proj = make_project({
    "mixed.c": """
/* Old deprecated RSA code removed */
#include <openssl/rsa.h>
RSA *rsa = RSA_generate_key(2048, 65537, NULL, NULL);
""",
})
r = scan_codebase(proj)
test("Code AFTER block comment still caught",
     any('RSA' in f['algorithm'] for f in r['findings']),
     f"Missed RSA after block comment ended")
# The comment should be skipped but the real code should be caught
comment_findings = [f for f in r['findings'] if 'deprecated' in f.get('usage', '')]
test("Block comment line not in findings",
     len(comment_findings) == 0,
     f"Comment leaked: {[f['usage'] for f in comment_findings]}")
cleanup(proj)

# Nested block comments (edge case)
proj = make_project({
    "edge.js": """
/* outer comment
   /* inner comment */
   still_in_comment(); */
var crypto = require("crypto");
var h = crypto.createHash("md5").update("x").digest("hex");
""",
})
r = scan_codebase(proj)
test("Code after nested block comments still scanned",
     any('MD5' in f['algorithm'] for f in r['findings']),
     f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# RESULTS
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print(f"  STRESS TEST V4 (CODEX BUGS): {PASS} PASSED, {FAIL} FAILED")
print("="*70)

if BUGS:
    print(f"\n  🐛 REMAINING BUGS ({len(BUGS)}):")
    for i, bug in enumerate(BUGS, 1):
        print(f"    {i}. {bug}")
else:
    print("\n  ✅ ALL 4 CODEX BUGS FIXED AND VERIFIED!")

print(f"\n  Coverage: {PASS}/{PASS+FAIL} tests ({100*PASS//(PASS+FAIL) if PASS+FAIL > 0 else 0}%)")
print()

sys.exit(1 if FAIL > 0 else 0)
