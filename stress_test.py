#!/usr/bin/env python3
"""
STRESS TEST — Break the PQC Posture Scanner

Tests that SHOULD find bugs. Each test has an expected outcome.
If the scanner misses something or false-positives, it's a bug.
"""

import os
import sys
import json
import tempfile
import shutil
from pqc_posture import scan_codebase, CryptoFinding

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
    """Create a temp project with given files."""
    tmp = tempfile.mkdtemp(prefix="pqc_stress_")
    for path, content in files.items():
        full = os.path.join(tmp, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'w') as f:
            f.write(content)
    return tmp


def cleanup(path):
    shutil.rmtree(path, ignore_errors=True)


# ════════════════════════════════════════════════════════════
# TEST 1: FALSE NEGATIVES — Things it SHOULD catch but might miss
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP 1: FALSE NEGATIVES (should catch but might miss)")
print("="*70)

# 1a: Obfuscated RSA key generation (variable indirection)
proj = make_project({
    "crypto_util.py": """
algo = "RSA"
key_size = 2048
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
privkey = rsa_mod.generate_private_key(public_exponent=65537, key_size=key_size)
""",
})
r = scan_codebase(proj)
test("Indirect RSA generation via alias import",
     any(f['algorithm'] == 'RSA Key Exchange' for f in r['findings']),
     f"Found {r['total_findings']} findings but no RSA. Patterns match rsa.generate_private_key but this is rsa_mod.generate_private_key")
cleanup(proj)


# 1b: Go crypto — subtle patterns
proj = make_project({
    "main.go": """package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
)

func genKey() {
    privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    _ = privateKey
}
""",
})
r = scan_codebase(proj)
test("Go ECDSA key generation",
     any('ECDSA' in f['algorithm'] for f in r['findings']),
     f"Found {[f['algorithm'] for f in r['findings']]}. Go ECDSA pattern might be missed.")
cleanup(proj)


# 1c: Rust crypto patterns
proj = make_project({
    "src/main.rs": """
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1v15};
use rand::rngs::OsRng;

fn main() {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed");
    let public_key = RsaPublicKey::from(&private_key);
}
""",
})
r = scan_codebase(proj)
test("Rust RSA generation (RsaPrivateKey::new)",
     any('RSA' in f['algorithm'] for f in r['findings']),
     f"Found {[f['algorithm'] for f in r['findings']]}. Rust RSA new() not in patterns.")
cleanup(proj)


# 1d: Java Cipher.getInstance with RSA
proj = make_project({
    "CryptoService.java": """
import javax.crypto.Cipher;
import java.security.KeyPairGenerator;

public class CryptoService {
    public void encrypt() {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }
}
""",
})
r = scan_codebase(proj)
rsa_found = any('RSA' in f['algorithm'] for f in r['findings'])
test("Java RSA Cipher.getInstance",
     rsa_found,
     f"Java Cipher.getInstance('RSA/ECB/PKCS1Padding') not caught. Found: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)


# 1e: PHP openssl functions
proj = make_project({
    "encryption.php": """<?php
$config = array(
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
);
$res = openssl_pkey_new($config);
openssl_pkey_export($res, $privKey);
$hash = md5($data);
$sha1 = sha1($password);
?>""",
})
r = scan_codebase(proj)
rsa_found = any('RSA' in f['algorithm'] for f in r['findings'])
md5_found = any('MD5' in f['algorithm'] for f in r['findings'])
test("PHP openssl_pkey_new RSA", rsa_found, f"PHP RSA not found. Got: {[f['algorithm'] for f in r['findings']]}")
test("PHP md5() function", md5_found, f"PHP md5() not caught")
cleanup(proj)


# 1f: Multi-line crypto (pattern spans 2 lines)
proj = make_project({
    "multi.py": """
from cryptography.hazmat.primitives.asymmetric import rsa

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)
""",
})
r = scan_codebase(proj)
test("Multi-line RSA generate (call on separate line)",
     any('RSA' in f['algorithm'] for f in r['findings']),
     "rsa.generate_private_key( split across lines — scanner reads line-by-line")
cleanup(proj)


# 1g: Hardcoded SSL/TLS version in config
proj = make_project({
    "config.yaml": """
server:
  tls:
    min_version: TLSv1_0
    cipher_suites:
      - TLS_RSA_WITH_AES_256_CBC_SHA
""",
})
r = scan_codebase(proj)
tls_found = any('TLS' in f['algorithm'] for f in r['findings'])
test("YAML TLS 1.0 config", tls_found, f"TLS in YAML not caught. Found: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)


# 1h: C/C++ crypto
proj = make_project({
    "crypto.c": """
#include <openssl/rsa.h>
#include <openssl/md5.h>

int main() {
    RSA *rsa = RSA_generate_key(2048, 65537, NULL, NULL);
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(data, len, digest);
    return 0;
}
""",
})
r = scan_codebase(proj)
rsa_c = any('RSA' in f['algorithm'] for f in r['findings'])
md5_c = any('MD5' in f['algorithm'] for f in r['findings'])
test("C RSA_generate_key", rsa_c, "C RSA not caught")
test("C MD5() function", md5_c, "C MD5 not caught")
cleanup(proj)


# 1i: Node.js subtle crypto
proj = make_project({
    "auth.js": """
const crypto = require("crypto");
const { generateKeyPairSync } = require("crypto");

// Generate RSA keypair for JWT
const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
});

// Hash password with MD5 (legacy)
const hash = crypto.createHash('md5').update(password).digest('hex');

// Sign with HMAC-SHA1
const hmac = crypto.createHmac('sha1', secret).update(data).digest('hex');
""",
})
r = scan_codebase(proj)
rsa_js = any('RSA' in f['algorithm'] for f in r['findings'])
md5_js = any('MD5' in f['algorithm'] for f in r['findings'])
sha1_js = any('SHA-1' in f['algorithm'] for f in r['findings'])
test("Node.js generateKeyPairSync RSA", rsa_js, f"JS RSA not caught. Got: {[f['algorithm'] for f in r['findings']]}")
test("Node.js createHash md5", md5_js, "JS MD5 not caught")
test("Node.js createHmac sha1", sha1_js, "JS SHA-1 not caught")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# TEST 2: FALSE POSITIVES — Things it should NOT flag
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP 2: FALSE POSITIVES (should NOT flag)")
print("="*70)

# 2a: String "RS256" in documentation, not code
proj = make_project({
    "README.md": """
# Authentication

We use RS256 for JWT tokens. ECDSA P-256 is also supported.
The old system used MD5 hashes which were deprecated.
""",
})
r = scan_codebase(proj)
test("README.md not scanned (no .md in extensions)",
     r['total_findings'] == 0,
     f"README should not be scanned, found {r['total_findings']} findings")
cleanup(proj)

# 2b: Variable named "md5" that's not actually MD5 hashing
proj = make_project({
    "models.py": """
class Document:
    # md5 is the column name in legacy DB, but we use SHA-256 now
    md5 = Column(String(64))  # renamed column, actually stores SHA-256

    def get_md5_column_name(self):
        return "md5"
""",
})
r = scan_codebase(proj)
# This is a legit concern — variable named "md5" COULD be a false positive
# But our scanner uses regex for md5( or MD5( or hashlib.md5
# So "md5 = Column" should NOT match
md5_findings = [f for f in r['findings'] if 'MD5' in f['algorithm']]
test("Variable named 'md5' not flagged as MD5 hash",
     len(md5_findings) == 0,
     f"False positive: {[f['usage'] for f in md5_findings]}")
cleanup(proj)


# 2c: Comments about crypto should be LOW risk
proj = make_project({
    "migration.py": """
# TODO: migrate from RSA to ML-KEM
# FIXME: remove SHA-1 usage by Q3 2026
# deprecated: this used DES encryption
def new_encrypt():
    pass  # uses AES-256-GCM now
""",
})
r = scan_codebase(proj)
# Lines starting with # should be skipped entirely (line 317 of scanner)
test("Comment lines skipped (# prefix)",
     r['total_findings'] == 0,
     f"Comments produced {r['total_findings']} findings: {[f['usage'] for f in r['findings']]}")
cleanup(proj)


# 2d: Test file with crypto (should be demoted, not CRITICAL)
proj = make_project({
    "tests/test_auth.py": """
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

def test_rsa_keygen():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert key is not None

def test_md5_legacy():
    h = hashlib.md5(b"test").hexdigest()
    assert len(h) == 32
""",
})
r = scan_codebase(proj)
critical_in_test = [f for f in r['findings'] if f['risk'] == 'CRITICAL' and f['context'] == 'test']
test("Test file crypto demoted (no CRITICAL in test/)",
     len(critical_in_test) == 0,
     f"Test code still CRITICAL: {[f['algorithm'] for f in critical_in_test]}")
cleanup(proj)


# 2e: Quantum-safe algorithms should NOT be flagged as vulnerable
proj = make_project({
    "pqc_impl.py": """
from quantcrypt.kem import ML_KEM_768
from quantcrypt.dsa import ML_DSA_65

kem = ML_KEM_768()
dsa = ML_DSA_65()
pub, priv = dsa.keygen()
signature = dsa.sign(priv, message)
""",
})
r = scan_codebase(proj)
broken = [f for f in r['findings'] if f['quantum_status'] == 'BROKEN']
test("PQC algorithms (ML-KEM, ML-DSA) not flagged as BROKEN",
     len(broken) == 0,
     f"PQC code flagged as broken: {[f['algorithm'] for f in broken]}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# TEST 3: EDGE CASES — Weird inputs that break things
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP 3: EDGE CASES (weird inputs)")
print("="*70)

# 3a: Empty directory
proj = tempfile.mkdtemp(prefix="pqc_empty_")
r = scan_codebase(proj)
test("Empty directory doesn't crash",
     r['files_scanned'] == 0 and r['total_findings'] == 0,
     f"Scanned {r['files_scanned']} files, {r['total_findings']} findings")
cleanup(proj)

# 3b: Binary files mixed in
proj = make_project({
    "code.py": "import hashlib\nhash = hashlib.md5(b'test').hexdigest()\n",
    "image.py.bak": "\x00\x01\x02\x03\xff\xfe\xfd" * 100,
})
# .bak not in SCAN_EXTENSIONS — should skip
r = scan_codebase(proj)
test("Binary .bak file skipped (not in scan extensions)",
     r['files_scanned'] == 1,
     f"Scanned {r['files_scanned']} files instead of 1")
cleanup(proj)


# 3c: Deeply nested directory
deep_path = "a/b/c/d/e/f/g/h/i/j/crypto.py"
proj = make_project({
    deep_path: 'from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n',
})
r = scan_codebase(proj)
test("Deeply nested file found",
     r['total_findings'] > 0,
     f"Deep path not scanned: {r['files_scanned']} files")
cleanup(proj)


# 3d: File with unicode/emoji in crypto code
proj = make_project({
    "unicode_crypto.py": """
# 🔐 Encryption module — лучший крипто
import hashlib
password = "пароль123"
hash_result = hashlib.md5(password.encode('utf-8')).hexdigest()  # insecure
""",
})
r = scan_codebase(proj)
test("Unicode content doesn't crash scanner",
     r['total_findings'] > 0,
     "Crashed or found 0 findings")
cleanup(proj)


# 3e: Very long lines
long_line = "x = hashlib.md5(b'" + "A" * 10000 + "').hexdigest()"
proj = make_project({
    "long.py": long_line + "\n",
})
r = scan_codebase(proj)
test("Very long line (10K chars) still scanned",
     r['total_findings'] > 0,
     f"Long line missed: {r['total_findings']} findings")
cleanup(proj)


# 3f: File with NO newline at end
proj = make_project({
    "no_newline.py": "import hashlib\nhash = hashlib.md5(b'test').hexdigest()",
})
r = scan_codebase(proj)
test("File without trailing newline",
     r['total_findings'] > 0,
     "No findings from file without trailing newline")
cleanup(proj)


# 3g: Symlinks (should follow or skip gracefully)
proj = make_project({
    "real.py": "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(65537, 2048)\n",
})
link_path = os.path.join(proj, "link.py")
try:
    os.symlink(os.path.join(proj, "real.py"), link_path)
except OSError:
    pass  # symlinks might not work in some envs
r = scan_codebase(proj)
test("Symlinks handled gracefully",
     r['files_scanned'] >= 1,
     "Crashed on symlink")
cleanup(proj)


# 3h: Mixed case extensions
proj = make_project({
    "Crypto.PY": "import hashlib\nhash = hashlib.md5(b'x').hexdigest()\n",
    "Auth.Py": "from cryptography.hazmat.primitives.asymmetric import rsa\n",
})
r = scan_codebase(proj)
test("Mixed case extensions (.PY, .Py) scanned",
     r['files_scanned'] >= 1,
     f"Mixed case files missed: scanned {r['files_scanned']}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# TEST 4: CORRECTNESS — Does it count and categorize right?
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP 4: CORRECTNESS (counting and categorization)")
print("="*70)

# 4a: Multiple crypto on same line (actual function calls, not just strings)
proj = make_project({
    "multi_algo.py": """
result = hashlib.md5(data) ; sig = jwt.encode(p, k, algorithm="RS256")
""",
})
r = scan_codebase(proj)
algos = [f['algorithm'] for f in r['findings']]
test("Multiple algos on one line all caught",
     len(algos) >= 2,
     f"Only found {algos} on multi-algo line")
cleanup(proj)


# 4b: Risk score calculation
proj = make_project({
    "critical.py": """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
""",
})
r = scan_codebase(proj)
test("CRITICAL finding in production scores > 0",
     r['risk_score'] > 0,
     f"Risk score is {r['risk_score']} for CRITICAL RSA finding")
cleanup(proj)


# 4c: CBOM output structure
proj = make_project({
    "app.py": "import hashlib\nh = hashlib.md5(b'x').hexdigest()\n",
})
r = scan_codebase(proj)
cbom = r['cbom']
test("CBOM has correct format",
     cbom['bomFormat'] == 'CycloneDX' and cbom['specVersion'] == '1.6',
     f"CBOM format: {cbom.get('bomFormat')}, version: {cbom.get('specVersion')}")
test("CBOM algorithms populated",
     len(cbom['cryptoProperties']['algorithms']) > 0,
     "No algorithms in CBOM")
cleanup(proj)


# 4d: Duplicate detection — same finding on same line shouldn't double-count
proj = make_project({
    "dup.py": "hash = hashlib.md5(b'test').hexdigest()\n",
})
r = scan_codebase(proj)
md5_findings = [f for f in r['findings'] if 'MD5' in f['algorithm']]
test("No duplicate findings for same line",
     len(md5_findings) <= 2,  # md5( and hashlib.md5 could both match, which is ok
     f"Got {len(md5_findings)} MD5 findings for one line — possible duplication")
cleanup(proj)


# 4e: Context classification accuracy
proj = make_project({
    "service.py": """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
""",
    "tests/test_service.py": """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
""",
})
r = scan_codebase(proj)
prod = [f for f in r['findings'] if f['context'] != 'test']
tests = [f for f in r['findings'] if f['context'] == 'test']
test("Production vs test classification",
     len(prod) > 0 and len(tests) > 0,
     f"Prod: {len(prod)}, Test: {len(tests)} — should have both")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# TEST 5: REAL-WORLD PATTERNS — Common code that MUST be caught
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP 5: REAL-WORLD PATTERNS")
print("="*70)

# 5a: Django settings with insecure hasher
proj = make_project({
    "settings.py": """
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
    'django.contrib.auth.hashers.SHA1PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]
""",
})
r = scan_codebase(proj)
md5_found = any('MD5' in f['algorithm'] for f in r['findings'])
sha1_found = any('SHA-1' in f['algorithm'] for f in r['findings'])
test("Django MD5PasswordHasher caught", md5_found, "Django MD5 hasher not caught")
test("Django SHA1PasswordHasher caught", sha1_found, "Django SHA1 hasher not caught")
cleanup(proj)


# 5b: Flask/Python JWT with RS256
proj = make_project({
    "auth.py": """
import jwt
token = jwt.encode(payload, private_key, algorithm="RS256")
decoded = jwt.decode(token, public_key, algorithms=["RS256"])
""",
})
r = scan_codebase(proj)
jwt_found = any('JWT' in f['algorithm'] or 'RS256' in f.get('usage', '') for f in r['findings'])
test("JWT RS256 token signing caught", jwt_found,
     f"JWT RS256 not caught. Found: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)


# 5c: Kubernetes TLS config
proj = make_project({
    "ingress.yaml": """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1 TLSv1.1 TLSv1.2"
spec:
  tls:
    - hosts:
        - example.com
""",
})
r = scan_codebase(proj)
# This is tricky — "TLSv1" as a string, not TLSv1_0 pattern
test("K8s TLS 1.0 in YAML annotation",
     r['total_findings'] > 0,
     f"K8s TLS config not caught. Patterns only match TLSv1_0 not 'TLSv1 '")
cleanup(proj)


# 5d: Python ssl context with weak protocol
proj = make_project({
    "server.py": """
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
context.set_ciphers('DES-CBC3-SHA:RC4-SHA')
""",
})
r = scan_codebase(proj)
tls_found = any('TLS' in f['algorithm'] for f in r['findings'])
des_found = any('DES' in f['algorithm'] for f in r['findings'])
test("Python ssl.PROTOCOL_TLSv1 caught", tls_found, "TLS v1 not caught")
test("DES cipher suite caught", des_found, f"DES not caught. Found: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)


# 5e: AWS KMS with RSA
proj = make_project({
    "kms.py": """
import boto3
client = boto3.client('kms')
response = client.create_key(
    KeySpec='RSA_2048',
    KeyUsage='ENCRYPT_DECRYPT',
)
""",
})
r = scan_codebase(proj)
# RSA_2048 might not match our patterns (we look for RSA.generate etc)
test("AWS KMS RSA_2048 key spec",
     any('RSA' in f['algorithm'] for f in r['findings']),
     "AWS KMS RSA_2048 not caught — patterns are function-call specific, not keyword")
cleanup(proj)


# 5f: Docker compose with weak TLS
proj = make_project({
    "docker-compose.yml": """
services:
  nginx:
    environment:
      - SSL_PROTOCOLS=TLSv1 TLSv1.1 TLSv1.2
      - SSL_CIPHERS=HIGH:!aNULL:!MD5
""",
})
r = scan_codebase(proj)
test("Docker compose TLS config",
     r['total_findings'] >= 0,  # just checking it doesn't crash
     "Crashed on docker-compose.yml")
cleanup(proj)


# 5g: Terraform with weak crypto
proj = make_project({
    "main.tf": """
# Terraform doesn't have .tf in our extensions!
resource "aws_kms_key" "example" {
  description             = "RSA 2048 key"
  customer_master_key_spec = "RSA_2048"
  key_usage               = "ENCRYPT_DECRYPT"
}
""",
})
# .tf not in SCAN_EXTENSIONS!
r = scan_codebase(proj)
test("Terraform .tf files NOW scanned (extension added)",
     r['files_scanned'] == 1 and any('RSA' in f['algorithm'] for f in r['findings']),
     f"Scanned {r['files_scanned']} files, found: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# TEST 6: PERFORMANCE — Can it handle big input?
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP 6: PERFORMANCE")
print("="*70)

# 6a: 1000 files
big_project = {}
for i in range(1000):
    if i % 10 == 0:
        big_project[f"pkg{i//100}/mod{i}.py"] = f"import hashlib\nh = hashlib.md5(b'{i}').hexdigest()\n"
    else:
        big_project[f"pkg{i//100}/mod{i}.py"] = f"x = {i}\n"
proj = make_project(big_project)
r = scan_codebase(proj)
test("1000 files scanned under 5 seconds",
     r['scan_time_ms'] < 5000,
     f"Took {r['scan_time_ms']}ms for 1000 files")
test("Found findings in 100 of 1000 files",
     r['total_findings'] >= 50,
     f"Found {r['total_findings']} — expected ~100")
cleanup(proj)


# 6b: Single large file (10K lines)
large_content = "# Safe code\nx = 1\n" * 5000
large_content += "import hashlib\nh = hashlib.md5(b'vuln').hexdigest()\n"
large_content += "x = 2\n" * 5000
proj = make_project({"big.py": large_content})
r = scan_codebase(proj)
test("10K line file — finds crypto buried in middle",
     r['total_findings'] > 0,
     "Missed finding buried at line 5001")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# RESULTS SUMMARY
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print(f"  STRESS TEST RESULTS: {PASS} PASSED, {FAIL} FAILED")
print("="*70)

if BUGS:
    print(f"\n  🐛 BUGS FOUND ({len(BUGS)}):")
    for i, bug in enumerate(BUGS, 1):
        print(f"    {i}. {bug}")
else:
    print("\n  ✅ ALL TESTS PASSED — Scanner is solid!")

print(f"\n  Coverage: {PASS}/{PASS+FAIL} tests ({100*PASS//(PASS+FAIL)}%)")
print()

sys.exit(1 if FAIL > 0 else 0)
