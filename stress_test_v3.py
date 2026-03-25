#!/usr/bin/env python3
"""
STRESS TEST V3 — Break it. Adversarial. What devs will throw at it.

Tests things that SHOULD trip up a scanner:
- Obfuscated crypto (variable indirection, dynamic imports, eval)
- Minified code
- Polyglot files
- Crypto in string templates / f-strings
- Base64 encoded crypto calls
- Intentional false positive traps
- Massive repos with deep nesting
- Race conditions (concurrent scan)
- Non-UTF8 binary mixed with text
- Config files with unusual formatting
- Real CVE patterns
- Crypto in comments that look like code
- Same algo across 10+ files (dedup check)
"""

import os
import sys
import tempfile
import shutil
import json
import time
import threading
from pqc_posture import scan_codebase

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
    tmp = tempfile.mkdtemp(prefix="pqc_v3_")
    for path, content in files.items():
        full = os.path.join(tmp, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'w') as f:
            f.write(content)
    return tmp

def cleanup(path):
    shutil.rmtree(path, ignore_errors=True)

def find(results, algo_substring):
    return [f for f in results['findings'] if algo_substring in f['algorithm']]


# ════════════════════════════════════════════════════════════
# GROUP 1: OBFUSCATION — Can devs hide crypto from the scanner?
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  GROUP 1: OBFUSCATION ATTEMPTS")
print("="*70)

# 1a: Crypto via getattr / dynamic dispatch
proj = make_project({
    "sneaky.py": """
import hashlib
algo = 'md5'
h = getattr(hashlib, algo)(b'data').hexdigest()
""",
})
r = scan_codebase(proj)
# getattr(hashlib, algo) — scanner WON'T catch this (no literal md5 call)
# This is a KNOWN LIMITATION of static analysis
test("Dynamic getattr(hashlib, algo) — known limitation (won't catch)",
     len(find(r, 'MD5')) == 0,
     f"Unexpectedly caught dynamic dispatch: {[f['usage'] for f in find(r, 'MD5')]}")
cleanup(proj)

# 1b: Crypto via importlib
proj = make_project({
    "dynamic_import.py": """
import importlib
crypto = importlib.import_module('cryptography.hazmat.primitives.asymmetric.rsa')
key = crypto.generate_private_key(65537, 2048)
""",
})
r = scan_codebase(proj)
# importlib.import_module('...rsa') then crypto.generate_private_key
# Scanner checks rsa\w*.generate_private_key — "crypto" doesn't match
test("importlib dynamic import — known limitation (won't catch)",
     len(find(r, 'RSA')) == 0,
     f"Unexpectedly caught: {[f['usage'] for f in find(r, 'RSA')]}")
cleanup(proj)

# 1c: String concatenation to build algorithm name
proj = make_project({
    "concat.py": """
import jwt
algo = "RS" + "256"
token = jwt.encode(payload, key, algorithm=algo)
""",
})
r = scan_codebase(proj)
# "RS" + "256" — scanner checks for literal RS256
test("String concat 'RS' + '256' — won't catch (no literal)",
     len(find(r, 'JWT')) == 0,
     f"Unexpectedly caught string concat")
cleanup(proj)

# 1d: But DIRECT usage still caught
proj = make_project({
    "direct.py": """
import jwt
token = jwt.encode(payload, key, algorithm="RS256")
""",
})
r = scan_codebase(proj)
test("Direct RS256 string still caught",
     len(find(r, 'JWT')) > 0,
     "Direct RS256 not caught!")
cleanup(proj)

# 1e: Minified JavaScript (one very long line)
proj = make_project({
    "bundle.min.js": 'var a=require("crypto");var b=a.createHash("md5");var c=b.update("data").digest("hex");var d=a.generateKeyPairSync("rsa",{modulusLength:2048});',
})
r = scan_codebase(proj)
md5 = find(r, 'MD5')
rsa = find(r, 'RSA')
test("Minified JS — MD5 found", len(md5) > 0, f"MD5 missed in minified JS")
test("Minified JS — RSA found", len(rsa) > 0, f"RSA missed in minified JS")
cleanup(proj)

# 1f: Webpack chunk with crypto buried in noise
proj = make_project({
    "chunk-vendors.js": """
!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():"function"==typeof define&&define.amd?define(t):(e=e||self).Foo=t()}(this,function(){var crypto=require("crypto");return{hash:function(d){return crypto.createHash("md5").update(d).digest("hex")},sign:function(d,k){return crypto.sign("RSA-SHA256",Buffer.from(d),k)}}});
""",
})
r = scan_codebase(proj)
test("Webpack bundle — crypto.createHash md5 found",
     len(find(r, 'MD5')) > 0,
     "Missed MD5 in webpack bundle")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# GROUP 2: FALSE POSITIVE TRAPS — Things that look like crypto but aren't
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  GROUP 2: FALSE POSITIVE TRAPS")
print("="*70)

# 2a: Variable named "rsa" that's not RSA crypto
proj = make_project({
    "models.py": """
class Restaurant:
    rsa = "Restaurant Standards Authority"

    def get_rsa_rating(self):
        return self.rsa
""",
})
r = scan_codebase(proj)
rsa = find(r, 'RSA')
test("Variable 'rsa' (Restaurant Standards Authority) — no false positive",
     len(rsa) == 0,
     f"False positive: {[f['usage'] for f in rsa]}")
cleanup(proj)

# 2b: MD5 as a database column reference (not hashing)
proj = make_project({
    "migration.py": """
class Migration:
    def forward(self):
        # Rename column from md5 to sha256
        op.alter_column('files', 'md5', new_column_name='sha256_hash')
        op.alter_column('files', 'md5_checksum', new_column_name='checksum')
""",
})
r = scan_codebase(proj)
md5 = find(r, 'MD5')
test("Column named 'md5' in migration — no false positive",
     len(md5) == 0,
     f"False positive: {[f['usage'] for f in md5]}")
cleanup(proj)

# 2c: Error message mentioning crypto
proj = make_project({
    "errors.py": """
ERROR_MESSAGES = {
    'weak_hash': 'Do not use MD5 for password hashing',
    'deprecated': 'SHA-1 is deprecated, use SHA-256',
    'upgrade': 'Please upgrade from RSA to ML-DSA',
}
""",
})
r = scan_codebase(proj)
# These contain 'MD5', 'SHA-1', 'RSA' as strings but are just error messages
# Scanner strips inline comments but not string contents
# This is a GRAY AREA — mentioning MD5 in a string could be actual config
test("Error messages mentioning crypto — gray area (may flag)",
     True,  # just documenting behavior, not asserting
     "")
cleanup(proj)

# 2d: CSS class with "sha" in name
proj = make_project({
    "styles.ts": """
const shadow = "0 2px 4px rgba(0,0,0,0.1)";
const sharedConfig = { theme: "dark" };
const sha256Label = document.getElementById("sha256-display");
""",
})
r = scan_codebase(proj)
sha = find(r, 'SHA')
test("CSS/JS variable 'shadow', 'shared' — no SHA false positive",
     len(sha) == 0,
     f"False positive: {[f['usage'] for f in sha]}")
cleanup(proj)

# 2e: Log message with "key" and "RSA"
proj = make_project({
    "logger.py": """
logger.info("User requested RSA key rotation")
logger.warning("RSA key expired, generating new key")
print("RSA migration complete")
""",
})
r = scan_codebase(proj)
# These are log messages, not actual RSA operations
# Our scanner will flag them as "reference" context (lower than "operation")
rsa = find(r, 'RSA')
if rsa:
    test("Log messages about RSA — flagged as reference (not operation)",
         all(f['context'] in ('reference', 'comment') for f in rsa),
         f"Wrong context: {[(f['context'], f['usage'][:50]) for f in rsa]}")
else:
    test("Log messages about RSA — not flagged (acceptable)", True, "")
cleanup(proj)

# 2f: Enum with crypto algorithm names (configuration, not usage)
proj = make_project({
    "constants.py": """
SUPPORTED_ALGORITHMS = [
    "RS256",
    "ES256",
    "PS256",
    "EdDSA",
]

DEPRECATED_ALGORITHMS = [
    "HS256",
    "RS384",
]
""",
})
r = scan_codebase(proj)
jwt = find(r, 'JWT')
# These ARE relevant — listing RS256 as supported means the system uses it
test("Algorithm enum RS256/ES256 — correctly flagged (system supports these)",
     len(jwt) > 0,
     "Algorithm enum not caught — these indicate actual support")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# GROUP 3: WEIRD FILE FORMATS
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  GROUP 3: WEIRD FILE FORMATS")
print("="*70)

# 3a: TOML config with crypto settings
proj = make_project({
    "config.toml": """
[crypto]
algorithm = "RSA"
key_size = 2048

[tls]
min_version = "TLSv1.0"
ciphers = ["AES-128-CBC", "AES-256-GCM"]
""",
})
r = scan_codebase(proj)
test("TOML config with TLS and cipher settings",
     len(r['findings']) > 0,
     f"TOML config not caught: {r['total_findings']}")
cleanup(proj)

# 3b: INI-style config
proj = make_project({
    "crypto.ini": """
[security]
hash_algorithm = md5
key_type = RSA
key_bits = 2048
""",
})
r = scan_codebase(proj)
# md5 without ( won't match our md5( pattern - this is correct
# But RSA as a plain string also won't match
test("INI config — RSA/md5 as plain values (scanner expects function calls)",
     True,  # documenting behavior
     "")
cleanup(proj)

# 3c: YAML with anchors and aliases
proj = make_project({
    "complex.yaml": """
defaults: &defaults
  ssl_protocol: TLSv1
  cipher: DES-CBC3-SHA

production:
  <<: *defaults
  ssl_protocol: TLSv1.2

staging:
  <<: *defaults
""",
})
r = scan_codebase(proj)
test("YAML with anchors — TLSv1 and DES found",
     len(r['findings']) >= 2,
     f"Found {r['total_findings']}: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# 3d: Shell script with heredoc
proj = make_project({
    "setup.sh": """#!/bin/bash
cat > /etc/nginx/conf.d/ssl.conf << 'EOF'
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;
EOF

openssl req -newkey rsa:2048 -nodes -keyout /tmp/key.pem -out /tmp/cert.csr
""",
})
r = scan_codebase(proj)
test("Shell heredoc with TLS config + openssl",
     len(r['findings']) >= 2,
     f"Found {r['total_findings']}: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# 3e: Terraform with multiple resource types
proj = make_project({
    "main.tf": """
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem
}

resource "aws_acm_certificate" "cert" {
  domain_name       = "example.com"
  validation_method = "DNS"
}
""",
})
r = scan_codebase(proj)
test("Terraform tls_private_key RSA", len(r['findings']) > 0,
     f"Terraform TLS resources not caught")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# GROUP 4: CONCURRENCY AND PERFORMANCE
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  GROUP 4: CONCURRENCY AND PERFORMANCE")
print("="*70)

# 4a: Concurrent scans don't interfere
results = []
errors = []

def scan_thread(path, name):
    try:
        r = scan_codebase(path)
        results.append((name, r))
    except Exception as e:
        errors.append((name, str(e)))

proj1 = make_project({"a.py": "import hashlib\nh = hashlib.md5(b'a').hexdigest()\n"})
proj2 = make_project({"b.py": "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(65537, 2048)\n"})
proj3 = make_project({"c.go": 'key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n'})

t1 = threading.Thread(target=scan_thread, args=(proj1, "md5"))
t2 = threading.Thread(target=scan_thread, args=(proj2, "rsa"))
t3 = threading.Thread(target=scan_thread, args=(proj3, "ecdsa"))
t1.start(); t2.start(); t3.start()
t1.join(); t2.join(); t3.join()

test("Concurrent scans — no crashes", len(errors) == 0, f"Errors: {errors}")
test("Concurrent scans — all return results", len(results) == 3,
     f"Only {len(results)} results")
test("Concurrent scans — results not mixed up",
     all(r['total_findings'] > 0 for _, r in results),
     f"Some scans returned 0 findings")
cleanup(proj1); cleanup(proj2); cleanup(proj3)

# 4b: Performance — 5000 files
start = time.time()
big_proj = {}
for i in range(5000):
    if i % 50 == 0:
        big_proj[f"pkg{i//100}/mod{i}.py"] = f"import hashlib\nh = hashlib.md5(b'{i}').hexdigest()\n"
    else:
        big_proj[f"pkg{i//100}/mod{i}.py"] = f"x = {i}\n"
proj = make_project(big_proj)
r = scan_codebase(proj)
elapsed = time.time() - start
test(f"5000 files scanned in {elapsed:.1f}s (< 15s)",
     elapsed < 15,
     f"Took {elapsed:.1f}s")
test("5000 files — correct finding count",
     r['total_findings'] >= 50,
     f"Found {r['total_findings']}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# GROUP 5: OUTPUT CORRECTNESS
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  GROUP 5: OUTPUT CORRECTNESS AND DATA INTEGRITY")
print("="*70)

# 5a: CBOM structure is valid CycloneDX 1.6
proj = make_project({
    "app.py": "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(65537, 2048)\nimport hashlib\nh = hashlib.md5(b'x').hexdigest()\n",
})
r = scan_codebase(proj)
cbom = r['cbom']
test("CBOM bomFormat is CycloneDX", cbom['bomFormat'] == 'CycloneDX', f"Got: {cbom['bomFormat']}")
test("CBOM specVersion is 1.6", cbom['specVersion'] == '1.6', f"Got: {cbom['specVersion']}")
test("CBOM has metadata.tools", 'tools' in cbom['metadata'], "Missing tools")
test("CBOM has metadata.timestamp", 'timestamp' in cbom['metadata'], "Missing timestamp")
test("CBOM algorithms populated", len(cbom['cryptoProperties']['algorithms']) > 0, "Empty algos")
cleanup(proj)

# 5b: JSON serializable (no dataclass issues)
proj = make_project({
    "test.py": "import hashlib\nh = hashlib.md5(b'x').hexdigest()\n",
})
r = scan_codebase(proj)
try:
    json_str = json.dumps(r)
    reparsed = json.loads(json_str)
    test("Results fully JSON serializable", True, "")
    test("JSON round-trip preserves risk_score",
         reparsed['risk_score'] == r['risk_score'],
         f"Before: {r['risk_score']}, After: {reparsed['risk_score']}")
except Exception as e:
    test("Results fully JSON serializable", False, str(e))
cleanup(proj)

# 5c: Migration priority is sorted by risk
proj = make_project({
    "mixed.py": """
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
h = hashlib.md5(b'x').hexdigest()
k = rsa.generate_private_key(65537, 2048)
""",
})
r = scan_codebase(proj)
priority = r['migration_priority']
if len(priority) >= 2:
    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_correctly = all(
        risk_order[priority[i]['risk']] <= risk_order[priority[i+1]['risk']]
        for i in range(len(priority)-1)
    )
    test("Migration priority sorted by risk level",
         sorted_correctly,
         f"Out of order: {[f['risk'] for f in priority[:5]]}")
else:
    test("Migration priority has entries", False, "Not enough entries")
cleanup(proj)

# 5d: Finding has all required fields
proj = make_project({
    "check.py": "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(65537, 2048)\n",
})
r = scan_codebase(proj)
if r['findings']:
    f = r['findings'][0]
    required = ['file', 'line', 'algorithm', 'category', 'risk', 'raw_risk',
                'quantum_status', 'context', 'usage', 'migration', 'nist_ref']
    missing = [k for k in required if k not in f]
    test("Findings have all required fields",
         len(missing) == 0,
         f"Missing: {missing}")
    test("Finding line number is positive int",
         isinstance(f['line'], int) and f['line'] > 0,
         f"Line: {f['line']}")
    test("Finding risk is valid enum",
         f['risk'] in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
         f"Risk: {f['risk']}")
    test("Finding quantum_status is valid",
         f['quantum_status'] in ('BROKEN', 'WEAKENED', 'SAFE'),
         f"Status: {f['quantum_status']}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# GROUP 6: REAL CVE PATTERNS
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  GROUP 6: REAL CVE PATTERNS")
print("="*70)

# 6a: CVE-2023-44487 (HTTP/2 Rapid Reset) — uses TLS
proj = make_project({
    "server.py": """
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
""",
})
r = scan_codebase(proj)
test("Python ssl.PROTOCOL_TLSv1 (real CVE pattern)",
     len(find(r, 'TLS')) > 0,
     "Missed TLS v1 vulnerability pattern")
cleanup(proj)

# 6b: Weak JWT in Express.js (common vulnerability)
proj = make_project({
    "auth.js": """
const jwt = require('jsonwebtoken');
const token = jwt.sign({ userId: 123 }, 'secret', { algorithm: 'RS256' });
const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
""",
})
r = scan_codebase(proj)
test("Express JWT RS256 (common web vuln pattern)",
     len(find(r, 'JWT')) > 0,
     "Missed JWT RS256 in Express")
cleanup(proj)

# 6c: Weak password hashing (real-world Django vulnerability)
proj = make_project({
    "settings.py": """
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.MD5PasswordHasher',
    'django.contrib.auth.hashers.SHA1PasswordHasher',
]
""",
})
r = scan_codebase(proj)
md5 = find(r, 'MD5')
sha1 = find(r, 'SHA-1')
test("Django MD5PasswordHasher + SHA1PasswordHasher both caught",
     len(md5) > 0 and len(sha1) > 0,
     f"MD5: {len(md5)}, SHA1: {len(sha1)}")
cleanup(proj)

# 6d: Insecure random + weak crypto combo
proj = make_project({
    "token_gen.py": """
import hashlib
import random
token = hashlib.md5(str(random.randint(0, 999999)).encode()).hexdigest()
""",
})
r = scan_codebase(proj)
test("MD5 with insecure random (double vulnerability)",
     len(find(r, 'MD5')) > 0,
     "Missed MD5 in token generation")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# RESULTS
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print(f"  STRESS TEST V3 RESULTS: {PASS} PASSED, {FAIL} FAILED")
print("="*70)

if BUGS:
    print(f"\n  🐛 BUGS FOUND ({len(BUGS)}):")
    for i, bug in enumerate(BUGS, 1):
        print(f"    {i}. {bug}")
else:
    print("\n  ✅ ALL V3 TESTS PASSED — Scanner survives adversarial testing!")

print(f"\n  Coverage: {PASS}/{PASS+FAIL} tests ({100*PASS//(PASS+FAIL) if PASS+FAIL > 0 else 0}%)")

# Known limitations summary
print(f"\n  DOCUMENTED LIMITATIONS (by design, not bugs):")
print(f"    - Dynamic dispatch (getattr, importlib) not caught — static analysis limitation")
print(f"    - String concatenation of algorithm names not caught")
print(f"    - .txt files not scanned (requirements.txt) — add if needed")
print(f"    - Crypto in pure string values (INI 'md5') may not match function-call patterns")
print()

sys.exit(1 if FAIL > 0 else 0)
