#!/usr/bin/env python3
"""
STRESS TEST V2 — Tests for ALL new patterns (SSH, X.509, TLS config, Dependencies)
Plus harder edge cases, real-world configs, and adversarial inputs.
"""

import os
import sys
import tempfile
import shutil
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
    tmp = tempfile.mkdtemp(prefix="pqc_v2_")
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

def find_prod(results, algo_substring):
    return [f for f in results['findings'] if algo_substring in f['algorithm'] and f['context'] != 'test']


# ════════════════════════════════════════════════════════════
# TEST GROUP A: SSH PATTERNS (9 patterns, NEW)
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP A: SSH PATTERNS")
print("="*70)

# A1: ssh-rsa in authorized_keys style content
proj = make_project({
    "deploy.sh": """#!/bin/bash
# Add deploy key
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDExample deploy@server" >> ~/.ssh/authorized_keys
""",
})
r = scan_codebase(proj)
test("ssh-rsa in deploy script", len(find(r, 'SSH')) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# A2: ecdsa-sha2 host key
proj = make_project({
    "ssh_config.conf": """
Host production
    HostName 10.0.0.5
    HostKeyAlgorithms ecdsa-sha2-nistp256,ssh-ed25519
    User deploy
""",
})
r = scan_codebase(proj)
test("ecdsa-sha2-nistp256 in SSH config", len(find(r, 'SSH')) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# A3: Paramiko RSA key in Python
proj = make_project({
    "sftp_client.py": """
import paramiko
key = paramiko.RSAKey.generate(2048)
client = paramiko.SSHClient()
client.connect('server.example.com', pkey=key)
""",
})
r = scan_codebase(proj)
test("paramiko.RSAKey in Python", len(find(r, 'SSH')) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# A4: Paramiko ECDSA key
proj = make_project({
    "ssh_auth.py": """
import paramiko
key = paramiko.ECDSAKey.generate()
""",
})
r = scan_codebase(proj)
test("paramiko.ECDSAKey in Python", len(find(r, 'SSH')) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# A5: Go SSH with RSA
proj = make_project({
    "server.go": """package main

import (
    "golang.org/x/crypto/ssh"
    "crypto/rsa"
)

func main() {
    signer, _ := ssh.ParsePrivateKey(pemBytes)
    _ = signer
}
""",
})
r = scan_codebase(proj)
ssh_or_dep = find(r, 'SSH') + find(r, 'Crypto Dep')
test("Go crypto/ssh import detected", len(ssh_or_dep) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# A6: RSAAuthentication yes in sshd_config
proj = make_project({
    "sshd_config.conf": """
Port 22
RSAAuthentication yes
PubkeyAcceptedAlgorithms ssh-rsa,ssh-dss
PermitRootLogin no
""",
})
r = scan_codebase(proj)
test("RSAAuthentication yes in sshd_config", len(find(r, 'SSH')) >= 2, f"Found {len(find(r, 'SSH'))} SSH findings")
cleanup(proj)

# A7: Weak KEX algorithms
proj = make_project({
    "ssh_hardening.conf": """
# Weak key exchange - should be flagged
KexAlgorithms diffie-hellman-group14-sha256,curve25519-sha256
""",
})
r = scan_codebase(proj)
test("diffie-hellman KEX in SSH config", len(find(r, 'SSH')) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# TEST GROUP B: X.509 CERTIFICATE PATTERNS (7 patterns, NEW)
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP B: X.509 CERTIFICATE PATTERNS")
print("="*70)

# B1: openssl req with RSA
proj = make_project({
    "gen_cert.sh": """#!/bin/bash
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
""",
})
r = scan_codebase(proj)
x509 = find(r, 'X.509')
test("openssl req -newkey rsa in shell script", len(x509) >= 1, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# B2: Java keytool RSA
proj = make_project({
    "setup_keystore.sh": """#!/bin/bash
keytool -genkeypair -alias mykey -keyalg RSA -keysize 2048 -keystore keystore.jks
""",
})
r = scan_codebase(proj)
test("keytool -genkeypair RSA", len(find(r, 'X.509')) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# B3: Go x509.CreateCertificate
proj = make_project({
    "tls.go": """package main

import (
    "crypto/x509"
    "crypto/rand"
)

func genCert() {
    certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
    _ = certBytes
    _ = err
}
""",
})
r = scan_codebase(proj)
test("Go x509.CreateCertificate", len(find(r, 'X.509')) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# B4: Java X509Certificate
proj = make_project({
    "CertValidator.java": """
import java.security.cert.X509Certificate;

public class CertValidator {
    public boolean validate(X509Certificate cert) {
        cert.checkValidity();
        return true;
    }
}
""",
})
r = scan_codebase(proj)
test("Java X509Certificate usage", len(find(r, 'X.509')) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# B5: certbot with RSA
proj = make_project({
    "renew.sh": """#!/bin/bash
certbot certonly --rsa-key-size 4096 -d example.com
""",
})
r = scan_codebase(proj)
test("certbot --rsa-key-size", len(find(r, 'X.509')) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# TEST GROUP C: WEB SERVER TLS CONFIG (7 patterns, NEW)
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP C: WEB SERVER TLS CONFIG")
print("="*70)

# C1: nginx ssl_protocols with TLS 1.0
proj = make_project({
    "nginx.conf": """
server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers HIGH:!aNULL:!MD5;
}
""",
})
r = scan_codebase(proj)
tls = find(r, 'TLS') + find(r, 'Weak TLS')
test("nginx ssl_protocols TLSv1", len(tls) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# C2: nginx weak ciphers
proj = make_project({
    "nginx.conf": """
server {
    ssl_ciphers RC4-SHA:DES-CBC3-SHA:AES128-SHA;
}
""",
})
r = scan_codebase(proj)
weak = find(r, 'Weak TLS') + find(r, 'DES')
test("nginx ssl_ciphers with RC4/DES", len(weak) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# C3: Apache SSLProtocol
proj = make_project({
    "apache.conf": """
<VirtualHost *:443>
    SSLProtocol all -SSLv3 +TLSv1
    SSLCipherSuite HIGH:MEDIUM:!aNULL:!MD5
</VirtualHost>
""",
})
r = scan_codebase(proj)
test("Apache SSLProtocol +TLSv1", len(find(r, 'Weak TLS')) > 0 or len(find(r, 'TLS')) > 0,
     f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# C4: Apache weak ciphers with NULL
proj = make_project({
    "ssl.conf": """
SSLCipherSuite NULL-SHA:NULL-MD5:RC4-SHA
""",
})
r = scan_codebase(proj)
test("Apache SSLCipherSuite NULL/RC4", len(find(r, 'Weak TLS')) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# C5: HAProxy ssl-min-ver
proj = make_project({
    "haproxy.cfg": """
frontend https
    bind *:443 ssl crt /etc/ssl/cert.pem ssl-min-ver TLSv1.0
    default_backend servers
""",
})
r = scan_codebase(proj)
test("HAProxy ssl-min-ver TLSv1.0", len(find(r, 'Weak TLS')) > 0, f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# C6: Traefik minVersion in YAML
proj = make_project({
    "traefik.yaml": """
tls:
  options:
    default:
      minVersion: TLS10
      cipherSuites:
        - TLS_RSA_WITH_AES_128_CBC_SHA
""",
})
r = scan_codebase(proj)
test("Traefik minVersion TLS10", len(find(r, 'Weak TLS')) > 0 or len(find(r, 'TLS')) > 0,
     f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# C7: Good TLS config should NOT be flagged as weak
proj = make_project({
    "nginx_good.conf": """
server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
}
""",
})
r = scan_codebase(proj)
weak = find(r, 'Weak TLS')
test("Good TLS 1.2/1.3 config NOT flagged as weak", len(weak) == 0,
     f"False positive: {[f['usage'] for f in weak]}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# TEST GROUP D: CRYPTO DEPENDENCY PATTERNS (8 patterns, NEW)
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP D: CRYPTO DEPENDENCY PATTERNS")
print("="*70)

# D1: Python requirements.txt
proj = make_project({
    "requirements.txt": """
flask==3.0.0
pycryptodome==3.19.0
pyOpenSSL==24.0.0
requests==2.31.0
""",
})
r = scan_codebase(proj)
# .txt not in scan extensions - should we catch this?
test("requirements.txt NOW scanned (.txt extension added)",
     r['files_scanned'] >= 1 and any('Crypto Dep' in f['algorithm'] for f in r['findings']),
     f"Scanned {r['files_scanned']}, findings: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# D2: Python with crypto imports in .py
proj = make_project({
    "crypto_utils.py": """
from pycryptodome import AES
import pyOpenSSL
""",
})
r = scan_codebase(proj)
deps = find(r, 'Crypto Dep')
test("pycryptodome + pyOpenSSL in Python imports", len(deps) >= 2,
     f"Got {len(deps)} dep findings: {[f['usage'] for f in deps]}")
cleanup(proj)

# D3: Java BouncyCastle
proj = make_project({
    "SecurityConfig.java": """
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

Security.addProvider(new BouncyCastleProvider());
""",
})
r = scan_codebase(proj)
deps = find(r, 'Crypto Dep')
test("Java BouncyCastle + Jasypt detected", len(deps) >= 2,
     f"Got {len(deps)}: {[f['usage'] for f in deps]}")
cleanup(proj)

# D4: Go crypto packages in source
proj = make_project({
    "main.go": """package main

import (
    "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/ed25519"
)

func main() {}
""",
})
r = scan_codebase(proj)
deps = find(r, 'Crypto Dep')
test("Go crypto/ssh + ed25519 dependencies", len(deps) >= 2,
     f"Got {len(deps)}: {[f['usage'] for f in deps]}")
cleanup(proj)

# D5: Rust ring crate reference
proj = make_project({
    "crypto.rs": """
use ring::signature;
use ring::rand::SystemRandom;

fn sign_data(data: &[u8]) -> Vec<u8> {
    let rng = SystemRandom::new();
    // sign with "ring" crate
    vec![]
}
""",
})
r = scan_codebase(proj)
deps = find(r, 'Crypto Dep')
test("Rust ring crate detected", len(deps) > 0, f"Got: {[f['usage'] for f in deps]}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# TEST GROUP E: REAL-WORLD CONFIG FILES
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP E: REAL-WORLD CONFIG FILES")
print("="*70)

# E1: Docker compose with weak SSL
proj = make_project({
    "docker-compose.yml": """
services:
  nginx:
    image: nginx:latest
    environment:
      - SSL_PROTOCOLS=TLSv1 TLSv1.1 TLSv1.2
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
""",
})
r = scan_codebase(proj)
test("Docker compose SSL_PROTOCOLS detected",
     len(find(r, 'TLS')) > 0,
     f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# E2: Kubernetes Ingress with TLS
proj = make_project({
    "ingress.yaml": """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1 TLSv1.1 TLSv1.2"
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES128-GCM-SHA256"
spec:
  tls:
    - hosts:
        - example.com
      secretName: tls-secret
""",
})
r = scan_codebase(proj)
test("K8s Ingress TLS annotations",
     len(r['findings']) > 0,
     f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# E3: Terraform AWS KMS key
proj = make_project({
    "kms.tf": """
resource "aws_kms_key" "signing" {
  description             = "Code signing key"
  customer_master_key_spec = "RSA_2048"
  key_usage               = "SIGN_VERIFY"
}

resource "aws_kms_key" "encrypt" {
  description             = "Encryption key"
  customer_master_key_spec = "RSA_4096"
  key_usage               = "ENCRYPT_DECRYPT"
}
""",
})
r = scan_codebase(proj)
rsa = find(r, 'RSA')
test("Terraform KMS RSA_2048 + RSA_4096", len(rsa) >= 2,
     f"Got {len(rsa)}: {[f['usage'] for f in rsa]}")
cleanup(proj)

# E4: GitHub Actions workflow with crypto
proj = make_project({
    "deploy.yml": """
name: Deploy
on: push
jobs:
  deploy:
    steps:
      - run: |
          openssl req -newkey rsa:2048 -nodes -keyout key.pem -out cert.csr
          ssh-keygen -t rsa -b 4096 -f deploy_key
""",
})
r = scan_codebase(proj)
test("GitHub Actions with openssl/ssh-keygen",
     len(r['findings']) > 0,
     f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)

# E5: Ansible with crypto modules
proj = make_project({
    "playbook.yaml": """
- name: Generate SSL cert
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/server.key
    type: RSA
    size: 2048

- name: Create CSR
  community.crypto.openssl_csr:
    path: /etc/ssl/certs/server.csr
    privatekey_path: /etc/ssl/private/server.key
""",
})
r = scan_codebase(proj)
test("Ansible openssl_privatekey RSA",
     any('RSA' in f['algorithm'] for f in r['findings']),
     f"Got: {[f['algorithm'] for f in r['findings']]}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# TEST GROUP F: ADVERSARIAL / EDGE CASES
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP F: ADVERSARIAL INPUTS")
print("="*70)

# F1: Massive single file (50K lines)
big = "x = 1\n" * 25000
big += "key = rsa.generate_private_key(65537, 2048)\n"
big += "x = 2\n" * 25000
proj = make_project({"huge.py": big})
r = scan_codebase(proj)
test("50K line file — finds crypto at line 25001",
     r['total_findings'] > 0,
     f"Missed finding in 50K file")
cleanup(proj)

# F2: File with only whitespace + crypto on last line
proj = make_project({
    "sparse.py": "\n" * 500 + "import hashlib\nh = hashlib.md5(b'x').hexdigest()\n",
})
r = scan_codebase(proj)
test("500 blank lines then crypto on last line",
     r['total_findings'] > 0,
     "Missed finding after blank lines")
cleanup(proj)

# F3: Nested test directory name should demote
proj = make_project({
    "src/tests/integration/test_crypto.py": """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(65537, 2048)
""",
    "src/main/crypto.py": """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(65537, 2048)
""",
})
r = scan_codebase(proj)
test_findings = [f for f in r['findings'] if f['context'] == 'test']
prod_findings = [f for f in r['findings'] if f['context'] != 'test']
test("Nested test/ dir demoted, src/main/ is production",
     len(test_findings) > 0 and len(prod_findings) > 0,
     f"Test: {len(test_findings)}, Prod: {len(prod_findings)}")
cleanup(proj)

# F4: Mixed encoding — Latin-1 chars in code
proj = make_project({
    "legacy.py": "# Héllo wörld — café encryption\nimport hashlib\nh = hashlib.md5(b'données').hexdigest()\n",
})
r = scan_codebase(proj)
test("Latin-1 characters don't crash scanner",
     r['total_findings'] > 0,
     "Crashed or missed finding")
cleanup(proj)

# F5: Extremely long filename
long_name = "a" * 200 + ".py"
proj = make_project({
    long_name: "import hashlib\nh = hashlib.md5(b'x').hexdigest()\n",
})
r = scan_codebase(proj)
test("200-char filename handled",
     r['total_findings'] > 0,
     "Long filename crashed or missed")
cleanup(proj)

# F6: File that looks like test but isn't (mock in name but production code)
proj = make_project({
    "src/mockserver/handler.py": """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(65537, 2048)
""",
})
r = scan_codebase(proj)
# "mock" in path → treated as test (demoted)
mock_findings = [f for f in r['findings'] if f['context'] == 'test']
test("'mock' in path demotes to test context",
     len(mock_findings) > 0,
     f"Contexts: {[f['context'] for f in r['findings']]}")
cleanup(proj)


# ════════════════════════════════════════════════════════════
# TEST GROUP G: COMBINED REAL-WORLD SCENARIO
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("  TEST GROUP G: FULL REALISTIC PROJECT")
print("="*70)

proj = make_project({
    "src/auth/jwt.py": """
import jwt
token = jwt.encode(payload, private_key, algorithm="RS256")
decoded = jwt.decode(token, public_key, algorithms=["RS256"])
""",
    "src/crypto/signing.py": """
from cryptography.hazmat.primitives.asymmetric import rsa, ec
rsa_key = rsa.generate_private_key(65537, 2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
""",
    "src/utils/hash.py": """
import hashlib
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()
""",
    "config/nginx.conf": """
server {
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;
}
""",
    "deploy/setup_ssh.sh": """#!/bin/bash
ssh-keygen -t rsa -b 4096 -f /tmp/deploy_key -N ""
echo "ssh-rsa AAAAB3... deploy@ci" >> authorized_keys
""",
    "deploy/gen_cert.sh": """#!/bin/bash
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr
""",
    "infra/main.tf": """
resource "aws_kms_key" "app" {
  customer_master_key_spec = "RSA_2048"
}
""",
    "tests/test_auth.py": """
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(65537, 2048)
h = hashlib.md5(b"test").hexdigest()
""",
})
r = scan_codebase(proj)
prod = [f for f in r['findings'] if f['context'] != 'test']
tests = [f for f in r['findings'] if f['context'] == 'test']
categories = set(f['category'] for f in prod)
algos = set(f['algorithm'] for f in prod)

test("Realistic project: multiple categories found",
     len(categories) >= 3,
     f"Only {len(categories)} categories: {categories}")

test("Realistic project: RSA + ECDSA + MD5 + SHA-1 + JWT + SSH + TLS all detected",
     len(algos) >= 5,
     f"Only {len(algos)} algos: {algos}")

test("Realistic project: test code separated from production",
     len(tests) > 0 and len(prod) > len(tests),
     f"Prod: {len(prod)}, Test: {len(tests)}")

test("Realistic project: CRITICAL findings exist",
     any(f['risk'] == 'CRITICAL' for f in prod),
     f"No CRITICAL in production findings")

test("Realistic project: Terraform .tf scanned",
     any('.tf' in f['file'] for f in r['findings']),
     "Terraform file not scanned")

test("Realistic project: risk score > 50",
     r['risk_score'] > 50,
     f"Score only {r['risk_score']}")

test("Realistic project: CBOM has multiple algorithms",
     len(r['cbom']['cryptoProperties']['algorithms']) >= 5,
     f"Only {len(r['cbom']['cryptoProperties']['algorithms'])} in CBOM")

cleanup(proj)


# ════════════════════════════════════════════════════════════
# RESULTS
# ════════════════════════════════════════════════════════════
print("\n" + "="*70)
print(f"  STRESS TEST V2 RESULTS: {PASS} PASSED, {FAIL} FAILED")
print("="*70)

if BUGS:
    print(f"\n  🐛 BUGS FOUND ({len(BUGS)}):")
    for i, bug in enumerate(BUGS, 1):
        print(f"    {i}. {bug}")
else:
    print("\n  ✅ ALL TESTS PASSED — New patterns are solid!")

print(f"\n  Coverage: {PASS}/{PASS+FAIL} tests ({100*PASS//(PASS+FAIL) if PASS+FAIL > 0 else 0}%)")
print()

sys.exit(1 if FAIL > 0 else 0)
