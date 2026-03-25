#!/usr/bin/env python3
"""
PQC Posture — Full Crypto Inventory + Risk Score + Migration Plan + CBOM

This is the REAL product. Not a toy. Scans actual codebases,
generates industry-standard output, scores risk, gives migration paths.
"""

import os
import re
import json
import hashlib
import time
from dataclasses import dataclass, asdict
from typing import List, Dict
from collections import Counter


@dataclass(frozen=True)
class CryptoFinding:
    file: str
    line: int
    algorithm: str
    category: str  # key_exchange, signature, hash, symmetric, protocol
    risk: str  # CRITICAL, HIGH, MEDIUM, LOW
    quantum_status: str  # BROKEN, WEAKENED, SAFE
    usage: str  # what the code is actually doing
    migration: str  # what to replace it with
    nist_ref: str  # NIST standard reference


# Comprehensive crypto detection — not just keywords, ACTUAL USAGE PATTERNS
CRYPTO_PATTERNS = {
    # ═══ KEY EXCHANGE (quantum BREAKS these) ═══
    "RSA Key Exchange": {
        "patterns": [
            r'RSA\.generate',
            r'rsa\.generate_private_key',
            r'PKCS1_OAEP',
            r'PKCS1_v1_5',
            r'RSA_generate_key',
            r'openssl_pkey_new.*RSA',
            r'KeyPairGenerator\.getInstance\("RSA"',
            r'crypto\.generateKeyPairSync\("rsa"',
            r'rsa\.GenerateKey\(',
        ],
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) — NIST FIPS 203",
        "nist_ref": "NIST SP 800-208, FIPS 203",
    },
    "Diffie-Hellman": {
        "patterns": [
            r'DiffieHellman',
            r'dh\.generate_parameters',
            r'DHParameterNumbers',
            r'createDiffieHellman',
            r'KeyAgreement\.getInstance\("DH"',
        ],
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) — NIST FIPS 203",
        "nist_ref": "NIST SP 800-56A",
    },
    "ECDH": {
        "patterns": [
            r'ECDH',
            r'ec\.ECDH\(',
            r'KeyAgreement\.getInstance\("ECDH"',
            r'crypto\.diffieHellman.*curve',
        ],
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) — NIST FIPS 203",
        "nist_ref": "NIST SP 800-56A",
    },

    # ═══ SIGNATURES (quantum BREAKS these) ═══
    "ECDSA": {
        "patterns": [
            r'ECDSA',
            r'ec\.generate_private_key',
            r'ec\.SECP256R1',
            r'ec\.SECP384R1',
            r'ec\.SECP521R1',
            r'ECDSASign',
            r'Signature\.getInstance\(".*ECDSA"',
            r'crypto\.sign.*ec',
            r'ecdsa\.GenerateKey\(',
        ],
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) — NIST FIPS 204",
        "nist_ref": "NIST FIPS 186-5, FIPS 204",
    },
    "RSA Signature": {
        "patterns": [
            r'RSA_sign',
            r'PKCS1v15.*sign',
            r'PSS.*sign',
            r'Signature\.getInstance\(".*RSA"',
            r'crypto\.sign.*rsa',
        ],
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) — NIST FIPS 204",
        "nist_ref": "NIST FIPS 186-5, FIPS 204",
    },
    "DSA": {
        "patterns": [
            r'DSA\.generate',
            r'dsa\.generate_private_key',
            r'KeyPairGenerator\.getInstance\("DSA"',
        ],
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) — NIST FIPS 204",
        "nist_ref": "NIST FIPS 186-5",
    },
    "Ed25519": {
        "patterns": [
            r'Ed25519',
            r'ed25519\.Ed25519PrivateKey',
            r'crypto\.sign.*ed25519',
            r'ed25519\.GenerateKey\(',
        ],
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 44 or FALCON-512 — NIST FIPS 204/205",
        "nist_ref": "NIST FIPS 204",
    },

    # ═══ HASH FUNCTIONS (quantum WEAKENS these) ═══
    "MD5": {
        "patterns": [
            r'hashlib\.md5',
            r'MD5\.new',
            r'MessageDigest\.getInstance\("MD5"',
            r'crypto\.createHash\("md5"',
            r'md5\.New\(\)',
        ],
        "category": "hash",
        "risk": "HIGH",
        "quantum_status": "WEAKENED",
        "migration": "SHA-256 or SHA-3-256 minimum. SHA-384+ recommended.",
        "nist_ref": "NIST SP 800-131A (MD5 deprecated)",
    },
    "SHA-1": {
        "patterns": [
            r'hashlib\.sha1',
            r'SHA\.new',
            r'SHA1\.new',
            r'MessageDigest\.getInstance\("SHA-1"',
            r'crypto\.createHash\("sha1"',
            r'sha1\.New\(\)',
        ],
        "category": "hash",
        "risk": "HIGH",
        "quantum_status": "WEAKENED",
        "migration": "SHA-256 or SHA-3-256 minimum",
        "nist_ref": "NIST SP 800-131A (SHA-1 deprecated)",
    },

    # ═══ SYMMETRIC (quantum resistant but needs bigger keys) ═══
    "DES/3DES": {
        "patterns": [
            r'DES\.new',
            r'DESede',
            r'TripleDES',
            r'DES3\.new',
            r'crypto\.createCipheriv\("des',
        ],
        "category": "symmetric",
        "risk": "HIGH",
        "quantum_status": "WEAKENED",
        "migration": "AES-256-GCM",
        "nist_ref": "NIST SP 800-131A (DES withdrawn)",
    },
    "AES-128": {
        "patterns": [
            r'AES.*128',
            r'aes-128',
            r'AES/CBC/.*128',
        ],
        "category": "symmetric",
        "risk": "MEDIUM",
        "quantum_status": "WEAKENED",
        "migration": "AES-256-GCM (Grover's halves effective key length)",
        "nist_ref": "NIST SP 800-131A",
    },
    "AES-256": {
        "patterns": [
            r'AES.*256',
            r'aes-256',
            r'AES/GCM/.*256',
        ],
        "category": "symmetric",
        "risk": "LOW",
        "quantum_status": "SAFE",
        "migration": "Already quantum-resistant (128-bit effective security with Grover's)",
        "nist_ref": "NIST SP 800-131A",
    },

    # ═══ PROTOCOLS ═══
    "TLS 1.0/1.1": {
        "patterns": [
            r'TLSv1_0',
            r'TLSv1_1',
            r'SSLv3',
            r'ssl\.PROTOCOL_TLSv1\b',
            r'TLS_RSA_WITH',
        ],
        "category": "protocol",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "TLS 1.3 with hybrid PQC key exchange (ML-KEM + X25519)",
        "nist_ref": "NIST SP 800-52 Rev 2",
    },
    "JWT with RSA/ECDSA": {
        "patterns": [
            r'RS256',
            r'RS384',
            r'RS512',
            r'ES256',
            r'ES384',
            r'PS256',
        ],
        "category": "protocol",
        "risk": "HIGH",
        "quantum_status": "BROKEN",
        "migration": "Consider PQC-compatible token signing when libraries support it",
        "nist_ref": "RFC 7518, NIST FIPS 204",
    },
}

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist',
             'build', '.next', '.tox', 'vendor', 'third_party'}
SCAN_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
                   '.rb', '.php', '.cs', '.c', '.cpp', '.h', '.yaml', '.yml',
                   '.toml', '.cfg', '.ini', '.conf'}


def scan_codebase(path: str) -> Dict:
    """Full crypto inventory scan with CBOM output."""
    start = time.time()
    findings = []
    files_scanned = 0
    files_with_crypto = set()
    crypto_libs_found = set()

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCAN_EXTENSIONS:
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'r', errors='ignore') as f:
                    lines = f.readlines()
                files_scanned += 1
            except Exception:
                continue

            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
                    continue

                for algo_name, config in CRYPTO_PATTERNS.items():
                    for pattern in config['patterns']:
                        if re.search(pattern, line):
                            rel_path = os.path.relpath(fpath, path)
                            findings.append(CryptoFinding(
                                file=rel_path,
                                line=i,
                                algorithm=algo_name,
                                category=config['category'],
                                risk=config['risk'],
                                quantum_status=config['quantum_status'],
                                usage=stripped[:120],
                                migration=config['migration'],
                                nist_ref=config['nist_ref'],
                            ))
                            files_with_crypto.add(rel_path)

                # Detect crypto library imports
                for lib_pattern, lib_name in [
                    (r'from cryptography', 'cryptography (Python)'),
                    (r'import crypto', 'crypto (Node.js)'),
                    (r'import javax\.crypto', 'javax.crypto (Java)'),
                    (r'from hashlib', 'hashlib (Python)'),
                    (r'import ssl', 'ssl (Python)'),
                    (r'from OpenSSL', 'pyOpenSSL'),
                    (r'require\("crypto"\)', 'crypto (Node.js)'),
                    (r'import "crypto/', 'crypto (Go)'),
                    (r'use openssl', 'OpenSSL (Rust)'),
                ]:
                    if re.search(lib_pattern, line):
                        crypto_libs_found.add(lib_name)

    elapsed_ms = int((time.time() - start) * 1000)

    # Risk scoring
    risk_counts = Counter(f.risk for f in findings)
    category_counts = Counter(f.category for f in findings)
    algo_counts = Counter(f.algorithm for f in findings)
    status_counts = Counter(f.quantum_status for f in findings)

    # Risk score (0-100, higher = more exposed)
    risk_score = min(100, (
        risk_counts.get('CRITICAL', 0) * 25 +
        risk_counts.get('HIGH', 0) * 10 +
        risk_counts.get('MEDIUM', 0) * 3 +
        risk_counts.get('LOW', 0) * 1
    ))

    # CBOM (Crypto Bill of Materials)
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "tools": [{"name": "PQC Posture Scanner", "version": "0.1.0"}],
            "component": {"name": os.path.basename(path), "type": "application"},
        },
        "cryptoProperties": {
            "algorithms": [
                {
                    "name": algo,
                    "occurrences": count,
                    "quantumSafe": algo_counts.get(algo, '') != 'BROKEN',
                }
                for algo, count in algo_counts.items()
            ],
            "libraries": list(crypto_libs_found),
        },
    }

    return {
        "scan_path": path,
        "files_scanned": files_scanned,
        "files_with_crypto": len(files_with_crypto),
        "total_findings": len(findings),
        "scan_time_ms": elapsed_ms,
        "risk_score": risk_score,
        "risk_level": "CRITICAL" if risk_score >= 50 else "HIGH" if risk_score >= 25 else "MEDIUM" if risk_score >= 10 else "LOW",
        "quantum_exposure": {
            "broken": status_counts.get("BROKEN", 0),
            "weakened": status_counts.get("WEAKENED", 0),
            "safe": status_counts.get("SAFE", 0),
        },
        "by_risk": dict(risk_counts),
        "by_category": dict(category_counts),
        "by_algorithm": dict(algo_counts),
        "crypto_libraries": sorted(crypto_libs_found),
        "findings": [asdict(f) for f in findings],
        "cbom": cbom,
        "migration_priority": [
            asdict(f) for f in sorted(
                findings,
                key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}[x.risk]
            )
        ][:20],
    }


def print_report(result: Dict):
    """Print human-readable posture report."""
    print(f"\n{'='*70}")
    print(f"  PQC POSTURE REPORT — {result['scan_path']}")
    print(f"{'='*70}\n")

    # Risk gauge
    score = result['risk_score']
    level = result['risk_level']
    bar_len = score // 2
    bar = '#' * bar_len + '-' * (50 - bar_len)
    print(f"  QUANTUM RISK SCORE: {score}/100 [{level}]")
    print(f"  [{bar}]")
    print()

    # Summary
    print(f"  Files scanned:       {result['files_scanned']}")
    print(f"  Files with crypto:   {result['files_with_crypto']}")
    print(f"  Total findings:      {result['total_findings']}")
    print(f"  Scan time:           {result['scan_time_ms']}ms")
    print()

    # Quantum exposure
    exp = result['quantum_exposure']
    print(f"  QUANTUM EXPOSURE:")
    print(f"    BROKEN (quantum defeats):    {exp['broken']}")
    print(f"    WEAKENED (quantum degrades): {exp['weakened']}")
    print(f"    SAFE (quantum-resistant):    {exp['safe']}")
    print()

    # By category
    print(f"  BY CATEGORY:")
    for cat, count in sorted(result['by_category'].items()):
        print(f"    {cat:20s} {count}")
    print()

    # Crypto libraries
    if result['crypto_libraries']:
        print(f"  CRYPTO LIBRARIES DETECTED:")
        for lib in result['crypto_libraries']:
            print(f"    - {lib}")
        print()

    # Top findings with migration paths
    print(f"  MIGRATION PRIORITY (top 10):")
    print(f"  {'Risk':10s} {'Algorithm':20s} {'File':30s} {'Migration':30s}")
    print(f"  {'-'*90}")
    seen = set()
    count = 0
    for f in result['migration_priority']:
        key = f"{f['algorithm']}:{f['file']}"
        if key in seen:
            continue
        seen.add(key)
        print(f"  {f['risk']:10s} {f['algorithm']:20s} {f['file'][:30]:30s} {f['migration'][:30]}")
        count += 1
        if count >= 10:
            break

    # CBOM summary
    print(f"\n  CBOM (Crypto Bill of Materials):")
    print(f"    Format: CycloneDX 1.6")
    print(f"    Algorithms found: {len(result['cbom']['cryptoProperties']['algorithms'])}")
    print(f"    Libraries found:  {len(result['cbom']['cryptoProperties']['libraries'])}")

    print(f"\n{'='*70}")
    if score >= 50:
        print(f"  VERDICT: CRITICAL quantum exposure. Migration urgently recommended.")
    elif score >= 25:
        print(f"  VERDICT: HIGH quantum exposure. Plan migration within 6 months.")
    elif score >= 10:
        print(f"  VERDICT: MODERATE exposure. Monitor and plan for PQC transition.")
    else:
        print(f"  VERDICT: LOW exposure. Continue monitoring.")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    import sys

    targets = [
        ("/root/openclaw", "OpenClaw Gateway"),
        ("/root/ai-factory", "AI Factory"),
        ("/root/quantum-mcp", "Quantum MCP"),
        ("/root/codeguard-mcp", "CodeGuard Pro"),
        ("/root/polymarket-mcp", "Polymarket MCP"),
    ]

    print("\n" + "="*70)
    print("  PQC POSTURE — FULL INFRASTRUCTURE AUDIT")
    print("  Scanning Miles's entire stack for quantum vulnerabilities")
    print("="*70)

    all_results = []
    for path, name in targets:
        if os.path.isdir(path):
            print(f"\n  Scanning {name}...")
            result = scan_codebase(path)
            all_results.append((name, result))
            print_report(result)

            # Save CBOM to file
            cbom_path = os.path.join(path, "CBOM.json")
            with open(cbom_path, 'w') as f:
                json.dump(result['cbom'], f, indent=2)

    # Summary across all projects
    print("\n" + "="*70)
    print("  INFRASTRUCTURE-WIDE SUMMARY")
    print("="*70 + "\n")

    total_findings = sum(r['total_findings'] for _, r in all_results)
    total_broken = sum(r['quantum_exposure']['broken'] for _, r in all_results)
    total_files = sum(r['files_scanned'] for _, r in all_results)

    print(f"  {'Project':25s} {'Risk Score':12s} {'Findings':10s} {'Broken':8s} {'Status'}")
    print(f"  {'-'*80}")
    for name, r in all_results:
        status = "MIGRATE NOW" if r['risk_score'] >= 50 else "PLAN" if r['risk_score'] >= 25 else "MONITOR" if r['risk_score'] >= 10 else "OK"
        print(f"  {name:25s} {r['risk_score']:>5}/100     {r['total_findings']:>5}      {r['quantum_exposure']['broken']:>4}    {status}")

    print(f"\n  TOTAL: {total_files} files, {total_findings} findings, {total_broken} quantum-broken")
    print(f"  CBOM files generated in each project directory")
