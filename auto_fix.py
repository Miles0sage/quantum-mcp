#!/usr/bin/env python3
"""
PQC Auto-Fix Migration Engine — pattern-based, zero API calls.

When the scanner finds quantum-vulnerable crypto, this engine generates
migration code automatically. Drop-in replacements for common patterns,
refactor suggestions for complex cases, manual review flags for the rest.

This is the feature NOBODY else has.
"""

import os
import re
import difflib
from typing import List, Dict, Optional


# ═══════════════════════════════════════════════════════════════════════
# Migration Rules — ordered by confidence
# ═══════════════════════════════════════════════════════════════════════

# Each rule: (regex_pattern, replacement_func_or_string, confidence, migration_type, explanation)
# replacement can be a string or a callable(match, full_line) -> str

DROP_IN_RULES: List[Dict] = [
    # ── Hash upgrades (confidence 0.95) ──
    {
        "id": "md5-call",
        "pattern": r'hashlib\.md5\b',
        "replacement": "hashlib.sha256",
        "confidence": 0.95,
        "migration_type": "drop-in",
        "explanation": "MD5 is broken (collisions trivial). SHA-256 is quantum-resistant for hashing.",
        "imports_needed": [],
    },
    {
        "id": "sha1-call",
        "pattern": r'hashlib\.sha1\b',
        "replacement": "hashlib.sha256",
        "confidence": 0.95,
        "migration_type": "drop-in",
        "explanation": "SHA-1 is broken (SHAttered attack, 2017). SHA-256 is quantum-resistant for hashing.",
        "imports_needed": [],
    },
    {
        "id": "md5-new",
        "pattern": r'hashlib\.new\(\s*["\']md5["\']\s*\)',
        "replacement": 'hashlib.new("sha256")',
        "confidence": 0.95,
        "migration_type": "drop-in",
        "explanation": "MD5 is broken. Replacing with SHA-256 via hashlib.new().",
        "imports_needed": [],
    },
    {
        "id": "sha1-new",
        "pattern": r'hashlib\.new\(\s*["\']sha1["\']\s*\)',
        "replacement": 'hashlib.new("sha256")',
        "confidence": 0.95,
        "migration_type": "drop-in",
        "explanation": "SHA-1 is broken. Replacing with SHA-256 via hashlib.new().",
        "imports_needed": [],
    },
    # ── JWT algorithm upgrades (confidence 0.9) ──
    {
        "id": "jwt-rs256",
        "pattern": r'algorithm\s*=\s*["\']RS256["\']',
        "replacement": 'algorithm="EdDSA"',
        "confidence": 0.9,
        "migration_type": "drop-in",
        "explanation": "RS256 (RSA) is quantum-vulnerable. EdDSA is the interim upgrade until PQC JWT standards exist.",
        "imports_needed": [],
    },
    {
        "id": "jwt-es256",
        "pattern": r'algorithm\s*=\s*["\']ES256["\']',
        "replacement": 'algorithm="EdDSA"',
        "confidence": 0.9,
        "migration_type": "drop-in",
        "explanation": "ES256 (ECDSA) is quantum-vulnerable. EdDSA is the interim upgrade until PQC JWT standards exist.",
        "imports_needed": [],
    },
    # ── TLS protocol upgrades (confidence 0.9) ──
    {
        "id": "tls-v1",
        "pattern": r'ssl\.PROTOCOL_TLSv1\b',
        "replacement": "ssl.PROTOCOL_TLS_CLIENT",
        "confidence": 0.9,
        "migration_type": "drop-in",
        "explanation": "TLSv1 is deprecated and insecure. PROTOCOL_TLS_CLIENT enforces TLS 1.2+ with hostname verification.",
        "imports_needed": [],
    },
    {
        "id": "tls-v1_1",
        "pattern": r'ssl\.PROTOCOL_TLSv1_1\b',
        "replacement": "ssl.PROTOCOL_TLS_CLIENT",
        "confidence": 0.9,
        "migration_type": "drop-in",
        "explanation": "TLSv1.1 is deprecated. PROTOCOL_TLS_CLIENT enforces TLS 1.2+ with hostname verification.",
        "imports_needed": [],
    },
    {
        "id": "tls-v1_2",
        "pattern": r'ssl\.PROTOCOL_TLSv1_2\b',
        "replacement": "ssl.PROTOCOL_TLS_CLIENT",
        "confidence": 0.85,
        "migration_type": "drop-in",
        "explanation": "TLSv1.2 explicit pinning prevents negotiation to TLS 1.3. PROTOCOL_TLS_CLIENT allows 1.2+ negotiation.",
        "imports_needed": [],
    },
    # ── Django password hashers (confidence 0.9) ──
    {
        "id": "django-md5",
        "pattern": r'MD5PasswordHasher',
        "replacement": "PBKDF2PasswordHasher",
        "confidence": 0.9,
        "migration_type": "drop-in",
        "explanation": "MD5PasswordHasher is cryptographically broken. PBKDF2PasswordHasher is Django's recommended default.",
        "imports_needed": [],
    },
    {
        "id": "django-sha1",
        "pattern": r'SHA1PasswordHasher',
        "replacement": "PBKDF2PasswordHasher",
        "confidence": 0.9,
        "migration_type": "drop-in",
        "explanation": "SHA1PasswordHasher is cryptographically broken. PBKDF2PasswordHasher is Django's recommended default.",
        "imports_needed": [],
    },
]

REFACTOR_RULES: List[Dict] = [
    # ── RSA key generation (confidence 0.6) ──
    {
        "id": "rsa-keygen",
        "pattern": r'rsa\.generate_private_key\s*\(\s*\d+\s*,\s*\d+',
        "confidence": 0.6,
        "migration_type": "refactor",
        "explanation": (
            "RSA key generation is quantum-vulnerable (Shor's algorithm). "
            "Migration path: Replace with ML-KEM (CRYSTALS-Kyber) for key exchange "
            "or ML-DSA (CRYSTALS-Dilithium) for signing. "
            "See NIST FIPS 203/204. Library: oqs-python (liboqs)."
        ),
        "comment": (
            "# PQC-MIGRATION: Replace RSA with ML-KEM (FIPS 203) for key exchange\n"
            "# or ML-DSA (FIPS 204) for signing. Install: pip install oqs\n"
            "# See: https://github.com/open-quantum-safe/liboqs-python"
        ),
    },
    {
        "id": "rsa-keygen-cryptography",
        "pattern": r'rsa\.generate_private_key\s*\(\s*public_exponent\s*=\s*\d+',
        "confidence": 0.6,
        "migration_type": "refactor",
        "explanation": (
            "RSA key generation (cryptography library) is quantum-vulnerable. "
            "Migration path: ML-KEM 768 for key exchange, ML-DSA 65 for signing."
        ),
        "comment": (
            "# PQC-MIGRATION: Replace RSA with ML-KEM (FIPS 203) for key exchange\n"
            "# or ML-DSA (FIPS 204) for signing. Install: pip install oqs\n"
            "# See: https://github.com/open-quantum-safe/liboqs-python"
        ),
    },
    # ── EC key generation (confidence 0.6) ──
    {
        "id": "ec-keygen-secp256r1",
        "pattern": r'ec\.generate_private_key\s*\(\s*(?:ec\.)?SECP256R1\s*\(',
        "confidence": 0.6,
        "migration_type": "refactor",
        "explanation": (
            "ECDSA/ECDH with SECP256R1 is quantum-vulnerable (Shor's algorithm). "
            "Migration path: ML-DSA 65 (CRYSTALS-Dilithium) for signing, "
            "ML-KEM 768 (CRYSTALS-Kyber) for key exchange. See NIST FIPS 204/203."
        ),
        "comment": (
            "# PQC-MIGRATION: Replace ECDSA/ECDH with ML-DSA (FIPS 204) for signing\n"
            "# or ML-KEM (FIPS 203) for key exchange. Install: pip install oqs\n"
            "# See: https://github.com/open-quantum-safe/liboqs-python"
        ),
    },
    {
        "id": "ec-keygen-generic",
        "pattern": r'ec\.generate_private_key\s*\(',
        "confidence": 0.5,
        "migration_type": "refactor",
        "explanation": (
            "Elliptic curve key generation is quantum-vulnerable. "
            "Migration: ML-DSA (signing) or ML-KEM (key exchange)."
        ),
        "comment": (
            "# PQC-MIGRATION: Replace EC with ML-DSA (FIPS 204) for signing\n"
            "# or ML-KEM (FIPS 203) for key exchange. Install: pip install oqs"
        ),
    },
    # ── Go ECDSA (confidence 0.5) ──
    {
        "id": "go-ecdsa",
        "pattern": r'ecdsa\.GenerateKey\s*\(\s*elliptic\.P256\s*\(\s*\)',
        "confidence": 0.5,
        "migration_type": "refactor",
        "explanation": (
            "Go ECDSA P-256 is quantum-vulnerable. "
            "Migration: circl library (Cloudflare) for ML-DSA, or liboqs Go bindings."
        ),
        "comment": (
            "// PQC-MIGRATION: Replace ECDSA P-256 with ML-DSA (FIPS 204)\n"
            "// See: https://github.com/cloudflare/circl"
        ),
    },
]

MANUAL_PATTERNS: List[Dict] = [
    {
        "id": "multi-file-crypto",
        "keywords": ["CryptoProvider", "KeyManager", "CertificateFactory", "KeyStore"],
        "confidence": 0.3,
        "migration_type": "manual",
        "explanation": (
            "MANUAL REVIEW: Complex crypto infrastructure detected. "
            "Multi-file refactoring likely required. Audit the full crypto stack "
            "and plan a phased migration to PQC algorithms."
        ),
    },
]


def generate_fix(finding: dict, source_lines: List[str]) -> dict:
    """Generate a migration fix for a quantum-vulnerable crypto finding.

    Args:
        finding: A finding dict from scan_codebase() output (CryptoFinding as dict).
        source_lines: All lines of the source file (0-indexed list of strings).

    Returns:
        {
            "original_line": str,
            "fixed_line": str,
            "explanation": str,
            "imports_needed": List[str],
            "confidence": float,  # 0.0-1.0
            "migration_type": str,  # "drop-in", "refactor", "manual"
        }
    """
    line_num = finding.get("line", 0)
    if line_num < 1 or line_num > len(source_lines):
        return _manual_fix(finding, "")

    original_line = source_lines[line_num - 1]
    stripped = original_line.rstrip("\n")

    # Try drop-in rules first (highest confidence)
    for rule in DROP_IN_RULES:
        match = re.search(rule["pattern"], stripped)
        if match:
            fixed = re.sub(rule["pattern"], rule["replacement"], stripped)
            # Add PQC migration comment
            indent = _get_indent(original_line)
            comment = f"{indent}# PQC-FIX: {rule['explanation']}\n"
            fixed_line = comment + fixed + "\n"
            return {
                "original_line": original_line,
                "fixed_line": fixed_line,
                "explanation": rule["explanation"],
                "imports_needed": list(rule.get("imports_needed", [])),
                "confidence": rule["confidence"],
                "migration_type": rule["migration_type"],
            }

    # Try refactor rules (medium confidence)
    for rule in REFACTOR_RULES:
        match = re.search(rule["pattern"], stripped)
        if match:
            indent = _get_indent(original_line)
            comment_lines = rule["comment"].replace("\n", f"\n{indent}")
            fixed_line = f"{indent}{comment_lines}\n{original_line}"
            return {
                "original_line": original_line,
                "fixed_line": fixed_line,
                "explanation": rule["explanation"],
                "imports_needed": [],
                "confidence": rule["confidence"],
                "migration_type": rule["migration_type"],
            }

    # Fall through to manual review
    return _manual_fix(finding, original_line)


def _manual_fix(finding: dict, original_line: str) -> dict:
    """Generate a manual review placeholder fix."""
    algo = finding.get("algorithm", "unknown")
    migration = finding.get("migration", "See NIST PQC standards")
    explanation = (
        f"MANUAL REVIEW: {algo} usage detected. "
        f"Automated fix not available for this pattern. "
        f"Recommended migration: {migration}"
    )
    indent = _get_indent(original_line) if original_line else ""
    comment = f"{indent}# PQC-TODO: {explanation}\n"
    fixed_line = comment + original_line if original_line else comment
    return {
        "original_line": original_line,
        "fixed_line": fixed_line,
        "explanation": explanation,
        "imports_needed": [],
        "confidence": 0.3,
        "migration_type": "manual",
    }


def _get_indent(line: str) -> str:
    """Extract leading whitespace from a line."""
    return line[: len(line) - len(line.lstrip())]


def generate_fixes(scan_result: dict, source_dir: str) -> dict:
    """Generate fixes for all findings in a scan result.

    Args:
        scan_result: Output from scan_codebase() or JSON equivalent.
        source_dir: Root directory of the scanned source code.

    Returns:
        {
            "total_findings": int,
            "auto_fixable": int,
            "fixes": [...],
            "patch": str,  # unified diff format
        }
    """
    findings = scan_result.get("findings", [])

    # Group findings by file
    by_file: Dict[str, List[dict]] = {}
    for f in findings:
        rel_path = f.get("file", "")
        if rel_path not in by_file:
            by_file[rel_path] = []
        by_file[rel_path].append(f)

    all_fixes = []
    auto_fixable = 0
    patch_parts = []

    for rel_path, file_findings in sorted(by_file.items()):
        abs_path = os.path.join(source_dir, rel_path)
        try:
            with open(abs_path, "r", errors="ignore") as fh:
                source_lines = fh.readlines()
        except (OSError, IOError):
            continue

        file_fixes = []
        for finding in sorted(file_findings, key=lambda x: x.get("line", 0)):
            fix = generate_fix(finding, source_lines)
            fix["file"] = rel_path
            fix["line"] = finding.get("line", 0)
            fix["algorithm"] = finding.get("algorithm", "")
            fix["risk"] = finding.get("risk", "")
            file_fixes.append(fix)
            if fix["migration_type"] in ("drop-in", "refactor"):
                auto_fixable += 1

        all_fixes.extend(file_fixes)

        # Build patched version of the file for unified diff
        patched_lines = _apply_fixes_to_lines(source_lines, file_fixes)
        if patched_lines != source_lines:
            diff = difflib.unified_diff(
                source_lines,
                patched_lines,
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
                lineterm="",
            )
            patch_parts.append("\n".join(diff))

    patch = "\n".join(patch_parts)

    return {
        "total_findings": len(findings),
        "auto_fixable": auto_fixable,
        "fixes": all_fixes,
        "patch": patch,
    }


def _apply_fixes_to_lines(
    source_lines: List[str], fixes: List[dict]
) -> List[str]:
    """Apply fixes to source lines, producing new patched lines.

    Handles line offset shifts from inserted comment lines.
    Processes fixes in reverse line order to maintain correct positions.
    """
    result = list(source_lines)  # copy
    # Sort fixes by line number descending so insertions don't shift later fixes
    sorted_fixes = sorted(fixes, key=lambda f: f.get("line", 0), reverse=True)

    for fix in sorted_fixes:
        line_num = fix.get("line", 0)
        if line_num < 1 or line_num > len(source_lines):
            continue
        idx = line_num - 1
        original = fix.get("original_line", "")
        fixed = fix.get("fixed_line", "")
        if original and fixed and fixed != original:
            # Replace the original line with the fixed content (may be multiple lines)
            fixed_lines = fixed.splitlines(True)
            # Ensure last line has newline
            if fixed_lines and not fixed_lines[-1].endswith("\n"):
                fixed_lines[-1] += "\n"
            result[idx : idx + 1] = fixed_lines

    return result


def apply_fixes_to_files(scan_result: dict, source_dir: str) -> Dict[str, int]:
    """Apply all auto-fixes directly to source files.

    Returns:
        Dict mapping relative file paths to number of fixes applied.
    """
    fix_result = generate_fixes(scan_result, source_dir)
    applied: Dict[str, int] = {}

    # Group fixes by file
    by_file: Dict[str, List[dict]] = {}
    for fix in fix_result["fixes"]:
        rel_path = fix.get("file", "")
        if rel_path not in by_file:
            by_file[rel_path] = []
        by_file[rel_path].append(fix)

    for rel_path, fixes in by_file.items():
        abs_path = os.path.join(source_dir, rel_path)
        try:
            with open(abs_path, "r", errors="ignore") as fh:
                source_lines = fh.readlines()
        except (OSError, IOError):
            continue

        patched = _apply_fixes_to_lines(source_lines, fixes)
        if patched != source_lines:
            with open(abs_path, "w") as fh:
                fh.writelines(patched)
            applied[rel_path] = len(fixes)

    return applied


def write_patch(scan_result: dict, source_dir: str, patch_path: str) -> str:
    """Generate fixes and write the unified diff patch to a file.

    Returns:
        The patch content as a string.
    """
    fix_result = generate_fixes(scan_result, source_dir)
    patch = fix_result["patch"]
    with open(patch_path, "w") as f:
        f.write(patch)
    return patch


def print_fixes(scan_result: dict, source_dir: str) -> None:
    """Print a human-readable summary of suggested fixes to stdout."""
    fix_result = generate_fixes(scan_result, source_dir)
    fixes = fix_result["fixes"]

    if not fixes:
        print("  No findings to fix.")
        return

    print(f"\n  PQC AUTO-FIX SUGGESTIONS")
    print(f"  {'='*70}")
    print(f"  Total findings: {fix_result['total_findings']}")
    print(f"  Auto-fixable:   {fix_result['auto_fixable']}")
    print(f"  Manual review:  {fix_result['total_findings'] - fix_result['auto_fixable']}")
    print()

    current_file = None
    for fix in fixes:
        if fix["file"] != current_file:
            current_file = fix["file"]
            print(f"  --- {current_file} ---")

        confidence_bar = _confidence_bar(fix["confidence"])
        migration_label = fix["migration_type"].upper()
        print(f"  Line {fix['line']:>4d} [{fix['risk']:8s}] {fix['algorithm']}")
        print(f"           Type: {migration_label}  Confidence: {confidence_bar} ({fix['confidence']:.0%})")
        print(f"           {fix['explanation'][:100]}")
        if fix["migration_type"] == "drop-in":
            orig = fix["original_line"].strip()
            # Extract just the fixed code line (skip the comment)
            fixed_parts = fix["fixed_line"].strip().split("\n")
            fixed_code = fixed_parts[-1].strip() if fixed_parts else ""
            print(f"           - {orig}")
            print(f"           + {fixed_code}")
        print()

    print(f"  {'='*70}")
    if fix_result["auto_fixable"] > 0:
        print(f"  Run with --fix-patch fixes.patch to generate a patch file.")
        print(f"  Run with --fix-apply to apply fixes directly (creates backup comments).")
    print()


def _confidence_bar(confidence: float) -> str:
    """Visual confidence bar."""
    filled = int(confidence * 10)
    return "[" + "#" * filled + "." * (10 - filled) + "]"
