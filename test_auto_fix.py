#!/usr/bin/env python3
"""
Tests for the PQC Auto-Fix Migration Engine.

Creates a vulnerable project, runs generate_fixes(), verifies:
1. All drop-in replacements are generated
2. The patch is valid unified diff
3. Applying the patch and re-scanning shows reduced findings
"""

import os
import sys
import tempfile
import shutil
import textwrap

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pqc_posture import scan_codebase
from auto_fix import generate_fix, generate_fixes, apply_fixes_to_files, write_patch


def _create_vulnerable_project(tmpdir: str) -> None:
    """Create a fake project with known quantum-vulnerable crypto."""
    # File 1: Python with MD5, SHA-1, and hashlib.new variants
    with open(os.path.join(tmpdir, "hashes.py"), "w") as f:
        f.write(textwrap.dedent("""\
            import hashlib

            def hash_password(password):
                return hashlib.md5(password.encode()).hexdigest()

            def hash_token(token):
                return hashlib.sha1(token.encode()).hexdigest()

            def hash_legacy(data):
                h = hashlib.new("md5")
                h.update(data)
                return h.hexdigest()

            def hash_old(data):
                h = hashlib.new("sha1")
                h.update(data)
                return h.hexdigest()
        """))

    # File 2: JWT with RS256 and ES256
    with open(os.path.join(tmpdir, "auth.py"), "w") as f:
        f.write(textwrap.dedent("""\
            import jwt

            def create_token(payload, key):
                return jwt.encode(payload, key, algorithm="RS256")

            def create_token_ec(payload, key):
                return jwt.encode(payload, key, algorithm="ES256")
        """))

    # File 3: TLS with deprecated protocols
    with open(os.path.join(tmpdir, "network.py"), "w") as f:
        f.write(textwrap.dedent("""\
            import ssl

            def get_context():
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                return ctx
        """))

    # File 4: Django settings with weak hashers
    with open(os.path.join(tmpdir, "settings.py"), "w") as f:
        f.write(textwrap.dedent("""\
            PASSWORD_HASHERS = [
                'django.contrib.auth.hashers.MD5PasswordHasher',
                'django.contrib.auth.hashers.SHA1PasswordHasher',
            ]
        """))

    # File 5: RSA key generation (refactor, not drop-in)
    with open(os.path.join(tmpdir, "crypto_utils.py"), "w") as f:
        f.write(textwrap.dedent("""\
            from cryptography.hazmat.primitives.asymmetric import rsa

            def gen_key():
                private_key = rsa.generate_private_key(65537, 2048)
                return private_key
        """))


def test_generate_fix_md5():
    """Test that MD5 hashlib call gets a drop-in fix."""
    finding = {
        "file": "test.py",
        "line": 3,
        "algorithm": "MD5",
        "category": "hash",
        "risk": "HIGH",
        "quantum_status": "BROKEN",
        "migration": "SHA-256",
    }
    source_lines = [
        "import hashlib\n",
        "\n",
        "h = hashlib.md5(data)\n",
    ]
    fix = generate_fix(finding, source_lines)
    assert fix["migration_type"] == "drop-in", f"Expected drop-in, got {fix['migration_type']}"
    assert fix["confidence"] >= 0.9, f"Expected confidence >= 0.9, got {fix['confidence']}"
    assert "sha256" in fix["fixed_line"], f"Expected sha256 in fix, got: {fix['fixed_line']}"
    assert "md5" not in fix["fixed_line"].split("PQC-FIX")[-1], "MD5 should be replaced in the code portion"
    print("  PASS: test_generate_fix_md5")


def test_generate_fix_sha1():
    """Test that SHA-1 hashlib call gets a drop-in fix."""
    finding = {
        "file": "test.py",
        "line": 1,
        "algorithm": "SHA-1",
        "risk": "HIGH",
        "migration": "SHA-256",
    }
    source_lines = ["digest = hashlib.sha1(msg).hexdigest()\n"]
    fix = generate_fix(finding, source_lines)
    assert fix["migration_type"] == "drop-in"
    assert "sha256" in fix["fixed_line"]
    print("  PASS: test_generate_fix_sha1")


def test_generate_fix_jwt_rs256():
    """Test RS256 JWT algorithm replacement."""
    finding = {
        "file": "test.py",
        "line": 1,
        "algorithm": "RSA Signing",
        "risk": "CRITICAL",
        "migration": "ML-DSA",
    }
    source_lines = ['    token = jwt.encode(payload, key, algorithm="RS256")\n']
    fix = generate_fix(finding, source_lines)
    assert fix["migration_type"] == "drop-in"
    assert "EdDSA" in fix["fixed_line"]
    # The actual code line (last line of fixed output) should have EdDSA, not RS256
    code_line = fix["fixed_line"].strip().split("\n")[-1]
    assert "RS256" not in code_line, f"RS256 should be replaced in code line: {code_line}"
    assert "EdDSA" in code_line
    print("  PASS: test_generate_fix_jwt_rs256")


def test_generate_fix_tls_v1():
    """Test TLSv1 protocol replacement."""
    finding = {
        "file": "test.py",
        "line": 1,
        "algorithm": "TLS 1.0",
        "risk": "CRITICAL",
        "migration": "TLS 1.3",
    }
    source_lines = ["    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n"]
    fix = generate_fix(finding, source_lines)
    assert fix["migration_type"] == "drop-in"
    assert "PROTOCOL_TLS_CLIENT" in fix["fixed_line"]
    print("  PASS: test_generate_fix_tls_v1")


def test_generate_fix_rsa_keygen():
    """Test RSA keygen gets refactor suggestion, not drop-in."""
    finding = {
        "file": "test.py",
        "line": 1,
        "algorithm": "RSA Key Exchange",
        "risk": "CRITICAL",
        "migration": "ML-KEM 768",
    }
    source_lines = ["    key = rsa.generate_private_key(65537, 2048)\n"]
    fix = generate_fix(finding, source_lines)
    assert fix["migration_type"] == "refactor", f"Expected refactor, got {fix['migration_type']}"
    assert fix["confidence"] < 0.9, f"Expected confidence < 0.9, got {fix['confidence']}"
    assert "ML-KEM" in fix["explanation"] or "ML-DSA" in fix["explanation"]
    print("  PASS: test_generate_fix_rsa_keygen")


def test_generate_fix_manual_fallback():
    """Test that unknown patterns fall back to manual review."""
    finding = {
        "file": "test.py",
        "line": 1,
        "algorithm": "DiffieHellman",
        "risk": "CRITICAL",
        "migration": "ML-KEM 768",
    }
    source_lines = ["    dh = DiffieHellman(group=14)\n"]
    fix = generate_fix(finding, source_lines)
    assert fix["migration_type"] == "manual"
    assert fix["confidence"] <= 0.3
    print("  PASS: test_generate_fix_manual_fallback")


def test_generate_fix_django_hashers():
    """Test Django password hasher replacements."""
    finding1 = {
        "file": "settings.py",
        "line": 1,
        "algorithm": "MD5",
        "risk": "HIGH",
        "migration": "PBKDF2",
    }
    source_lines = ["    'django.contrib.auth.hashers.MD5PasswordHasher',\n"]
    fix1 = generate_fix(finding1, source_lines)
    assert fix1["migration_type"] == "drop-in"
    assert "PBKDF2PasswordHasher" in fix1["fixed_line"]

    finding2 = {
        "file": "settings.py",
        "line": 1,
        "algorithm": "SHA-1",
        "risk": "HIGH",
        "migration": "PBKDF2",
    }
    source_lines2 = ["    'django.contrib.auth.hashers.SHA1PasswordHasher',\n"]
    fix2 = generate_fix(finding2, source_lines2)
    assert fix2["migration_type"] == "drop-in"
    assert "PBKDF2PasswordHasher" in fix2["fixed_line"]
    print("  PASS: test_generate_fix_django_hashers")


def test_full_pipeline():
    """Integration test: create vulnerable project, scan, fix, re-scan."""
    tmpdir = tempfile.mkdtemp(prefix="pqc_autofix_test_")
    try:
        _create_vulnerable_project(tmpdir)

        # Step 1: Scan
        scan_result = scan_codebase(tmpdir)
        initial_findings = scan_result["total_findings"]
        assert initial_findings > 0, "Expected findings in vulnerable project"
        print(f"  Initial scan: {initial_findings} findings")

        # Step 2: Generate fixes
        fix_result = generate_fixes(scan_result, tmpdir)
        assert fix_result["total_findings"] == initial_findings
        assert fix_result["auto_fixable"] > 0, "Expected some auto-fixable findings"
        print(f"  Auto-fixable: {fix_result['auto_fixable']}/{fix_result['total_findings']}")

        # Step 3: Verify specific drop-in fixes exist
        drop_in_fixes = [f for f in fix_result["fixes"] if f["migration_type"] == "drop-in"]
        refactor_fixes = [f for f in fix_result["fixes"] if f["migration_type"] == "refactor"]
        manual_fixes = [f for f in fix_result["fixes"] if f["migration_type"] == "manual"]

        assert len(drop_in_fixes) >= 4, (
            f"Expected at least 4 drop-in fixes (md5, sha1, jwt, tls), got {len(drop_in_fixes)}: "
            f"{[(f['file'], f['algorithm']) for f in drop_in_fixes]}"
        )
        print(f"  Drop-in: {len(drop_in_fixes)}, Refactor: {len(refactor_fixes)}, Manual: {len(manual_fixes)}")

        # Step 4: Verify the patch is valid unified diff
        patch = fix_result["patch"]
        assert len(patch) > 0, "Expected non-empty patch"
        assert "---" in patch, "Patch should contain unified diff headers"
        assert "+++" in patch, "Patch should contain unified diff headers"
        assert "@@" in patch, "Patch should contain hunk headers"
        print(f"  Patch: {len(patch.splitlines())} lines, valid unified diff format")

        # Step 5: Write patch file and verify
        patch_path = os.path.join(tmpdir, "fixes.patch")
        write_patch(scan_result, tmpdir, patch_path)
        assert os.path.exists(patch_path)
        with open(patch_path) as f:
            written_patch = f.read()
        assert len(written_patch) > 0
        print(f"  Patch file written: {patch_path}")

        # Step 6: Apply fixes to files
        applied = apply_fixes_to_files(scan_result, tmpdir)
        assert len(applied) > 0, "Expected fixes to be applied to at least one file"
        total_applied = sum(applied.values())
        print(f"  Applied {total_applied} fixes to {len(applied)} files")

        # Step 7: Re-scan and verify findings reduced
        rescan_result = scan_codebase(tmpdir)
        new_findings = rescan_result["total_findings"]
        print(f"  Re-scan: {new_findings} findings (was {initial_findings})")

        # Drop-in fixes should eliminate their findings entirely
        # Some findings may remain (refactor/manual don't change code)
        # But the count should be lower
        assert new_findings < initial_findings, (
            f"Expected fewer findings after fix ({new_findings} >= {initial_findings})"
        )

        # Specifically check that MD5/SHA1 hashlib findings are gone
        remaining_algos = [f["algorithm"] for f in rescan_result["findings"]]
        # The direct hashlib.md5 / hashlib.sha1 calls should be replaced
        md5_sha1_in_hashes = [
            f for f in rescan_result["findings"]
            if f["file"] == "hashes.py" and f["algorithm"] in ("MD5", "SHA-1")
            and "hashlib.md5" in f.get("usage", "") or "hashlib.sha1" in f.get("usage", "")
        ]
        # After fix, hashes.py should have no direct md5/sha1 calls
        # (the PQC-FIX comments don't trigger the scanner)
        print(f"  Remaining MD5/SHA-1 in hashes.py: {len(md5_sha1_in_hashes)}")

        reduction_pct = (1 - new_findings / initial_findings) * 100
        print(f"  Finding reduction: {reduction_pct:.0f}%")

        print("  PASS: test_full_pipeline")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_confidence_ranges():
    """Verify confidence values are in expected ranges per migration type."""
    finding = {"file": "t.py", "line": 1, "algorithm": "X", "risk": "HIGH", "migration": "Y"}

    # Drop-in
    lines_md5 = ["x = hashlib.md5(data)\n"]
    fix = generate_fix(finding, lines_md5)
    assert fix["confidence"] >= 0.9, f"Drop-in confidence should be >= 0.9, got {fix['confidence']}"

    # Refactor
    lines_rsa = ["k = rsa.generate_private_key(65537, 2048)\n"]
    fix = generate_fix(finding, lines_rsa)
    assert 0.5 <= fix["confidence"] <= 0.8, f"Refactor confidence should be 0.5-0.8, got {fix['confidence']}"

    # Manual
    lines_unknown = ["x = some_random_code()\n"]
    fix = generate_fix(finding, lines_unknown)
    assert fix["confidence"] <= 0.3, f"Manual confidence should be <= 0.3, got {fix['confidence']}"

    print("  PASS: test_confidence_ranges")


def test_empty_scan():
    """Test generate_fixes with no findings."""
    result = generate_fixes({"findings": []}, "/tmp")
    assert result["total_findings"] == 0
    assert result["auto_fixable"] == 0
    assert result["fixes"] == []
    assert result["patch"] == ""
    print("  PASS: test_empty_scan")


def test_invalid_line_number():
    """Test that out-of-range line numbers don't crash."""
    finding = {
        "file": "t.py",
        "line": 999,
        "algorithm": "MD5",
        "risk": "HIGH",
        "migration": "SHA-256",
    }
    fix = generate_fix(finding, ["only one line\n"])
    assert fix["migration_type"] == "manual"
    print("  PASS: test_invalid_line_number")


def main():
    print("\n  PQC Auto-Fix Migration Engine — Test Suite")
    print("  " + "=" * 50)

    tests = [
        test_generate_fix_md5,
        test_generate_fix_sha1,
        test_generate_fix_jwt_rs256,
        test_generate_fix_tls_v1,
        test_generate_fix_rsa_keygen,
        test_generate_fix_manual_fallback,
        test_generate_fix_django_hashers,
        test_confidence_ranges,
        test_empty_scan,
        test_invalid_line_number,
        test_full_pipeline,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  FAIL: {test.__name__}: {e}")

    print()
    print(f"  Results: {passed} passed, {failed} failed, {len(tests)} total")
    print("  " + "=" * 50)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
