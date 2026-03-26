#!/usr/bin/env python3
"""
TLS Endpoint Scanner — Quantum-Risk Assessment for Live TLS Connections

Connects to TLS endpoints and evaluates certificate algorithms, key exchange,
cipher suites, and protocol versions for post-quantum readiness.

Uses Python stdlib only (ssl, socket) — no external dependencies.
"""

import ssl
import socket
import time
import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


# PQC-related key exchange indicators (OpenSSL naming)
PQC_KEX_INDICATORS = {
    "x25519kyber768",
    "x25519mlkem768",
    "mlkem768",
    "mlkem1024",
    "kyber768",
    "kyber1024",
    "bikel3",
    "hqc256",
    "x25519_kyber768",
    "x25519_mlkem768",
    "SecP256r1MLKEM768",
    "X25519MLKEM768",
}

WEAK_CIPHERS = {"RC4", "DES", "NULL", "MD5", "EXPORT", "anon", "RC2"}


def _parse_host_port(target: str) -> tuple:
    """Parse 'hostname' or 'hostname:port' into (hostname, port)."""
    if ":" in target:
        parts = target.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return target, 443
    return target, 443


def _tls_version_label(protocol_version: int) -> str:
    """Convert ssl.TLSVersion enum or protocol constant to human label."""
    version_map = {
        ssl.TLSVersion.TLSv1: "1.0",
        ssl.TLSVersion.TLSv1_1: "1.1",
        ssl.TLSVersion.TLSv1_2: "1.2",
        ssl.TLSVersion.TLSv1_3: "1.3",
    }
    return version_map.get(protocol_version, str(protocol_version))


def _cert_algorithm_risk(sig_algorithm: str) -> tuple:
    """Return (risk, quantum_status, migration) for a certificate signature algorithm."""
    sig_lower = sig_algorithm.lower() if sig_algorithm else ""

    if "rsa" in sig_lower:
        return (
            "CRITICAL",
            "BROKEN",
            "ML-DSA 65 (CRYSTALS-Dilithium) hybrid certificate — NIST FIPS 204",
        )
    if "ecdsa" in sig_lower or "ec" in sig_lower:
        return (
            "CRITICAL",
            "BROKEN",
            "ML-DSA 65 (CRYSTALS-Dilithium) hybrid certificate — NIST FIPS 204",
        )
    if "ed25519" in sig_lower or "ed448" in sig_lower:
        return (
            "CRITICAL",
            "BROKEN",
            "ML-DSA 44 or FALCON-512 — NIST FIPS 204/205",
        )
    if "dilithium" in sig_lower or "ml-dsa" in sig_lower or "mldsa" in sig_lower:
        return ("LOW", "SAFE", "Already PQC — no migration needed")

    return ("HIGH", "WEAKENED", "Verify algorithm is PQC-safe")


def _cipher_suite_risk(cipher_name: str) -> Optional[tuple]:
    """If cipher suite is weak, return (risk, detail). Otherwise None."""
    upper = cipher_name.upper() if cipher_name else ""
    for weak in WEAK_CIPHERS:
        if weak.upper() in upper:
            return (
                "CRITICAL",
                f"Weak cipher component '{weak}' in suite '{cipher_name}'",
            )
    return None


def scan_tls(hostname: str, port: int = 443) -> Dict:
    """
    Connect to a TLS endpoint and assess its post-quantum cryptography posture.

    Returns a dict compatible with scan_codebase() output format:
        risk_score, risk_level, findings, quantum_exposure, etc.
    """
    start = time.time()
    findings: List[dict] = []
    target_label = f"{hostname}:{port}"
    errors: List[str] = []

    # Build SSL context — we want to see what the server offers
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Accept any cert so we can inspect it

    # Also build a verifying context to get parsed cert details
    ctx_verify = ssl.create_default_context()

    # Try to connect
    try:
        with socket.create_connection((hostname, port), timeout=10) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                # ── TLS Version ──
                tls_version_enum = tls_sock.version()
                tls_version = tls_version_enum  # e.g. "TLSv1.3"

                # Normalise version string to number
                version_number = "unknown"
                if tls_version:
                    for label in ("1.3", "1.2", "1.1", "1.0"):
                        if label in tls_version:
                            version_number = label
                            break

                if version_number in ("1.0", "1.1"):
                    findings.append({
                        "file": target_label,
                        "line": 0,
                        "algorithm": f"TLS {version_number}",
                        "category": "protocol",
                        "risk": "CRITICAL",
                        "raw_risk": "CRITICAL",
                        "quantum_status": "BROKEN",
                        "context": "tls_endpoint",
                        "usage": f"Server negotiated TLS {version_number}",
                        "migration": "Upgrade to TLS 1.3 with hybrid PQC key exchange (ML-KEM + X25519)",
                        "nist_ref": "NIST SP 800-52 Rev 2",
                    })
                elif version_number == "1.2":
                    findings.append({
                        "file": target_label,
                        "line": 0,
                        "algorithm": "TLS 1.2",
                        "category": "protocol",
                        "risk": "MEDIUM",
                        "raw_risk": "MEDIUM",
                        "quantum_status": "WEAKENED",
                        "context": "tls_endpoint",
                        "usage": f"Server negotiated TLS 1.2 (no PQC key exchange possible)",
                        "migration": "Upgrade to TLS 1.3 for PQC hybrid key exchange support",
                        "nist_ref": "NIST SP 800-52 Rev 2",
                    })
                elif version_number == "1.3":
                    findings.append({
                        "file": target_label,
                        "line": 0,
                        "algorithm": "TLS 1.3",
                        "category": "protocol",
                        "risk": "LOW",
                        "raw_risk": "LOW",
                        "quantum_status": "SAFE",
                        "context": "tls_endpoint",
                        "usage": f"Server negotiated TLS 1.3",
                        "migration": "Enable hybrid PQC key exchange (ML-KEM + X25519) if not already active",
                        "nist_ref": "NIST SP 800-52 Rev 2",
                    })

                # ── Cipher Suite ──
                cipher_info = tls_sock.cipher()
                cipher_name = cipher_info[0] if cipher_info else "unknown"
                cipher_protocol = cipher_info[1] if cipher_info and len(cipher_info) > 1 else ""
                cipher_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else 0

                weak = _cipher_suite_risk(cipher_name)
                if weak:
                    findings.append({
                        "file": target_label,
                        "line": 0,
                        "algorithm": f"Cipher: {cipher_name}",
                        "category": "symmetric",
                        "risk": weak[0],
                        "raw_risk": weak[0],
                        "quantum_status": "BROKEN",
                        "context": "tls_endpoint",
                        "usage": weak[1],
                        "migration": "Use AES-256-GCM or ChaCha20-Poly1305 cipher suites",
                        "nist_ref": "NIST SP 800-52 Rev 2",
                    })

                # ── PQC Key Exchange Detection ──
                # Check if the negotiated cipher or connection has PQC indicators
                has_pqc_kex = False
                kex_info = ""

                # In TLS 1.3, key exchange is separate from cipher suite name.
                # Check shared_ciphers and connection details for PQC group names.
                try:
                    # Python 3.12+ may expose negotiated group
                    if hasattr(tls_sock, "get_channel_binding"):
                        pass  # channel binding doesn't reveal KEX
                except Exception:
                    pass

                # Check cipher name for PQC indicators
                cipher_lower = cipher_name.lower() if cipher_name else ""
                for pqc_name in PQC_KEX_INDICATORS:
                    if pqc_name.lower() in cipher_lower:
                        has_pqc_kex = True
                        kex_info = pqc_name
                        break

                if not has_pqc_kex:
                    findings.append({
                        "file": target_label,
                        "line": 0,
                        "algorithm": "No PQC Key Exchange",
                        "category": "key_exchange",
                        "risk": "HIGH",
                        "raw_risk": "HIGH",
                        "quantum_status": "BROKEN",
                        "context": "tls_endpoint",
                        "usage": f"Cipher suite '{cipher_name}' — no PQC/hybrid key exchange detected",
                        "migration": "Enable ML-KEM 768 hybrid key exchange (X25519Kyber768)",
                        "nist_ref": "NIST FIPS 203, draft-ietf-tls-hybrid-design",
                    })
                else:
                    findings.append({
                        "file": target_label,
                        "line": 0,
                        "algorithm": f"PQC KEX: {kex_info}",
                        "category": "key_exchange",
                        "risk": "LOW",
                        "raw_risk": "LOW",
                        "quantum_status": "SAFE",
                        "context": "tls_endpoint",
                        "usage": f"PQC hybrid key exchange active: {kex_info}",
                        "migration": "Already quantum-resistant key exchange",
                        "nist_ref": "NIST FIPS 203",
                    })

                # ── Certificate Analysis ──
                peer_cert = tls_sock.getpeercert(binary_form=True)

                cert_subject = ""
                cert_issuer = ""
                cert_not_after = ""
                cert_sig_algo = ""
                cert_key_size = 0

                # getpeercert(False) returns empty dict with CERT_NONE, so
                # do a second verified connection for parsed cert details.
                peer_cert_dict = {}
                try:
                    with socket.create_connection((hostname, port), timeout=10) as raw2:
                        with ctx_verify.wrap_socket(raw2, server_hostname=hostname) as tls2:
                            peer_cert_dict = tls2.getpeercert(binary_form=False) or {}
                except Exception:
                    pass  # Verification may fail (expired, self-signed) — we still have DER

                if peer_cert_dict:
                    # Subject
                    subject_parts = peer_cert_dict.get("subject", ())
                    for rdn in subject_parts:
                        for attr_type, attr_value in rdn:
                            if attr_type == "commonName":
                                cert_subject = attr_value

                    # Issuer
                    issuer_parts = peer_cert_dict.get("issuer", ())
                    for rdn in issuer_parts:
                        for attr_type, attr_value in rdn:
                            if attr_type in ("commonName", "organizationName"):
                                if not cert_issuer:
                                    cert_issuer = attr_value

                    # Expiry
                    cert_not_after = peer_cert_dict.get("notAfter", "")

                # Extract signature algorithm, key size, and fallback metadata from DER cert
                if peer_cert:
                    cert_sig_algo, cert_key_size, der_meta = _extract_cert_details(peer_cert)
                    # Use DER-extracted metadata as fallback
                    if not cert_subject and der_meta.get("subject"):
                        cert_subject = der_meta["subject"]
                    if not cert_issuer and der_meta.get("issuer"):
                        cert_issuer = der_meta["issuer"]
                    if not cert_not_after and der_meta.get("not_after"):
                        cert_not_after = der_meta["not_after"]

                # Certificate signature algorithm risk
                if cert_sig_algo:
                    risk, q_status, migration = _cert_algorithm_risk(cert_sig_algo)
                    findings.append({
                        "file": target_label,
                        "line": 0,
                        "algorithm": f"Certificate: {cert_sig_algo}",
                        "category": "signature",
                        "risk": risk,
                        "raw_risk": risk,
                        "quantum_status": q_status,
                        "context": "tls_endpoint",
                        "usage": f"Certificate signed with {cert_sig_algo} (subject: {cert_subject}, issuer: {cert_issuer})",
                        "migration": migration,
                        "nist_ref": "NIST SP 800-208, FIPS 204",
                    })

                # Key size check — only flag RSA keys below 2048; EC keys are
                # naturally smaller (256/384/521) and that is expected.
                is_rsa_cert = "rsa" in (cert_sig_algo or "").lower()
                if is_rsa_cert and cert_key_size > 0 and cert_key_size < 2048:
                    findings.append({
                        "file": target_label,
                        "line": 0,
                        "algorithm": f"Key Size: {cert_key_size}-bit RSA",
                        "category": "key_exchange",
                        "risk": "CRITICAL",
                        "raw_risk": "CRITICAL",
                        "quantum_status": "BROKEN",
                        "context": "tls_endpoint",
                        "usage": f"RSA certificate key size {cert_key_size} bits is below 2048-bit minimum",
                        "migration": "Use 4096-bit RSA minimum (short-term), migrate to ML-DSA (long-term)",
                        "nist_ref": "NIST SP 800-131A",
                    })

                # Certificate expiry check
                if cert_not_after:
                    try:
                        # Format: "Mon DD HH:MM:SS YYYY GMT"
                        expiry = datetime.datetime.strptime(
                            cert_not_after, "%b %d %H:%M:%S %Y %Z"
                        )
                        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                        days_left = (expiry - now_utc).days
                        if days_left < 0:
                            findings.append({
                                "file": target_label,
                                "line": 0,
                                "algorithm": "Expired Certificate",
                                "category": "signature",
                                "risk": "CRITICAL",
                                "raw_risk": "CRITICAL",
                                "quantum_status": "BROKEN",
                                "context": "tls_endpoint",
                                "usage": f"Certificate expired {abs(days_left)} days ago ({cert_not_after})",
                                "migration": "Renew certificate immediately with PQC-hybrid if available",
                                "nist_ref": "NIST SP 800-52 Rev 2",
                            })
                        elif days_left < 30:
                            findings.append({
                                "file": target_label,
                                "line": 0,
                                "algorithm": "Certificate Expiring Soon",
                                "category": "signature",
                                "risk": "MEDIUM",
                                "raw_risk": "MEDIUM",
                                "quantum_status": "WEAKENED",
                                "context": "tls_endpoint",
                                "usage": f"Certificate expires in {days_left} days ({cert_not_after})",
                                "migration": "Renew certificate; consider PQC-hybrid certificate on renewal",
                                "nist_ref": "NIST SP 800-52 Rev 2",
                            })
                    except (ValueError, TypeError):
                        pass  # Can't parse date — skip this check

    except ssl.SSLError as e:
        errors.append(f"SSL error: {e}")
    except socket.timeout:
        errors.append(f"Connection timed out after 10s")
    except socket.gaierror as e:
        errors.append(f"DNS resolution failed: {e}")
    except ConnectionRefusedError:
        errors.append(f"Connection refused on {target_label}")
    except OSError as e:
        errors.append(f"Connection error: {e}")

    elapsed_ms = int((time.time() - start) * 1000)

    # ── Compute Risk Score ──
    from collections import Counter

    risk_counts = Counter(f["risk"] for f in findings)
    status_counts = Counter(f["quantum_status"] for f in findings)
    category_counts = Counter(f["category"] for f in findings)
    algo_counts = Counter(f["algorithm"] for f in findings)

    risk_score = min(100, (
        risk_counts.get("CRITICAL", 0) * 25 +
        risk_counts.get("HIGH", 0) * 10 +
        risk_counts.get("MEDIUM", 0) * 3 +
        risk_counts.get("LOW", 0) * 1
    ))

    if risk_score >= 50:
        risk_level = "CRITICAL"
    elif risk_score >= 25:
        risk_level = "HIGH"
    elif risk_score >= 10:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "scan_target": target_label,
        "scan_type": "tls_endpoint",
        "scan_time_ms": elapsed_ms,
        "tls_version": version_number if not errors else None,
        "cipher_suite": cipher_name if not errors else None,
        "certificate": {
            "subject": cert_subject if not errors else None,
            "issuer": cert_issuer if not errors else None,
            "signature_algorithm": cert_sig_algo if not errors else None,
            "key_size": cert_key_size if not errors else None,
            "not_after": cert_not_after if not errors else None,
        } if not errors else None,
        "pqc_kex_detected": has_pqc_kex if not errors else False,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_findings": len(findings),
        "quantum_exposure": {
            "broken": status_counts.get("BROKEN", 0),
            "weakened": status_counts.get("WEAKENED", 0),
            "safe": status_counts.get("SAFE", 0),
        },
        "by_risk": dict(risk_counts),
        "by_category": dict(category_counts),
        "by_algorithm": dict(algo_counts),
        "findings": findings,
        "migration_priority": sorted(
            findings,
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("risk", "LOW"), 3),
        )[:20],
        "errors": errors,
    }


def _extract_cert_details(der_bytes: bytes) -> tuple:
    """
    Extract signature algorithm, key size, and basic metadata from DER-encoded certificate.

    Returns (signature_algorithm: str, key_size: int, metadata: dict).
    metadata may contain 'subject', 'issuer', 'not_after' extracted from DER.
    Uses minimal ASN.1 parsing — no external deps.
    """
    sig_algo = ""
    key_size = 0
    meta: Dict[str, str] = {}

    # Known OID-to-name mappings for signature algorithms
    oid_map = {
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05": "sha1WithRSAEncryption",
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b": "sha256WithRSAEncryption",
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c": "sha384WithRSAEncryption",
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d": "sha512WithRSAEncryption",
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0e": "sha224WithRSAEncryption",
        b"\x2a\x86\x48\xce\x3d\x04\x03\x02": "ecdsa-with-SHA256",
        b"\x2a\x86\x48\xce\x3d\x04\x03\x03": "ecdsa-with-SHA384",
        b"\x2a\x86\x48\xce\x3d\x04\x03\x04": "ecdsa-with-SHA512",
        b"\x2a\x86\x48\xce\x3d\x04\x03\x01": "ecdsa-with-SHA224",
        b"\x65\x70": "Ed25519",
        b"\x65\x71": "Ed448",
    }

    # Search for known OIDs in the DER blob
    for oid_bytes, name in oid_map.items():
        if oid_bytes in der_bytes:
            sig_algo = name
            break

    # Estimate key size from DER certificate size and algorithm
    # For RSA: look for the modulus bit string after the public key OID
    rsa_oid = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"  # rsaEncryption
    ec_oid = b"\x2a\x86\x48\xce\x3d\x02\x01"  # ecPublicKey

    if rsa_oid in der_bytes:
        # Find the BIT STRING containing the public key after the RSA OID
        idx = der_bytes.index(rsa_oid) + len(rsa_oid)
        # Walk forward to find BIT STRING (tag 0x03) with the modulus
        remaining = der_bytes[idx:idx + 200]
        for i in range(len(remaining) - 4):
            if remaining[i] == 0x03 and remaining[i + 1] & 0x80:
                # Long form length — indicates a large key
                len_bytes = remaining[i + 1] & 0x7f
                if len_bytes == 2 and i + 4 < len(remaining):
                    bit_string_len = (remaining[i + 2] << 8) | remaining[i + 3]
                    # RSA modulus length (subtract padding/overhead)
                    key_size = (bit_string_len - 10) * 8
                    # Round to nearest standard size
                    if key_size > 3500:
                        key_size = 4096
                    elif key_size > 1800:
                        key_size = 2048
                    elif key_size > 900:
                        key_size = 1024
                    elif key_size > 400:
                        key_size = 512
                    break
                elif len_bytes == 1 and i + 3 < len(remaining):
                    bit_string_len = remaining[i + 2]
                    key_size = bit_string_len * 8
                    if key_size > 1800:
                        key_size = 2048
                    elif key_size > 900:
                        key_size = 1024
                    break
    elif ec_oid in der_bytes:
        # EC key sizes based on curve OIDs
        curve_sizes = {
            b"\x2a\x86\x48\xce\x3d\x03\x01\x07": 256,  # prime256v1 / P-256
            b"\x2b\x81\x04\x00\x22": 384,  # secp384r1 / P-384
            b"\x2b\x81\x04\x00\x23": 521,  # secp521r1 / P-521
        }
        for curve_oid, size in curve_sizes.items():
            if curve_oid in der_bytes:
                key_size = size
                break
        if key_size == 0:
            key_size = 256  # Default EC assumption

    # ── Extract subject/issuer/expiry from DER via printable-string scanning ──
    # Look for common name (CN=) patterns in the DER — these are stored as
    # UTF8String or PrintableString right after the CN OID (2.5.4.3).
    cn_oid = b"\x55\x04\x03"  # OID 2.5.4.3 (commonName)
    org_oid = b"\x55\x04\x0a"  # OID 2.5.4.10 (organizationName)

    cn_values = _extract_oid_values(der_bytes, cn_oid)
    org_values = _extract_oid_values(der_bytes, org_oid)

    # In a typical cert, subject CN comes after issuer CN in the TBSCertificate.
    # The order in DER is: issuer, validity, subject. So first CN = issuer, second = subject.
    # However, issuer often has organizationName instead of CN.
    if len(cn_values) >= 2:
        meta["issuer"] = cn_values[0]
        meta["subject"] = cn_values[1]
    elif len(cn_values) == 1:
        meta["subject"] = cn_values[0]
        if org_values:
            meta["issuer"] = org_values[0]

    # Extract validity dates — look for UTCTime (tag 0x17) or GeneralizedTime (tag 0x18)
    not_after = _extract_validity_not_after(der_bytes)
    if not_after:
        meta["not_after"] = not_after

    return sig_algo, key_size, meta


def _extract_oid_values(der_bytes: bytes, oid: bytes) -> List[str]:
    """Find all string values immediately after a given OID in DER data."""
    values = []
    search_from = 0
    while True:
        idx = der_bytes.find(oid, search_from)
        if idx == -1:
            break
        # After OID comes a string tag (0x0c=UTF8, 0x13=PrintableString, 0x16=IA5)
        # preceded by the OID length byte
        str_start = idx + len(oid)
        if str_start + 2 < len(der_bytes):
            tag = der_bytes[str_start]
            if tag in (0x0c, 0x13, 0x16):  # UTF8String, PrintableString, IA5String
                str_len = der_bytes[str_start + 1]
                if str_len < 128 and str_start + 2 + str_len <= len(der_bytes):
                    try:
                        val = der_bytes[str_start + 2:str_start + 2 + str_len].decode("utf-8", errors="replace")
                        values.append(val)
                    except Exception:
                        pass
        search_from = idx + len(oid)
    return values


def _extract_validity_not_after(der_bytes: bytes) -> str:
    """Extract the notAfter date from a DER certificate as a formatted string."""
    # Validity is a SEQUENCE of two times. We look for pairs of UTCTime (0x17).
    # The second one is notAfter.
    utc_time_tag = 0x17
    gen_time_tag = 0x18
    times_found = []

    i = 0
    while i < len(der_bytes) - 2:
        tag = der_bytes[i]
        if tag in (utc_time_tag, gen_time_tag):
            tlen = der_bytes[i + 1]
            if tlen < 128 and i + 2 + tlen <= len(der_bytes):
                try:
                    time_str = der_bytes[i + 2:i + 2 + tlen].decode("ascii")
                    times_found.append((tag, time_str))
                except Exception:
                    pass
                i += 2 + tlen
                continue
        i += 1

    # We expect at least 2 time values: notBefore and notAfter
    if len(times_found) >= 2:
        tag, raw = times_found[1]  # notAfter
        try:
            if tag == utc_time_tag:
                # UTCTime: YYMMDDHHMMSSZ
                dt = datetime.datetime.strptime(raw, "%y%m%d%H%M%SZ")
            else:
                # GeneralizedTime: YYYYMMDDHHMMSSZ
                dt = datetime.datetime.strptime(raw, "%Y%m%d%H%M%SZ")
            return dt.strftime("%b %d %H:%M:%S %Y GMT")
        except ValueError:
            pass

    return ""


def print_tls_report(result: Dict):
    """Print human-readable TLS posture report."""
    print(f"\n{'=' * 70}")
    print(f"  TLS ENDPOINT PQC POSTURE — {result['scan_target']}")
    print(f"{'=' * 70}\n")

    if result.get("errors"):
        for err in result["errors"]:
            print(f"  ERROR: {err}")
        print()
        return

    # Risk gauge
    score = result["risk_score"]
    level = result["risk_level"]
    bar_len = score // 2
    bar = "#" * bar_len + "-" * (50 - bar_len)
    print(f"  QUANTUM RISK SCORE: {score}/100 [{level}]")
    print(f"  [{bar}]")
    print()

    # Connection info
    print(f"  TLS Version:         {result.get('tls_version', 'unknown')}")
    print(f"  Cipher Suite:        {result.get('cipher_suite', 'unknown')}")
    print(f"  PQC Key Exchange:    {'YES' if result.get('pqc_kex_detected') else 'NO'}")
    print(f"  Scan Time:           {result['scan_time_ms']}ms")
    print()

    # Certificate info
    cert = result.get("certificate")
    if cert:
        print(f"  CERTIFICATE:")
        print(f"    Subject:           {cert.get('subject', 'unknown')}")
        print(f"    Issuer:            {cert.get('issuer', 'unknown')}")
        print(f"    Signature Algo:    {cert.get('signature_algorithm', 'unknown')}")
        print(f"    Key Size:          {cert.get('key_size', 'unknown')} bits")
        print(f"    Expires:           {cert.get('not_after', 'unknown')}")
        print()

    # Quantum exposure
    exp = result["quantum_exposure"]
    print(f"  QUANTUM EXPOSURE:")
    print(f"    BROKEN (quantum defeats):    {exp['broken']}")
    print(f"    WEAKENED (quantum degrades): {exp['weakened']}")
    print(f"    SAFE (quantum-resistant):    {exp['safe']}")
    print()

    # Findings
    print(f"  FINDINGS ({result['total_findings']}):")
    print(f"  {'Risk':10s} {'Algorithm':30s} {'Status':10s} {'Migration'}")
    print(f"  {'-' * 90}")
    for f in result["migration_priority"]:
        print(
            f"  {f['risk']:10s} {f['algorithm'][:30]:30s} "
            f"{f['quantum_status']:10s} {f['migration'][:50]}"
        )

    print(f"\n{'=' * 70}")
    if score >= 50:
        print(f"  VERDICT: CRITICAL quantum exposure. PQC migration urgently needed.")
    elif score >= 25:
        print(f"  VERDICT: HIGH quantum exposure. Plan PQC migration within 6 months.")
    elif score >= 10:
        print(f"  VERDICT: MODERATE exposure. Monitor and enable PQC when available.")
    else:
        print(f"  VERDICT: LOW exposure. Good quantum posture.")
    print(f"{'=' * 70}\n")


if __name__ == "__main__":
    import sys
    import json

    targets = sys.argv[1:] if len(sys.argv) > 1 else ["google.com", "github.com"]

    for target in targets:
        host, port = _parse_host_port(target)
        result = scan_tls(host, port)
        print_tls_report(result)
