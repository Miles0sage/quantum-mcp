"""PQC Verification Service — Sign and verify code as quantum-safe.

This is the REAL product: not just scanning for vulnerabilities,
but providing quantum-safe signatures that CERTIFY code is secure.

Usage:
    from pqc_verify import sign_code, verify_code, generate_keypair

    # Generate org keys (once)
    pub, priv = generate_keypair()

    # Sign code after security review passes
    sig = sign_code(priv, code_hash)

    # Anyone can verify
    valid = verify_code(pub, code_hash, sig)
"""

from quantcrypt.dss import MLDSA_65
from quantcrypt.kem import MLKEM_768
import hashlib
import json
import time


def generate_keypair():
    """Generate ML-DSA 65 keypair for quantum-safe code signing."""
    dss = MLDSA_65()
    pub, priv = dss.keygen()
    return pub, priv


def sign_code(private_key: bytes, code: str, metadata: dict = None) -> dict:
    """Sign code with quantum-safe signature after security review."""
    dss = MLDSA_65()

    code_hash = hashlib.sha256(code.encode()).hexdigest()

    payload = json.dumps({
        "code_hash": code_hash,
        "timestamp": time.time(),
        "algorithm": "ML-DSA-65",
        "standard": "NIST FIPS 204",
        **(metadata or {}),
    }, sort_keys=True).encode()

    signature = dss.sign(private_key, payload)

    return {
        "code_hash": code_hash,
        "signature": signature.hex(),
        "algorithm": "ML-DSA-65",
        "payload": payload.decode(),
        "public_key_size": "1952 bytes",
        "signature_size": f"{len(signature)} bytes",
        "quantum_safe": True,
    }


def verify_code(public_key: bytes, code: str, attestation: dict) -> dict:
    """Verify quantum-safe code signature."""
    dss = MLDSA_65()

    code_hash = hashlib.sha256(code.encode()).hexdigest()
    if code_hash != attestation["code_hash"]:
        return {"valid": False, "reason": "Code hash mismatch — code was modified"}

    signature = bytes.fromhex(attestation["signature"])
    payload = attestation["payload"].encode()

    try:
        valid = dss.verify(public_key, payload, signature)
        return {
            "valid": valid,
            "algorithm": "ML-DSA-65",
            "quantum_safe": True,
            "code_hash": code_hash,
        }
    except Exception as e:
        return {"valid": False, "reason": str(e)}


def exchange_key():
    """Perform quantum-safe key exchange using ML-KEM 768."""
    kem = MLKEM_768()
    pub, priv = kem.keygen()
    ciphertext, shared_secret = kem.encaps(pub)
    return {
        "public_key": pub,
        "private_key": priv,
        "ciphertext": ciphertext,
        "shared_secret": shared_secret,
        "algorithm": "ML-KEM-768",
        "standard": "NIST FIPS 203",
        "quantum_safe": True,
    }


if __name__ == "__main__":
    print("=== PQC Verification Service Demo ===\n")

    # 1. Generate keys for an organization
    print("1. Generate quantum-safe signing keys...")
    pub, priv = generate_keypair()
    print(f"   Public key: {len(pub)} bytes")
    print(f"   Private key: {len(priv)} bytes\n")

    # 2. Code passes security review → sign it
    code = 'def hello(): return "quantum-safe verified"'
    print(f"2. Signing code: {code}")
    attestation = sign_code(priv, code, {"reviewer": "CodeGuard Pro", "scan_passed": True})
    print(f"   Hash: {attestation['code_hash'][:20]}...")
    print(f"   Signature: {attestation['signature'][:30]}...")
    print(f"   Algorithm: {attestation['algorithm']}\n")

    # 3. Anyone can verify
    print("3. Verifying...")
    result = verify_code(pub, code, attestation)
    print(f"   Valid: {result['valid']}")
    print(f"   Quantum-safe: {result['quantum_safe']}\n")

    # 4. Tampered code fails
    print("4. Tampered code verification...")
    tampered = verify_code(pub, code + " # hacked", attestation)
    print(f"   Valid: {tampered['valid']}")
    print(f"   Reason: {tampered.get('reason', 'n/a')}\n")

    # 5. Key exchange
    print("5. Quantum-safe key exchange...")
    kex = exchange_key()
    print(f"   Algorithm: {kex['algorithm']}")
    print(f"   Shared secret: {kex['shared_secret'].hex()[:30]}...")
    print(f"   Quantum-safe: {kex['quantum_safe']}")
