#!/usr/bin/env python3
"""
AST-based Crypto Analysis Engine

Upgrades PQC scanning from regex to real static analysis using Python's
built-in `ast` module. Zero external dependencies.

Catches what regex CANNOT:
1. Alias-aware import tracking (from rsa as r)
2. Multi-line function calls
3. Variable-tracked crypto (algo = "md5"; hashlib.new(algo))
4. Crypto argument analysis (jwt.encode(..., algorithm="RS256"))
5. Class method detection (AuthService.sign_token uses jwt.encode)
"""

import ast
from typing import List, Dict, Optional, Tuple


# ── Known crypto functions and their risk profiles ──────────────────────────
# Maps fully-qualified function names to finding metadata.
# Format: "module.function" -> {category, risk, quantum_status, migration, nist_ref}

CRYPTO_FUNCTIONS: Dict[str, dict] = {
    # RSA key generation
    "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key": {
        "algorithm": "RSA Key Exchange",
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) -- NIST FIPS 203",
        "nist_ref": "NIST SP 800-208, FIPS 203",
    },
    "rsa.generate_private_key": {
        "algorithm": "RSA Key Exchange",
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) -- NIST FIPS 203",
        "nist_ref": "NIST SP 800-208, FIPS 203",
    },
    # EC key generation
    "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key": {
        "algorithm": "ECDSA",
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
        "nist_ref": "NIST FIPS 186-5, FIPS 204",
    },
    "ec.generate_private_key": {
        "algorithm": "ECDSA",
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
        "nist_ref": "NIST FIPS 186-5, FIPS 204",
    },
    # DSA key generation
    "cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key": {
        "algorithm": "DSA",
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
        "nist_ref": "NIST FIPS 186-5",
    },
    "dsa.generate_private_key": {
        "algorithm": "DSA",
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
        "nist_ref": "NIST FIPS 186-5",
    },
    # Hashlib
    "hashlib.md5": {
        "algorithm": "MD5",
        "category": "hash",
        "risk": "HIGH",
        "quantum_status": "WEAKENED",
        "migration": "SHA-256 or SHA-3-256 minimum. SHA-384+ recommended.",
        "nist_ref": "NIST SP 800-131A (MD5 deprecated)",
    },
    "hashlib.sha1": {
        "algorithm": "SHA-1",
        "category": "hash",
        "risk": "HIGH",
        "quantum_status": "WEAKENED",
        "migration": "SHA-256 or SHA-3-256 minimum",
        "nist_ref": "NIST SP 800-131A (SHA-1 deprecated)",
    },
    "hashlib.new": {
        "algorithm": "_check_args",  # resolved from arguments
        "category": "hash",
        "risk": "HIGH",
        "quantum_status": "WEAKENED",
        "migration": "SHA-256 or SHA-3-256 minimum",
        "nist_ref": "NIST SP 800-131A",
    },
    # JWT
    "jwt.encode": {
        "algorithm": "_check_args",
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
        "nist_ref": "NIST FIPS 204",
    },
    "jwt.decode": {
        "algorithm": "_check_args",
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
        "nist_ref": "NIST FIPS 204",
    },
    # SSL
    "ssl.SSLContext": {
        "algorithm": "_check_args",
        "category": "protocol",
        "risk": "HIGH",
        "quantum_status": "WEAKENED",
        "migration": "TLS 1.3 with PQ key exchange",
        "nist_ref": "NIST SP 800-52 Rev. 2",
    },
    # Java-style
    "Cipher.getInstance": {
        "algorithm": "_check_args",
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) -- NIST FIPS 203",
        "nist_ref": "NIST SP 800-208, FIPS 203",
    },
    "KeyPairGenerator.getInstance": {
        "algorithm": "_check_args",
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) -- NIST FIPS 203",
        "nist_ref": "NIST SP 800-208, FIPS 203",
    },
    # Node.js crypto
    "crypto.createHash": {
        "algorithm": "_check_args",
        "category": "hash",
        "risk": "HIGH",
        "quantum_status": "WEAKENED",
        "migration": "SHA-256 or SHA-3-256 minimum",
        "nist_ref": "NIST SP 800-131A",
    },
    "crypto.generateKeyPairSync": {
        "algorithm": "_check_args",
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) -- NIST FIPS 203",
        "nist_ref": "NIST SP 800-208, FIPS 203",
    },
    # Paramiko
    "paramiko.RSAKey": {
        "algorithm": "RSA Key Exchange",
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) -- NIST FIPS 203",
        "nist_ref": "NIST SP 800-208, FIPS 203",
    },
    "paramiko.ECDSAKey": {
        "algorithm": "ECDSA",
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
        "nist_ref": "NIST FIPS 186-5, FIPS 204",
    },
    # PyCryptodome
    "PKCS1_OAEP.new": {
        "algorithm": "RSA Key Exchange",
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) -- NIST FIPS 203",
        "nist_ref": "NIST SP 800-208, FIPS 203",
    },
    "PKCS1_v1_5.new": {
        "algorithm": "RSA Key Exchange",
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) -- NIST FIPS 203",
        "nist_ref": "NIST SP 800-208, FIPS 203",
    },
}

# Argument values that indicate quantum-vulnerable algorithms
VULNERABLE_ALGO_ARGS = {
    "md5": {"algorithm": "MD5", "risk": "HIGH", "quantum_status": "WEAKENED",
            "category": "hash",
            "migration": "SHA-256 or SHA-3-256 minimum. SHA-384+ recommended.",
            "nist_ref": "NIST SP 800-131A (MD5 deprecated)"},
    "sha1": {"algorithm": "SHA-1", "risk": "HIGH", "quantum_status": "WEAKENED",
             "category": "hash",
             "migration": "SHA-256 or SHA-3-256 minimum",
             "nist_ref": "NIST SP 800-131A (SHA-1 deprecated)"},
    "rs256": {"algorithm": "RSA Signature (RS256)", "risk": "CRITICAL",
              "quantum_status": "BROKEN", "category": "signature",
              "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
              "nist_ref": "NIST FIPS 204"},
    "rs384": {"algorithm": "RSA Signature (RS384)", "risk": "CRITICAL",
              "quantum_status": "BROKEN", "category": "signature",
              "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
              "nist_ref": "NIST FIPS 204"},
    "rs512": {"algorithm": "RSA Signature (RS512)", "risk": "CRITICAL",
              "quantum_status": "BROKEN", "category": "signature",
              "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
              "nist_ref": "NIST FIPS 204"},
    "es256": {"algorithm": "ECDSA Signature (ES256)", "risk": "CRITICAL",
              "quantum_status": "BROKEN", "category": "signature",
              "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
              "nist_ref": "NIST FIPS 204"},
    "es384": {"algorithm": "ECDSA Signature (ES384)", "risk": "CRITICAL",
              "quantum_status": "BROKEN", "category": "signature",
              "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
              "nist_ref": "NIST FIPS 204"},
    "rsa": {"algorithm": "RSA Key Exchange", "risk": "CRITICAL",
            "quantum_status": "BROKEN", "category": "key_exchange",
            "migration": "ML-KEM 768 (CRYSTALS-Kyber) -- NIST FIPS 203",
            "nist_ref": "NIST SP 800-208, FIPS 203"},
    "dsa": {"algorithm": "DSA", "risk": "CRITICAL",
            "quantum_status": "BROKEN", "category": "signature",
            "migration": "ML-DSA 65 (CRYSTALS-Dilithium) -- NIST FIPS 204",
            "nist_ref": "NIST FIPS 186-5"},
}

# SSL protocol constants that are vulnerable
VULNERABLE_SSL_PROTOCOLS = {
    "ssl.PROTOCOL_TLSv1": "TLS 1.0 (Deprecated)",
    "ssl.PROTOCOL_TLSv1_1": "TLS 1.1 (Deprecated)",
    "ssl.PROTOCOL_TLSv1_2": "TLS 1.2 (Needs PQ upgrade)",
    "ssl.PROTOCOL_SSLv23": "SSLv23 (Deprecated)",
    "ssl.PROTOCOL_SSLv3": "SSLv3 (Broken)",
}

# RSA-related Cipher.getInstance patterns
RSA_CIPHER_PREFIXES = ("rsa/", "rsa")


class _CryptoVisitor(ast.NodeVisitor):
    """AST visitor that finds crypto usage with alias resolution and
    constant propagation."""

    def __init__(self, filepath: str, source_lines: List[str]):
        self.filepath = filepath
        self.source_lines = source_lines
        self.findings: List[dict] = []

        # import alias map: alias -> fully qualified module path
        # e.g. {"r": "cryptography.hazmat.primitives.asymmetric.rsa"}
        self.import_map: Dict[str, str] = {}

        # constant assignment map: variable name -> string value
        # Simple single-assignment constant propagation
        self.const_map: Dict[str, str] = {}

        # Current class name for method-level reporting
        self._current_class: Optional[str] = None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.import_map[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            full_path = f"{module}.{alias.name}" if module else alias.name
            name = alias.asname if alias.asname else alias.name
            self.import_map[name] = full_path
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track simple string constant assignments for propagation."""
        if (len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            self.const_map[node.targets[0].id] = node.value.value
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        old_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old_class

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._resolve_call_name(node.func)
        if func_name:
            self._check_crypto_call(node, func_name)
        self.generic_visit(node)

    # ── Name resolution ─────────────────────────────────────────────────

    def _resolve_call_name(self, node: ast.expr) -> Optional[str]:
        """Resolve a call target to a fully-qualified name using the
        import alias map."""
        if isinstance(node, ast.Name):
            # Direct name: could be an imported alias
            resolved = self.import_map.get(node.id, node.id)
            return resolved
        elif isinstance(node, ast.Attribute):
            # attr chain: obj.method or obj.sub.method
            parts = self._unpack_attribute(node)
            if not parts:
                return None

            # Try resolving the leftmost part through imports
            head = parts[0]
            resolved_head = self.import_map.get(head, head)
            full_name = ".".join([resolved_head] + parts[1:])
            return full_name
        return None

    def _unpack_attribute(self, node: ast.expr) -> Optional[List[str]]:
        """Unpack a.b.c into ["a", "b", "c"]."""
        parts: List[str] = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            parts.reverse()
            return parts
        return None

    # ── Crypto checking ─────────────────────────────────────────────────

    def _check_crypto_call(self, node: ast.Call, func_name: str) -> None:
        """Check if a resolved function call matches known crypto patterns."""
        # Try exact match first
        info = CRYPTO_FUNCTIONS.get(func_name)

        # Try suffix matching (handles deep module paths)
        if info is None:
            for known_func, known_info in CRYPTO_FUNCTIONS.items():
                if func_name.endswith(f".{known_func}") or func_name == known_func:
                    info = known_info
                    break

        # Try matching just the last two parts (e.g. "rsa.generate_private_key")
        if info is None:
            parts = func_name.rsplit(".", 1)
            if len(parts) == 2:
                short_name = f"{parts[0].rsplit('.', 1)[-1]}.{parts[1]}"
                info = CRYPTO_FUNCTIONS.get(short_name)

        # Try prefix matching: func_name starts with a known crypto object
        # e.g. "paramiko.RSAKey.generate" starts with "paramiko.RSAKey"
        if info is None:
            for known_func, known_info in CRYPTO_FUNCTIONS.items():
                if func_name.startswith(f"{known_func}."):
                    info = known_info
                    break

        if info is None:
            return

        algorithm = info["algorithm"]
        category = info["category"]
        risk = info["risk"]
        quantum_status = info["quantum_status"]
        migration = info["migration"]
        nist_ref = info["nist_ref"]

        # If algorithm depends on arguments, resolve it
        if algorithm == "_check_args":
            resolved = self._resolve_algo_from_args(node, func_name)
            if resolved is None:
                return  # Could not determine vulnerability from args
            algorithm = resolved["algorithm"]
            risk = resolved.get("risk", risk)
            quantum_status = resolved.get("quantum_status", quantum_status)
            category = resolved.get("category", category)
            migration = resolved.get("migration", migration)
            nist_ref = resolved.get("nist_ref", nist_ref)

        line_num = node.lineno
        usage = self._get_source_line(line_num)

        # Add class context if inside a method
        location = func_name
        if self._current_class:
            # Find enclosing function
            location = f"{self._current_class}.{func_name}"

        self.findings.append({
            "file": self.filepath,
            "line": line_num,
            "algorithm": algorithm,
            "category": category,
            "risk": risk,
            "raw_risk": risk,
            "quantum_status": quantum_status,
            "context": "operation",
            "usage": usage.strip()[:120],
            "migration": migration,
            "nist_ref": nist_ref,
            "ast_resolved": True,
            "resolved_name": func_name,
            "class_context": self._current_class,
        })

    def _resolve_algo_from_args(self, node: ast.Call, func_name: str) -> Optional[dict]:
        """Inspect call arguments to determine the specific algorithm."""
        # Check for hashlib.new("md5") / hashlib.new(algo) where algo = "md5"
        if func_name.endswith("hashlib.new") or func_name == "hashlib.new":
            return self._check_hash_arg(node)

        # Check for jwt.encode(..., algorithm="RS256")
        if func_name.endswith("jwt.encode") or func_name == "jwt.encode":
            return self._check_jwt_algo(node)

        if func_name.endswith("jwt.decode") or func_name == "jwt.decode":
            return self._check_jwt_algo(node)

        # Check for ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        if func_name.endswith("ssl.SSLContext") or func_name == "ssl.SSLContext":
            return self._check_ssl_protocol(node)

        # Check for crypto.createHash("md5")
        if func_name.endswith("crypto.createHash") or func_name == "crypto.createHash":
            return self._check_hash_arg(node)

        # Check for crypto.generateKeyPairSync("rsa")
        if func_name.endswith("crypto.generateKeyPairSync") or func_name == "crypto.generateKeyPairSync":
            return self._check_keygen_arg(node)

        # Check for Cipher.getInstance("RSA/...")
        if func_name.endswith("Cipher.getInstance") or func_name == "Cipher.getInstance":
            return self._check_cipher_arg(node)

        # Check for KeyPairGenerator.getInstance("RSA")
        if func_name.endswith("KeyPairGenerator.getInstance") or func_name == "KeyPairGenerator.getInstance":
            return self._check_keygen_arg(node)

        return None

    def _check_hash_arg(self, node: ast.Call) -> Optional[dict]:
        """Check first positional arg for hash algorithm name."""
        if node.args:
            val = self._resolve_value(node.args[0])
            if val is not None:
                return VULNERABLE_ALGO_ARGS.get(val.lower())
        return None

    def _check_jwt_algo(self, node: ast.Call) -> Optional[dict]:
        """Check algorithm keyword arg in jwt.encode/decode."""
        # Check keyword: algorithm="RS256"
        for kw in node.keywords:
            if kw.arg == "algorithm":
                val = self._resolve_value(kw.value)
                if val is not None:
                    return VULNERABLE_ALGO_ARGS.get(val.lower())
            elif kw.arg == "algorithms":
                # jwt.decode(..., algorithms=["RS256"])
                if isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        val = self._resolve_value(elt)
                        if val is not None:
                            result = VULNERABLE_ALGO_ARGS.get(val.lower())
                            if result:
                                return result
        return None

    def _check_ssl_protocol(self, node: ast.Call) -> Optional[dict]:
        """Check for ssl.PROTOCOL_TLSv1 etc."""
        if node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Attribute):
                parts = self._unpack_attribute(arg)
                if parts:
                    full = ".".join(parts)
                    # Resolve through import map
                    head = parts[0]
                    resolved_head = self.import_map.get(head, head)
                    resolved_full = ".".join([resolved_head] + parts[1:])

                    for proto_name, proto_desc in VULNERABLE_SSL_PROTOCOLS.items():
                        if resolved_full == proto_name or full == proto_name:
                            return {
                                "algorithm": proto_desc,
                                "risk": "HIGH",
                                "quantum_status": "WEAKENED",
                                "category": "protocol",
                                "migration": "TLS 1.3 with PQ key exchange",
                                "nist_ref": "NIST SP 800-52 Rev. 2",
                            }
        return None

    def _check_keygen_arg(self, node: ast.Call) -> Optional[dict]:
        """Check first arg for key type (rsa, dsa, etc.)."""
        if node.args:
            val = self._resolve_value(node.args[0])
            if val is not None:
                return VULNERABLE_ALGO_ARGS.get(val.lower())
        return None

    def _check_cipher_arg(self, node: ast.Call) -> Optional[dict]:
        """Check for RSA in Cipher.getInstance arg."""
        if node.args:
            val = self._resolve_value(node.args[0])
            if val is not None:
                val_lower = val.lower()
                if val_lower.startswith(RSA_CIPHER_PREFIXES):
                    return VULNERABLE_ALGO_ARGS.get("rsa")
        return None

    def _resolve_value(self, node: ast.expr) -> Optional[str]:
        """Resolve a node to a string value via constant propagation."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.const_map.get(node.id)
        return None

    def _get_source_line(self, lineno: int) -> str:
        """Get the source line (1-indexed)."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""


def analyze_python_ast(filepath: str, source: str) -> List[dict]:
    """Analyze Python source using AST. Returns findings compatible with
    CryptoFinding format.

    Args:
        filepath: Relative path for reporting (matches CryptoFinding.file).
        source: Python source code string.

    Returns:
        List of finding dicts with keys matching CryptoFinding fields plus
        extra AST-specific fields (ast_resolved, resolved_name, class_context).
    """
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return []  # Not valid Python; skip silently

    source_lines = source.splitlines()
    visitor = _CryptoVisitor(filepath, source_lines)
    visitor.visit(tree)
    return visitor.findings
