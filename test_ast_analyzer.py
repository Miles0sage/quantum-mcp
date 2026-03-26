#!/usr/bin/env python3
"""
Tests for AST-based Crypto Analysis Engine.

Proves AST catches what regex misses:
1. Aliased imports
2. Multi-line function calls
3. Variable-tracked algo names
4. Keyword argument detection
5. Class method crypto usage
6. Nested function calls
7. Multiple aliases in one file
8. Lambda/comprehension with crypto
"""

import unittest
from ast_analyzer import analyze_python_ast


class TestAliasedImport(unittest.TestCase):
    """1. AST resolves aliased imports that regex misses."""

    def test_rsa_alias(self):
        source = '''\
from cryptography.hazmat.primitives.asymmetric import rsa as r
key = r.generate_private_key(65537, 2048)
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1, "Should detect aliased rsa.generate_private_key")
        f = findings[0]
        self.assertEqual(f["algorithm"], "RSA Key Exchange")
        self.assertEqual(f["risk"], "CRITICAL")
        self.assertEqual(f["quantum_status"], "BROKEN")
        self.assertTrue(f["ast_resolved"])

    def test_ec_alias(self):
        source = '''\
from cryptography.hazmat.primitives.asymmetric import ec as elliptic
key = elliptic.generate_private_key(elliptic.SECP256R1())
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1, "Should detect aliased ec.generate_private_key")
        self.assertEqual(findings[0]["algorithm"], "ECDSA")


class TestMultiLineCall(unittest.TestCase):
    """2. AST parses multi-line function calls that regex sees only one line of."""

    def test_multi_line_rsa(self):
        source = '''\
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1, "Should detect multi-line rsa.generate_private_key")
        self.assertEqual(findings[0]["algorithm"], "RSA Key Exchange")

    def test_multi_line_jwt(self):
        source = '''\
import jwt
token = jwt.encode(
    {"sub": "user"},
    "secret",
    algorithm="RS256",
)
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1, "Should detect multi-line jwt.encode with RS256")
        self.assertIn("RS256", findings[0]["algorithm"])


class TestVariableTracking(unittest.TestCase):
    """3. AST resolves variable values that regex cannot."""

    def test_hashlib_new_with_variable(self):
        source = '''\
import hashlib
algo = "md5"
h = hashlib.new(algo)
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1, "Should detect variable-tracked md5")
        self.assertEqual(findings[0]["algorithm"], "MD5")

    def test_hashlib_new_sha1_variable(self):
        source = '''\
import hashlib
hash_name = "sha1"
digest = hashlib.new(hash_name)
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["algorithm"], "SHA-1")

    def test_variable_in_jwt(self):
        source = '''\
import jwt
signing_algo = "RS256"
token = jwt.encode(payload, key, algorithm=signing_algo)
'''
        # Note: this requires the variable to be resolvable from kwargs
        # Our constant propagation handles Name nodes in keyword values
        findings = analyze_python_ast("test.py", source)
        # The kwarg value is a Name node, which we resolve via const_map
        self.assertTrue(len(findings) >= 1, "Should detect variable RS256 in jwt.encode")


class TestKeywordArgDetection(unittest.TestCase):
    """4. AST inspects keyword arguments to detect specific algorithms."""

    def test_jwt_algorithm_kwarg(self):
        source = '''\
import jwt
token = jwt.encode(payload, key, algorithm="RS256")
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        self.assertIn("RS256", findings[0]["algorithm"])
        self.assertEqual(findings[0]["risk"], "CRITICAL")

    def test_jwt_decode_algorithms_list(self):
        source = '''\
import jwt
data = jwt.decode(token, key, algorithms=["RS256"])
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        self.assertIn("RS256", findings[0]["algorithm"])

    def test_ssl_protocol_arg(self):
        source = '''\
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1, "Should detect ssl.PROTOCOL_TLSv1")
        self.assertIn("TLS 1.0", findings[0]["algorithm"])

    def test_hashlib_new_string_literal(self):
        source = '''\
import hashlib
h = hashlib.new("md5")
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["algorithm"], "MD5")


class TestClassMethodDetection(unittest.TestCase):
    """5. AST detects crypto usage inside class methods."""

    def test_class_method_jwt(self):
        source = '''\
import jwt

class AuthService:
    def sign_token(self):
        return jwt.encode(self.payload, self.key, algorithm="RS256")
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["class_context"], "AuthService")
        self.assertIn("RS256", findings[0]["algorithm"])

    def test_class_method_hashlib(self):
        source = '''\
import hashlib

class DataProcessor:
    def compute_hash(self, data):
        return hashlib.md5(data).hexdigest()
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["class_context"], "DataProcessor")
        self.assertEqual(findings[0]["algorithm"], "MD5")


class TestNestedFunctionCalls(unittest.TestCase):
    """6. AST handles nested function calls."""

    def test_nested_hashlib(self):
        source = '''\
import hashlib
result = base64.b64encode(hashlib.md5(data.encode()).digest())
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1, "Should detect hashlib.md5 inside nesting")
        self.assertEqual(findings[0]["algorithm"], "MD5")

    def test_nested_jwt_in_response(self):
        source = '''\
import jwt
return JsonResponse({"token": jwt.encode(payload, key, algorithm="RS256")})
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        self.assertIn("RS256", findings[0]["algorithm"])


class TestMultipleAliases(unittest.TestCase):
    """7. AST tracks multiple aliases in one file."""

    def test_multiple_imports(self):
        source = '''\
from cryptography.hazmat.primitives.asymmetric import rsa as r
from cryptography.hazmat.primitives.asymmetric import ec as e
import hashlib as hl

rsa_key = r.generate_private_key(65537, 2048)
ec_key = e.generate_private_key(e.SECP256R1())
digest = hl.md5(b"data")
'''
        findings = analyze_python_ast("test.py", source)
        algorithms = {f["algorithm"] for f in findings}
        self.assertIn("RSA Key Exchange", algorithms, "Should detect aliased RSA")
        self.assertIn("ECDSA", algorithms, "Should detect aliased ECDSA")
        self.assertIn("MD5", algorithms, "Should detect aliased hashlib.md5")
        self.assertTrue(len(findings) >= 3)


class TestLambdaComprehension(unittest.TestCase):
    """8. AST detects crypto in lambdas and comprehensions."""

    def test_lambda_with_hashlib(self):
        source = '''\
import hashlib
hasher = lambda x: hashlib.md5(x.encode()).hexdigest()
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1, "Should detect hashlib.md5 in lambda")
        self.assertEqual(findings[0]["algorithm"], "MD5")

    def test_list_comprehension_with_hash(self):
        source = '''\
import hashlib
hashes = [hashlib.sha1(item.encode()).hexdigest() for item in items]
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1, "Should detect hashlib.sha1 in comprehension")
        self.assertEqual(findings[0]["algorithm"], "SHA-1")

    def test_generator_expression_with_crypto(self):
        source = '''\
import hashlib
gen = (hashlib.md5(x).digest() for x in data)
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["algorithm"], "MD5")


class TestEdgeCases(unittest.TestCase):
    """Additional edge cases for robustness."""

    def test_syntax_error_source_returns_empty(self):
        source = "def broken(:\n    pass"
        findings = analyze_python_ast("broken.py", source)
        self.assertEqual(findings, [])

    def test_safe_algorithm_not_flagged(self):
        source = '''\
import hashlib
h = hashlib.sha256(b"data")
'''
        findings = analyze_python_ast("test.py", source)
        self.assertEqual(len(findings), 0, "SHA-256 should not be flagged")

    def test_paramiko_rsa_key(self):
        source = '''\
import paramiko
key = paramiko.RSAKey.generate(2048)
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["algorithm"], "RSA Key Exchange")

    def test_pkcs1_oaep(self):
        source = '''\
from Crypto.Cipher import PKCS1_OAEP
cipher = PKCS1_OAEP.new(key)
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["algorithm"], "RSA Key Exchange")

    def test_dsa_generate(self):
        source = '''\
from cryptography.hazmat.primitives.asymmetric import dsa
key = dsa.generate_private_key(key_size=2048)
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["algorithm"], "DSA")

    def test_finding_has_all_required_fields(self):
        """Verify findings match CryptoFinding dataclass fields."""
        source = '''\
import hashlib
h = hashlib.md5(b"test")
'''
        findings = analyze_python_ast("test.py", source)
        self.assertTrue(len(findings) >= 1)
        required = {"file", "line", "algorithm", "category", "risk",
                     "raw_risk", "quantum_status", "context", "usage",
                     "migration", "nist_ref"}
        for f in findings:
            self.assertTrue(required.issubset(f.keys()),
                            f"Missing fields: {required - f.keys()}")


if __name__ == "__main__":
    unittest.main()
