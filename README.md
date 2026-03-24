# quantum-mcp

**Quantum computing MCP server. QRNG, PQC scanning, circuit execution, multi-backend routing.**

```bash
python3 server.py  # starts on :8200
```

## Tools

| Tool | What it does |
|------|-------------|
| `quantum_random` | Generate true quantum random bytes (simulator or IBM QPU) |
| `quantum_pqc_scan` | Scan codebases for quantum-vulnerable crypto (RSA, ECDSA, DH, MD5) |
| `quantum_backends` | List available quantum backends with costs |
| `quantum_circuit` | Run OpenQASM circuits on any backend |

## Quick Start

```bash
# QRNG — 256 bits of quantum randomness
curl -X POST http://localhost:8200/call \
  -H "Content-Type: application/json" \
  -d '{"tool":"quantum_random","args":{"n_bytes":32}}'

# PQC Scan — find quantum-vulnerable crypto in your code
curl -X POST http://localhost:8200/call \
  -H "Content-Type: application/json" \
  -d '{"tool":"quantum_pqc_scan","args":{"path":"/path/to/project"}}'

# List backends
curl -X POST http://localhost:8200/call \
  -H "Content-Type: application/json" \
  -d '{"tool":"quantum_backends","args":{}}'
```

## Backends

| Backend | Qubits | Cost | Auth |
|---------|--------|------|------|
| Local simulator | 32 | Free | None |
| IBM Quantum | 127 | $96/min (10 free min/month) | `IBM_QUANTUM_TOKEN` |
| Origin Wukong | 72 | Free | `ORIGIN_QUANTUM_TOKEN` |

## Environment Variables

```
IBM_QUANTUM_TOKEN=your_ibm_cloud_api_key
IBM_QUANTUM_CRN=your_cloud_resource_name
ORIGIN_QUANTUM_TOKEN=your_origin_token
QUANTUM_MCP_PORT=8200
```

## PQC Vulnerabilities Detected

| Vulnerability | Risk | Quantum Threat | Migration |
|--------------|------|----------------|-----------|
| RSA | CRITICAL | Shor's algorithm | ML-KEM (Kyber) |
| ECDSA/ECDH | CRITICAL | Shor's algorithm | ML-DSA (Dilithium) |
| Diffie-Hellman | CRITICAL | Period-finding | ML-KEM |
| DSA | HIGH | Quantum attacks | ML-DSA / SLH-DSA |
| SHA-1 | HIGH | Grover's algorithm | SHA-256 / SHA-3 |
| MD5 | HIGH | Grover's + classical | SHA-256 / SHA-3 |
| AES-128 | MEDIUM | Grover's halves security | AES-256 |

## Stack

- Python + FastAPI + Qiskit 2.3.1
- IBM Quantum Runtime 0.46.1
- Local Qiskit StatevectorSampler
- Bastion edge proxy (auto-SSL)

Built with Claude Code.
