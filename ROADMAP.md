# quantum-mcp — Product Roadmap

## Shipped (v0.1.0)
- [x] QRNG — quantum random bytes (simulator + IBM)
- [x] PQC Scanner — find quantum-vulnerable crypto in codebases
- [x] Backend listing — IBM 127Q, Wukong 72Q, local sim
- [x] Circuit runner — execute QASM on any backend
- [x] Telegram integration — /quantum commands in Segundo PA
- [x] Bastion route — quantum.overseerclaw.uk live with auto-SSL
- [x] GitHub repo — github.com/Miles0sage/quantum-mcp

## Next: Quantum-Fair Oracle (v0.2.0)
Commit-reveal oracle using quantum randomness for provably fair draws.
- [ ] Commit endpoint — run circuit, hash result, publish commitment
- [ ] Reveal endpoint — reveal value after timeout
- [ ] Verify endpoint — anyone can verify hash matches
- [ ] Audit trail — immutable log of all draws
- [ ] Batch mode — queue multiple draws per circuit execution
- [ ] Premium tier — real IBM QPU for paying customers
- [ ] API keys — rate limiting, usage tracking

## Future: Quantum-Verified AI (v0.3.0)
Every AI agent output stamped with quantum random nonce.
- [ ] Attestation API — sign agent outputs with quantum nonce
- [ ] Verification — prove output wasn't tampered with
- [ ] Integration with OpenClaw gateway
- [ ] Use case: regulated industries (finance, healthcare, legal)

## Future: Natural Language → Quantum Circuit (v0.4.0)
AI agent translates business problems into quantum circuits.
- [ ] Problem classifier — routing, optimization, sampling, ML
- [ ] QAOA circuit generator for combinatorial optimization
- [ ] VQE circuit generator for chemistry/materials
- [ ] Auto-backend selection (cheapest that can handle the circuit)
- [ ] Plain English in → business answer out

## Future: Auto-PQC Migration Agent (v0.5.0)
Don't just scan — automatically fix quantum-vulnerable crypto.
- [ ] RSA → ML-KEM auto-replacement
- [ ] ECDSA → ML-DSA auto-replacement
- [ ] MD5/SHA1 → SHA-256 auto-replacement
- [ ] Generate PR with changes + test results
- [ ] One command: /quantum harden /path/to/project

## Business Model
- Free tier: 100 oracle draws/mo (simulator), PQC scanning
- Pro ($49/mo): 1000 draws/mo (real IBM quantum), priority
- Enterprise ($499/mo): unlimited, SLA, custom integration
- Per-draw: $0.10-1.00 for one-off oracle resolution

## Key Insight
Nobody has connected AI agents + quantum computing + MCP protocol.
The quantum-mcp IS the glue layer. Everything else is a feature.
