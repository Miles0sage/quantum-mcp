# PQC Quantum Safety Check

> GitHub Agentic Workflow description for automated post-quantum cryptography scanning.

## Description

Automatically scan pull requests and pushes to main for quantum-vulnerable cryptography. Detects RSA, ECDSA, DH, DSA, weak hashes (MD5, SHA-1), and short symmetric keys (AES-128). Generates a Crypto Bill of Materials (CBOM) in CycloneDX 1.6 format and uploads SARIF results to GitHub Code Scanning.

## Trigger

- On `pull_request` targeting `main`
- On `push` to `main`

## Steps

1. **Scan the codebase for quantum-vulnerable crypto patterns.** Run the PQC Posture Scanner against the repository root. The scanner walks all source files (.py, .js, .ts, .go, .rs, .java, .rb, .php, .c, .cpp, .cs) and matches against known vulnerable patterns: RSA key generation, ECDSA signing, Diffie-Hellman exchange, DSA, MD5/SHA-1 hashing, AES-128. Each finding is tagged with a risk level (CRITICAL, HIGH, MEDIUM, LOW), the NIST migration path, and whether it appears in production or test code.

2. **Generate a CBOM (Crypto Bill of Materials) in CycloneDX 1.6 format.** The CBOM catalogs every cryptographic algorithm found in the codebase, including key sizes, usage locations, quantum vulnerability status, and recommended replacements. Output is saved as `cbom.json` and uploaded as a build artifact.

3. **If CRITICAL findings are found, comment on the PR with migration recommendations.** The comment includes the risk score (0-100), total findings count, production findings count, and a table of the top 5 highest-risk findings with file locations and NIST migration guidance (e.g., "RSA -> ML-KEM", "ECDSA -> ML-DSA").

4. **Upload SARIF results for GitHub Code Scanning integration.** Findings appear inline in the Code Scanning tab and on the PR diff. Each finding links to the NIST PQC project page and includes the specific migration recommendation.

## Example Output

PR comment posted by the workflow:

```
## PQC Posture Scan Results

| Metric | Value |
|--------|-------|
| **Risk Score** | 72/100 |
| **Risk Level** | CRITICAL |
| **Total Findings** | 14 |
| **Production Findings** | 9 |
| **Status** | FAIL |

### Top Findings

| File | Line | Algorithm | Risk | Migration |
|------|------|-----------|------|-----------|
| `src/auth.py` | 45 | RSA-2048 | CRITICAL | Migrate to ML-KEM (CRYSTALS-Kyber) |
| `src/auth.py` | 82 | ECDSA P-256 | CRITICAL | Migrate to ML-DSA (CRYSTALS-Dilithium) |
| `lib/crypto.js` | 12 | DH | CRITICAL | Migrate to ML-KEM for key exchange |
| `utils/hash.py` | 7 | MD5 | HIGH | Use SHA-256 or SHA-3 |
| `utils/hash.py` | 19 | SHA-1 | HIGH | Use SHA-256 or SHA-3 |
```

## Configuration Options

### fail-on

Set the minimum risk level that causes the workflow to fail. Default: `CRITICAL`.

```yaml
# Fail on HIGH or above
--fail-on HIGH

# Fail on any finding
--fail-on LOW

# Never fail (report only)
# Omit --fail-on entirely
```

### context

Filter findings by where they appear. Default: `prod` in the agentic workflow, `all` in CLI.

```yaml
# Production code only (excludes test files)
--context prod

# Test code only
--context test

# Everything
--context all
```

### min-risk

Only show findings at a given risk level or above.

```yaml
# Only CRITICAL and HIGH
--min-risk HIGH

# Everything including LOW
--min-risk LOW
```

### SARIF and CBOM output

Always generated in the agentic workflow. For CLI usage:

```bash
pqc-scan . --sarif results.sarif --cbom cbom.json
```

## Integration with Other Agentic Workflows

This workflow produces two artifacts other workflows can consume:

- **`pqc-results.sarif`** -- Standard SARIF 2.1.0, compatible with any tool that reads GitHub Code Scanning results.
- **`cbom.json`** -- CycloneDX 1.6 Crypto BOM, machine-readable inventory of all cryptographic usage. Feed this into supply chain tools, compliance pipelines, or a Copilot agent that generates migration PRs.

## Agents That Can Use This

- **Copilot CLI**: `gh copilot suggest "fix quantum-vulnerable crypto in this PR based on pqc-results.sarif"`
- **Claude Code**: Add `quantum-mcp` as an MCP server and use the `pqc_posture_scan` tool directly.
- **OpenAI Codex**: Reference the SARIF output in a Codex workflow step to auto-generate migration patches.
