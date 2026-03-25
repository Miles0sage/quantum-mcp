# PQC Posture Scanner -- Quick Start

Three ways to use the scanner: CLI, GitHub Action, or MCP server.

---

## Method 1: CLI (pip install)

```bash
pip install pqc-posture
pqc-scan .
```

Common flags:

```bash
# Scan with SARIF + CBOM output
pqc-scan /path/to/project --sarif results.sarif --cbom cbom.json

# Production code only, fail on CRITICAL
pqc-scan . --context prod --fail-on CRITICAL

# JSON output
pqc-scan . --format json

# Only HIGH and CRITICAL findings
pqc-scan . --min-risk HIGH
```

---

## Method 2: GitHub Action

Add to `.github/workflows/pqc-scan.yml`:

```yaml
name: PQC Posture Scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  pqc-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run PQC Posture Scanner
        id: scan
        uses: Miles0sage/quantum-mcp@main
        with:
          path: "."
          fail-on: "CRITICAL"
          format: "sarif"
          context-filter: "prod"
        continue-on-error: true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pqc-results.sarif
          category: pqc-posture

      - name: Upload CBOM
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: crypto-bill-of-materials
          path: CBOM.json

      - name: Fail on threshold
        if: steps.scan.outcome == 'failure'
        run: exit 1
```

### Action Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `fail-on` | `CRITICAL` | Fail threshold: CRITICAL, HIGH, MEDIUM, LOW, NONE |
| `format` | `text` | Output format: text, json, sarif |
| `context-filter` | `all` | Filter: all, prod, test |

### Action Outputs

| Output | Description |
|--------|-------------|
| `risk-score` | Quantum risk score (0-100) |
| `risk-level` | CRITICAL, HIGH, MEDIUM, or LOW |
| `findings-count` | Total findings |
| `production-findings` | Non-test findings count |

---

## Method 3: MCP Server

The scanner runs as an MCP server with 4 quantum tools including `pqc_posture_scan`.

### Claude Desktop

Add to `~/.config/claude/claude_desktop_config.json` (Linux) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "quantum-mcp": {
      "command": "python3",
      "args": ["/path/to/quantum-mcp/server.py"],
      "env": {
        "QUANTUM_MCP_PORT": "8200"
      }
    }
  }
}
```

### VS Code (Copilot MCP)

Add to `.vscode/settings.json` or user settings:

```json
{
  "mcp": {
    "servers": {
      "quantum-mcp": {
        "command": "python3",
        "args": ["/path/to/quantum-mcp/server.py"],
        "env": {
          "QUANTUM_MCP_PORT": "8200"
        }
      }
    }
  }
}
```

### Claude Code

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "quantum-mcp": {
      "command": "python3",
      "args": ["/path/to/quantum-mcp/server.py"],
      "env": {
        "QUANTUM_MCP_PORT": "8200"
      }
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `pqc_posture_scan` | Scan a directory for quantum-vulnerable crypto. Returns risk score, findings, CBOM. |
| `quantum_random` | Generate quantum random bytes (local simulator or IBM QPU). |
| `quantum_backends` | List available quantum computing backends. |
| `quantum_circuit` | Run an OpenQASM 2.0 circuit on simulator or real hardware. |

### Example MCP Usage

Once connected, ask your AI assistant:

```
Scan this project for quantum-vulnerable cryptography
```

The assistant calls `pqc_posture_scan` with `{"path": "."}` and returns the risk score, findings, and migration recommendations.

---

## Requirements

- Python 3.8+
- No external dependencies for the scanner (stdlib only)
- Optional: `qiskit` for quantum random number generation
- Optional: `qiskit-ibm-runtime` for real IBM quantum hardware
