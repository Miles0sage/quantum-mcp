#!/usr/bin/env python3
"""
PQC Posture Scanner — CLI entry point.

Usage:
    pqc-scan .                          Scan current directory
    pqc-scan /path/to/project           Scan specific path
    pqc-scan . --json                   JSON output
    pqc-scan . --cbom cbom.json         Save CBOM to file
    pqc-scan . --sarif out.sarif        SARIF output for GitHub Code Scanning
    pqc-scan . --format json|text|sarif Output format
    pqc-scan . --context prod           Only show production findings
    pqc-scan . --min-risk HIGH          Filter by minimum risk level
    pqc-scan . --fail-on CRITICAL       Exit code 1 if findings at this level or above
"""

import argparse
import json
import os
import sys
import time

from pqc_posture import scan_codebase, print_report


RISK_LEVELS = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _filter_findings(result, context=None, min_risk=None):
    """Return a new result dict with findings filtered by context and min-risk."""
    findings = result.get("findings", [])

    if context == "prod":
        findings = [f for f in findings if f.get("context") != "test"]
    elif context == "test":
        findings = [f for f in findings if f.get("context") == "test"]

    if min_risk and min_risk in RISK_LEVELS:
        threshold = RISK_LEVELS[min_risk]
        findings = [f for f in findings if RISK_LEVELS.get(f.get("risk", "LOW"), 3) <= threshold]

    # Return a shallow copy with filtered findings
    filtered = dict(result)
    filtered["findings"] = findings
    filtered["total_findings"] = len(findings)

    # Rebuild migration_priority from filtered findings
    filtered["migration_priority"] = sorted(
        findings,
        key=lambda x: RISK_LEVELS.get(x.get("risk", "LOW"), 3),
    )[:20]

    return filtered


def _has_findings_at_level(result, level):
    """Check if any findings exist at the given risk level or above."""
    if level not in RISK_LEVELS:
        return False
    threshold = RISK_LEVELS[level]
    return any(
        RISK_LEVELS.get(f.get("risk", "LOW"), 3) <= threshold
        for f in result.get("findings", [])
    )


def _build_sarif(result):
    """Build a SARIF 2.1.0 document from scan results."""
    rules = {}
    sarif_results = []

    for finding in result.get("findings", []):
        algo = finding["algorithm"]
        rule_id = algo.replace(" ", "-").replace("/", "-").lower()

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": algo,
                "shortDescription": {"text": f"Quantum-vulnerable: {algo}"},
                "fullDescription": {
                    "text": f"{algo} ({finding['category']}) — {finding['quantum_status']}. Migration: {finding['migration']}",
                },
                "helpUri": f"https://csrc.nist.gov/projects/post-quantum-cryptography",
                "properties": {
                    "tags": ["security", "cryptography", "post-quantum"],
                },
                "defaultConfiguration": {
                    "level": _sarif_level(finding.get("raw_risk", finding["risk"])),
                },
            }

        sarif_results.append({
            "ruleId": rule_id,
            "level": _sarif_level(finding["risk"]),
            "message": {
                "text": f"{algo} usage detected ({finding['quantum_status']}). {finding['migration']}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding["file"],
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding["line"],
                            "snippet": {"text": finding.get("usage", "")},
                        },
                    },
                },
            ],
            "properties": {
                "context": finding.get("context", ""),
                "quantumStatus": finding["quantum_status"],
                "nistRef": finding.get("nist_ref", ""),
            },
        })

    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PQC Posture Scanner",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Miles0sage/quantum-mcp",
                        "rules": list(rules.values()),
                    },
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": " ".join(sys.argv),
                    },
                ],
            },
        ],
    }
    return sarif


def _sarif_level(risk):
    """Map risk level to SARIF level."""
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }.get(risk, "note")


def main():
    parser = argparse.ArgumentParser(
        prog="pqc-scan",
        description="Post-Quantum Cryptography Posture Scanner — find quantum-vulnerable crypto in your codebase",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text", "sarif"],
        default=None,
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--cbom",
        metavar="FILE",
        help="Save Crypto Bill of Materials (CycloneDX) to file",
    )
    parser.add_argument(
        "--sarif",
        metavar="FILE",
        help="Save SARIF 2.1.0 output to file (for GitHub Code Scanning)",
    )
    parser.add_argument(
        "--context",
        choices=["prod", "test", "all"],
        default="all",
        help="Filter findings by context (default: all)",
    )
    parser.add_argument(
        "--min-risk",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Only show findings at this risk level or above",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Exit with code 1 if findings exist at this level or above (for CI)",
    )

    args = parser.parse_args()

    # Resolve path
    scan_path = os.path.abspath(args.path)
    if not os.path.isdir(scan_path):
        print(f"Error: '{scan_path}' is not a directory", file=sys.stderr)
        sys.exit(2)

    # Scan
    result = scan_codebase(scan_path)

    # Apply filters
    context_filter = args.context if args.context != "all" else None
    result = _filter_findings(result, context=context_filter, min_risk=args.min_risk)

    # Determine output format
    output_format = args.format
    if output_format is None:
        if args.json_output:
            output_format = "json"
        else:
            output_format = "text"

    # Output
    if output_format == "json":
        print(json.dumps(result, indent=2))
    elif output_format == "sarif":
        sarif = _build_sarif(result)
        print(json.dumps(sarif, indent=2))
    else:
        print_report(result)

    # Save CBOM if requested
    if args.cbom:
        cbom_path = os.path.abspath(args.cbom)
        with open(cbom_path, "w") as f:
            json.dump(result["cbom"], f, indent=2)
        print(f"\nCBOM saved to {cbom_path}", file=sys.stderr)

    # Save SARIF if requested
    if args.sarif:
        sarif_path = os.path.abspath(args.sarif)
        sarif = _build_sarif(result)
        with open(sarif_path, "w") as f:
            json.dump(sarif, f, indent=2)
        print(f"\nSARIF saved to {sarif_path}", file=sys.stderr)

    # CI fail-on check
    if args.fail_on and _has_findings_at_level(result, args.fail_on):
        sys.exit(1)


if __name__ == "__main__":
    main()
