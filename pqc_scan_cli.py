#!/usr/bin/env python3
"""
PQC Posture Scanner — CLI entry point.

Usage:
    pqc-scan .                          Scan current directory
    pqc-scan /path/to/project           Scan specific path
    pqc-scan --tls example.com          Scan a TLS endpoint
    pqc-scan --tls example.com:8443     Scan TLS on custom port
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

from pqc_posture import scan_codebase, print_report, grade_result, grade_is_worse_or_equal, GRADE_ORDER, diff_results
from html_report import generate_html_report
from auto_fix import generate_fixes, print_fixes, write_patch, apply_fixes_to_files


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
        "--tls",
        metavar="HOST[:PORT]",
        help="Scan a TLS endpoint instead of a codebase (e.g. example.com or example.com:8443)",
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
    parser.add_argument(
        "--show-suppressed",
        action="store_true",
        default=False,
        help="Include suppressed findings in output with a SUPPRESSED marker",
    )
    parser.add_argument(
        "--fail-on-grade",
        choices=GRADE_ORDER,
        default=None,
        metavar="GRADE",
        help="Exit with code 1 if grade is this or worse (e.g. --fail-on-grade C). Choices: " + ", ".join(GRADE_ORDER),
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save a self-contained HTML report to file",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="Compare against a baseline JSON (previous scan) and show diff",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        default=False,
        help="Show suggested PQC migration fixes for each finding",
    )
    parser.add_argument(
        "--fix-patch",
        metavar="FILE",
        default=None,
        help="Write a unified diff patch file with all auto-fixes",
    )
    parser.add_argument(
        "--fix-apply",
        action="store_true",
        default=False,
        help="Apply auto-fixes directly to source files",
    )

    args = parser.parse_args()

    # ── TLS endpoint scan mode ──
    if args.tls:
        from tls_scanner import scan_tls, print_tls_report, _parse_host_port

        host, port = _parse_host_port(args.tls)
        result = scan_tls(host, port)

        # Apply min-risk filter
        if args.min_risk and args.min_risk in RISK_LEVELS:
            threshold = RISK_LEVELS[args.min_risk]
            result["findings"] = [
                f for f in result["findings"]
                if RISK_LEVELS.get(f.get("risk", "LOW"), 3) <= threshold
            ]
            result["total_findings"] = len(result["findings"])
            result["migration_priority"] = sorted(
                result["findings"],
                key=lambda x: RISK_LEVELS.get(x.get("risk", "LOW"), 3),
            )[:20]

        # Determine output format
        output_format = args.format
        if output_format is None:
            output_format = "json" if args.json_output else "text"

        if output_format == "json":
            print(json.dumps(result, indent=2))
        else:
            print_tls_report(result)

        # CI fail-on check
        if args.fail_on and _has_findings_at_level(result, args.fail_on):
            sys.exit(1)
        return

    # ── Codebase scan mode ──

    # Resolve path
    scan_path = os.path.abspath(args.path)
    if not os.path.isdir(scan_path):
        print(f"Error: '{scan_path}' is not a directory", file=sys.stderr)
        sys.exit(2)

    # Scan
    result = scan_codebase(scan_path, show_suppressed=args.show_suppressed)

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

    # Show suppressed findings if requested
    if args.show_suppressed and result.get("suppressed"):
        if output_format == "text":
            print(f"\n  SUPPRESSED FINDINGS ({len(result['suppressed'])}):")
            print(f"  {'Risk':10s} {'Algorithm':18s} {'File':28s} {'Line':6s} {'Usage'}")
            print(f"  {'-'*90}")
            for f in result["suppressed"]:
                print(f"  {f['risk']:10s} {f['algorithm'][:18]:18s} {f['file'][:28]:28s} {f['line']:<6d} [SUPPRESSED] {f.get('usage', '')[:40]}")
            print()
        elif output_format == "json":
            # Already included in JSON output via result["suppressed"]
            pass

    # Save HTML report if requested
    if args.html:
        html_path = os.path.abspath(args.html)
        html_content = generate_html_report(result)
        with open(html_path, "w") as f:
            f.write(html_content)
        print(f"HTML report saved to {html_path}", file=sys.stderr)

    # Baseline diff
    if args.baseline:
        baseline_path = os.path.abspath(args.baseline)
        if not os.path.isfile(baseline_path):
            print(f"Error: baseline file '{baseline_path}' not found", file=sys.stderr)
            sys.exit(2)
        with open(baseline_path, "r") as f:
            baseline_data = json.load(f)
        diff = diff_results(result, baseline_data)
        print(f"\n  BASELINE COMPARISON:", file=sys.stderr)
        print(f"    {diff['new_count']} new findings (action required)", file=sys.stderr)
        print(f"    {diff['fixed_count']} fixed findings (good job)", file=sys.stderr)
        print(f"    {diff['unchanged_count']} unchanged", file=sys.stderr)
        if diff['new_findings']:
            print(f"\n  NEW FINDINGS:", file=sys.stderr)
            for nf in diff['new_findings'][:10]:
                print(f"    [{nf.get('risk', '?')}] {nf.get('algorithm', '?')} in {nf.get('file', '?')}:{nf.get('line', '?')}", file=sys.stderr)
        if diff['fixed_findings']:
            print(f"\n  FIXED FINDINGS:", file=sys.stderr)
            for ff in diff['fixed_findings'][:10]:
                print(f"    [{ff.get('risk', '?')}] {ff.get('algorithm', '?')} in {ff.get('file', '?')}:{ff.get('line', '?')}", file=sys.stderr)
        print(file=sys.stderr)
        # When baseline is provided, exit code is based on NEW findings only
        if args.fail_on:
            new_has_level = any(
                RISK_LEVELS.get(f.get("risk", "LOW"), 3) <= RISK_LEVELS.get(args.fail_on, 3)
                for f in diff['new_findings']
            )
            if new_has_level:
                sys.exit(1)
            # Skip the normal fail-on check below
            args.fail_on = None

    # ── Auto-fix features ──
    if args.fix:
        print_fixes(result, scan_path)

    if args.fix_patch:
        patch_path = os.path.abspath(args.fix_patch)
        patch_content = write_patch(result, scan_path, patch_path)
        patch_lines = len(patch_content.splitlines()) if patch_content else 0
        print(f"\nPatch written to {patch_path} ({patch_lines} lines)", file=sys.stderr)

    if args.fix_apply:
        print("\nApplying PQC auto-fixes to source files...", file=sys.stderr)
        applied = apply_fixes_to_files(result, scan_path)
        if applied:
            for rel_path, count in sorted(applied.items()):
                print(f"  Fixed {count} finding(s) in {rel_path}", file=sys.stderr)
            print(f"  Total: {sum(applied.values())} fixes applied to {len(applied)} file(s)", file=sys.stderr)
        else:
            print("  No auto-fixes applicable.", file=sys.stderr)

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

    # CI fail-on-grade check
    if args.fail_on_grade:
        actual_grade = result.get("grade", grade_result(result))
        if grade_is_worse_or_equal(actual_grade, args.fail_on_grade):
            print(f"\nGrade {actual_grade} is {args.fail_on_grade} or worse — failing.", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
