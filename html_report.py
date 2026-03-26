#!/usr/bin/env python3
"""
HTML Report Generator for PQC Posture Scanner.

Generates a self-contained HTML report with dark theme, charts,
findings table, and migration priority — suitable for client delivery.
"""

import html
import time
from collections import Counter


def _escape(text):
    """HTML-escape a string."""
    return html.escape(str(text)) if text else ""


def _grade_color(grade: str) -> str:
    """Return a color for the letter grade."""
    if grade.startswith("A"):
        return "#00ff88"
    if grade.startswith("B"):
        return "#88ff00"
    if grade.startswith("C"):
        return "#ffcc00"
    if grade.startswith("D"):
        return "#ff6600"
    return "#ff2244"


def _risk_color(risk: str) -> str:
    """Return a color for a risk level."""
    return {
        "CRITICAL": "#ff2244",
        "HIGH": "#ff6600",
        "MEDIUM": "#ffcc00",
        "LOW": "#00ff88",
    }.get(risk, "#888888")


def _status_color(status: str) -> str:
    """Return a color for quantum status."""
    return {
        "BROKEN": "#ff2244",
        "WEAKENED": "#ffcc00",
        "SAFE": "#00ff88",
    }.get(status, "#888888")


def _bar_segment_html(label, value, total, color):
    """Return an HTML bar segment for a stacked bar."""
    if total == 0 or value == 0:
        return ""
    pct = value / total * 100
    return (
        f'<div style="width:{pct:.1f}%;background:{color};height:100%;'
        f'display:inline-block;text-align:center;line-height:32px;'
        f'font-size:12px;color:#fff;font-weight:600;overflow:hidden;"'
        f' title="{label}: {value}">{value}</div>'
    )


def generate_html_report(result: dict) -> str:
    """Generate a self-contained HTML report from a PQC Posture scan result dict.

    Args:
        result: The dict returned by pqc_posture.scan_codebase().

    Returns:
        A complete HTML document as a string.
    """
    grade = result.get("grade", "?")
    score = result.get("risk_score", 0)
    risk_level = result.get("risk_level", "UNKNOWN")
    findings = result.get("findings", [])
    exp = result.get("quantum_exposure", {})
    by_algo = result.get("by_algorithm", {})
    by_cat = result.get("by_category", {})
    cbom = result.get("cbom", {})
    migration = result.get("migration_priority", [])
    crypto_libs = result.get("crypto_libraries", [])
    scan_path = result.get("scan_path", "unknown")
    scan_time = result.get("scan_time_ms", 0)
    files_scanned = result.get("files_scanned", 0)
    files_with_crypto = result.get("files_with_crypto", 0)
    total_findings = result.get("total_findings", 0)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC")

    broken = exp.get("broken", 0)
    weakened = exp.get("weakened", 0)
    safe = exp.get("safe", 0)
    total_exposure = broken + weakened + safe

    # Context breakdown
    context_counts = Counter(f.get("context", "?") for f in findings)
    prod_count = sum(1 for f in findings if f.get("context") != "test")
    test_count = sum(1 for f in findings if f.get("context") == "test")

    # Build findings table rows
    findings_rows = []
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("risk", "LOW"), 3)):
        findings_rows.append(
            f'<tr data-risk="{_escape(f.get("risk", ""))}" data-status="{_escape(f.get("quantum_status", ""))}">'
            f'<td><span class="risk-badge" style="background:{_risk_color(f.get("risk", ""))}">{_escape(f.get("risk", ""))}</span></td>'
            f'<td><span style="color:{_status_color(f.get("quantum_status", ""))}">{_escape(f.get("quantum_status", ""))}</span></td>'
            f'<td>{_escape(f.get("algorithm", ""))}</td>'
            f'<td class="mono">{_escape(f.get("file", ""))}</td>'
            f'<td class="mono">{f.get("line", "")}</td>'
            f'<td>{_escape(f.get("context", ""))}</td>'
            f'<td class="usage-cell">{_escape(f.get("usage", ""))}</td>'
            f'<td>{_escape(f.get("migration", ""))}</td>'
            f"</tr>"
        )
    findings_html = "\n".join(findings_rows)

    # Build algorithm chart bars
    algo_max = max(by_algo.values()) if by_algo else 1
    algo_bars = []
    for algo, count in sorted(by_algo.items(), key=lambda x: -x[1]):
        pct = count / algo_max * 100
        # Determine color from findings
        algo_status = "SAFE"
        for f in findings:
            if f.get("algorithm") == algo:
                algo_status = f.get("quantum_status", "SAFE")
                break
        color = _status_color(algo_status)
        algo_bars.append(
            f'<div class="algo-row">'
            f'<div class="algo-label">{_escape(algo)}</div>'
            f'<div class="algo-bar-container">'
            f'<div class="algo-bar" style="width:{pct:.1f}%;background:{color};"></div>'
            f'</div>'
            f'<div class="algo-count">{count}</div>'
            f'</div>'
        )
    algo_chart_html = "\n".join(algo_bars)

    # Migration priority rows (top 15 production only)
    mig_rows = []
    seen = set()
    count = 0
    for f in migration:
        if f.get("context") == "test":
            continue
        key = f"{f.get('algorithm', '')}:{f.get('file', '')}"
        if key in seen:
            continue
        seen.add(key)
        mig_rows.append(
            f'<tr>'
            f'<td><span class="risk-badge" style="background:{_risk_color(f.get("risk", ""))}">{_escape(f.get("risk", ""))}</span></td>'
            f'<td>{_escape(f.get("algorithm", ""))}</td>'
            f'<td class="mono">{_escape(f.get("file", ""))}</td>'
            f'<td>{_escape(f.get("migration", ""))}</td>'
            f'<td class="mono" style="font-size:11px">{_escape(f.get("nist_ref", ""))}</td>'
            f'</tr>'
        )
        count += 1
        if count >= 15:
            break
    migration_html = "\n".join(mig_rows)

    # CBOM summary
    cbom_algos = cbom.get("cryptoProperties", {}).get("algorithms", [])
    cbom_libs = cbom.get("cryptoProperties", {}).get("libraries", [])
    cbom_rows = []
    for a in cbom_algos:
        safe_str = "Yes" if a.get("quantumSafe") else "No"
        safe_color = "#00ff88" if a.get("quantumSafe") else "#ff2244"
        cbom_rows.append(
            f'<tr>'
            f'<td>{_escape(a.get("name", ""))}</td>'
            f'<td>{a.get("occurrences", 0)}</td>'
            f'<td><span style="color:{safe_color}">{safe_str}</span></td>'
            f'</tr>'
        )
    cbom_html = "\n".join(cbom_rows)

    # Verdict
    if score >= 50:
        verdict = "CRITICAL quantum exposure. Migration urgently recommended."
        verdict_color = "#ff2244"
    elif score >= 25:
        verdict = "HIGH quantum exposure. Plan migration within 6 months."
        verdict_color = "#ff6600"
    elif score >= 10:
        verdict = "MODERATE exposure. Monitor and plan for PQC transition."
        verdict_color = "#ffcc00"
    else:
        verdict = "LOW exposure. Continue monitoring."
        verdict_color = "#00ff88"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQC Posture Report — {_escape(scan_path)}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: #0a0a0f;
    color: #e0e0e0;
    line-height: 1.6;
    padding: 32px;
  }}
  h1 {{ color: #fff; font-size: 28px; margin-bottom: 4px; }}
  h2 {{
    color: #a0a0ff;
    font-size: 20px;
    margin: 32px 0 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid #222;
  }}
  .header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 24px;
    flex-wrap: wrap;
    gap: 16px;
  }}
  .header-left {{ flex: 1; min-width: 300px; }}
  .subtitle {{ color: #888; font-size: 14px; }}
  .grade-badge {{
    width: 100px; height: 100px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 36px; font-weight: 800;
    border: 4px solid;
    flex-shrink: 0;
  }}
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }}
  .stat-card {{
    background: #12121a;
    border: 1px solid #222;
    border-radius: 8px;
    padding: 16px;
    text-align: center;
  }}
  .stat-value {{
    font-size: 28px;
    font-weight: 700;
    color: #fff;
  }}
  .stat-label {{
    font-size: 12px;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 1px;
  }}
  .risk-bar-container {{
    background: #1a1a24;
    border-radius: 8px;
    height: 32px;
    overflow: hidden;
    margin: 8px 0 16px;
    display: flex;
  }}
  .exposure-bar {{
    background: #1a1a24;
    border-radius: 8px;
    height: 32px;
    overflow: hidden;
    display: flex;
    margin: 8px 0;
  }}
  .score-bar-track {{
    background: #1a1a24;
    border-radius: 16px;
    height: 24px;
    overflow: hidden;
    margin: 8px 0;
    position: relative;
  }}
  .score-bar-fill {{
    height: 100%;
    border-radius: 16px;
    transition: width 0.3s;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    margin-bottom: 16px;
  }}
  th {{
    background: #16161e;
    color: #a0a0ff;
    text-align: left;
    padding: 10px 12px;
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    position: sticky;
    top: 0;
    cursor: pointer;
    user-select: none;
  }}
  th:hover {{ background: #1e1e2a; }}
  td {{
    padding: 8px 12px;
    border-bottom: 1px solid #1a1a24;
    vertical-align: top;
  }}
  tr:hover {{ background: #14141c; }}
  .mono {{ font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 12px; }}
  .usage-cell {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .risk-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    color: #fff;
  }}
  .filter-bar {{
    margin: 12px 0;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }}
  .filter-btn {{
    background: #1a1a24;
    border: 1px solid #333;
    color: #ccc;
    padding: 6px 14px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
  }}
  .filter-btn:hover {{ background: #222; }}
  .filter-btn.active {{ background: #2a2a44; border-color: #6666cc; color: #fff; }}
  .algo-row {{
    display: flex;
    align-items: center;
    margin: 6px 0;
  }}
  .algo-label {{
    width: 220px;
    font-size: 13px;
    color: #ccc;
    flex-shrink: 0;
    text-align: right;
    padding-right: 12px;
  }}
  .algo-bar-container {{
    flex: 1;
    background: #1a1a24;
    border-radius: 4px;
    height: 22px;
    overflow: hidden;
  }}
  .algo-bar {{
    height: 100%;
    border-radius: 4px;
    min-width: 2px;
  }}
  .algo-count {{
    width: 40px;
    text-align: right;
    font-size: 13px;
    color: #888;
    padding-left: 8px;
  }}
  .verdict {{
    text-align: center;
    padding: 20px;
    border-radius: 8px;
    margin: 32px 0;
    font-size: 18px;
    font-weight: 700;
    border: 2px solid;
  }}
  .footer {{
    text-align: center;
    color: #555;
    font-size: 12px;
    margin-top: 32px;
    padding-top: 16px;
    border-top: 1px solid #222;
  }}
  @media print {{
    body {{ background: #fff; color: #111; padding: 16px; }}
    .stat-card {{ border: 1px solid #ccc; background: #f9f9f9; }}
    .stat-value {{ color: #111; }}
    h2 {{ color: #333; border-color: #ccc; }}
    th {{ background: #eee; color: #333; }}
    td {{ border-color: #ddd; }}
    tr:hover {{ background: transparent; }}
    .grade-badge {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
    .risk-badge {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
    .algo-bar, .score-bar-fill, .exposure-bar div {{
      print-color-adjust: exact;
      -webkit-print-color-adjust: exact;
    }}
    .filter-bar {{ display: none; }}
    .footer {{ color: #999; }}
  }}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="header-left">
    <h1>PQC Posture Report</h1>
    <div class="subtitle">{_escape(scan_path)}</div>
    <div class="subtitle">{timestamp} | Scan time: {scan_time}ms | PQC Posture Scanner v0.2.0</div>
  </div>
  <div class="grade-badge" style="color:{_grade_color(grade)};border-color:{_grade_color(grade)}">
    {_escape(grade)}
  </div>
</div>

<!-- Risk Score Bar -->
<div>
  <div style="display:flex;justify-content:space-between;align-items:baseline;">
    <span style="font-size:14px;color:#888;">Quantum Risk Score</span>
    <span style="font-size:24px;font-weight:700;color:{_risk_color(risk_level)}">{score}/100 <span style="font-size:14px;">({_escape(risk_level)})</span></span>
  </div>
  <div class="score-bar-track">
    <div class="score-bar-fill" style="width:{score}%;background:linear-gradient(90deg, #00ff88, #ffcc00 50%, #ff2244);"></div>
  </div>
</div>

<!-- Stats Cards -->
<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-value">{files_scanned}</div>
    <div class="stat-label">Files Scanned</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{files_with_crypto}</div>
    <div class="stat-label">Files with Crypto</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{total_findings}</div>
    <div class="stat-label">Total Findings</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:{_risk_color('CRITICAL')}">{result.get('by_risk', {}).get('CRITICAL', 0)}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:{_risk_color('HIGH')}">{result.get('by_risk', {}).get('HIGH', 0)}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:{_risk_color('MEDIUM')}">{result.get('by_risk', {}).get('MEDIUM', 0)}</div>
    <div class="stat-label">Medium</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:{_risk_color('LOW')}">{result.get('by_risk', {}).get('LOW', 0)}</div>
    <div class="stat-label">Low</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{prod_count} / {test_count}</div>
    <div class="stat-label">Production / Test</div>
  </div>
</div>

<!-- Quantum Exposure -->
<h2>Quantum Exposure</h2>
<div class="exposure-bar">
  {_bar_segment_html("BROKEN", broken, total_exposure, "#ff2244")}
  {_bar_segment_html("WEAKENED", weakened, total_exposure, "#ffcc00")}
  {_bar_segment_html("SAFE", safe, total_exposure, "#00ff88")}
</div>
<div style="display:flex;gap:24px;font-size:13px;color:#888;margin-bottom:8px;">
  <span><span style="color:#ff2244">&#9632;</span> BROKEN: {broken}</span>
  <span><span style="color:#ffcc00">&#9632;</span> WEAKENED: {weakened}</span>
  <span><span style="color:#00ff88">&#9632;</span> SAFE: {safe}</span>
</div>

<!-- Algorithm Breakdown -->
<h2>Algorithm Breakdown</h2>
{algo_chart_html}

<!-- Findings Table -->
<h2>All Findings</h2>
<div class="filter-bar">
  <button class="filter-btn active" onclick="filterFindings('ALL')">All ({total_findings})</button>
  <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical ({result.get('by_risk', {}).get('CRITICAL', 0)})</button>
  <button class="filter-btn" onclick="filterFindings('HIGH')">High ({result.get('by_risk', {}).get('HIGH', 0)})</button>
  <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium ({result.get('by_risk', {}).get('MEDIUM', 0)})</button>
  <button class="filter-btn" onclick="filterFindings('LOW')">Low ({result.get('by_risk', {}).get('LOW', 0)})</button>
</div>
<div style="overflow-x:auto;">
<table id="findings-table">
  <thead>
    <tr>
      <th onclick="sortTable(0)">Risk</th>
      <th onclick="sortTable(1)">Q-Status</th>
      <th onclick="sortTable(2)">Algorithm</th>
      <th onclick="sortTable(3)">File</th>
      <th onclick="sortTable(4)">Line</th>
      <th onclick="sortTable(5)">Context</th>
      <th onclick="sortTable(6)">Usage</th>
      <th onclick="sortTable(7)">Migration</th>
    </tr>
  </thead>
  <tbody>
    {findings_html}
  </tbody>
</table>
</div>

<!-- Migration Priority -->
<h2>Migration Priority (Production Code)</h2>
<table>
  <thead>
    <tr>
      <th>Risk</th>
      <th>Algorithm</th>
      <th>File</th>
      <th>Migration Path</th>
      <th>NIST Reference</th>
    </tr>
  </thead>
  <tbody>
    {migration_html}
  </tbody>
</table>

<!-- CBOM Summary -->
<h2>CBOM (Crypto Bill of Materials)</h2>
<div style="font-size:13px;color:#888;margin-bottom:12px;">
  Format: CycloneDX {_escape(cbom.get('specVersion', '1.6'))} |
  Algorithms: {len(cbom_algos)} |
  Libraries: {len(cbom_libs)}
  {(' (' + ', '.join(_escape(l) for l in cbom_libs) + ')') if cbom_libs else ''}
</div>
<table>
  <thead>
    <tr><th>Algorithm</th><th>Occurrences</th><th>Quantum Safe</th></tr>
  </thead>
  <tbody>
    {cbom_html}
  </tbody>
</table>

<!-- Crypto Libraries -->
{"<h2>Crypto Libraries Detected</h2><ul style='list-style:none;'>" + ''.join(f'<li style="padding:4px 0;font-size:14px;color:#ccc;">- {_escape(lib)}</li>' for lib in crypto_libs) + "</ul>" if crypto_libs else ""}

<!-- Verdict -->
<div class="verdict" style="color:{verdict_color};border-color:{verdict_color};background:{verdict_color}11;">
  {_escape(verdict)}
</div>

<!-- Scan Metadata -->
<h2>Scan Metadata</h2>
<table style="max-width:500px;">
  <tr><td style="color:#888;">Scan Path</td><td class="mono">{_escape(scan_path)}</td></tr>
  <tr><td style="color:#888;">Date</td><td>{timestamp}</td></tr>
  <tr><td style="color:#888;">Scan Duration</td><td>{scan_time}ms</td></tr>
  <tr><td style="color:#888;">Scanner Version</td><td>PQC Posture Scanner v0.2.0</td></tr>
  <tr><td style="color:#888;">Grade</td><td style="color:{_grade_color(grade)};font-weight:700;">{_escape(grade)}</td></tr>
  <tr><td style="color:#888;">Risk Score</td><td>{score}/100</td></tr>
</table>

<!-- Footer -->
<div class="footer">
  Generated by PQC Posture Scanner v0.2.0 | Post-Quantum Cryptography Assessment
</div>

<script>
function filterFindings(level) {{
  const rows = document.querySelectorAll('#findings-table tbody tr');
  const btns = document.querySelectorAll('.filter-btn');
  btns.forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  rows.forEach(row => {{
    if (level === 'ALL' || row.getAttribute('data-risk') === level) {{
      row.style.display = '';
    }} else {{
      row.style.display = 'none';
    }}
  }});
}}

let sortDir = {{}};
function sortTable(col) {{
  const table = document.getElementById('findings-table');
  const tbody = table.querySelector('tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  sortDir[col] = !sortDir[col];
  const dir = sortDir[col] ? 1 : -1;
  rows.sort((a, b) => {{
    const aText = a.children[col].textContent.trim();
    const bText = b.children[col].textContent.trim();
    const aNum = parseInt(aText);
    const bNum = parseInt(bText);
    if (!isNaN(aNum) && !isNaN(bNum)) return (aNum - bNum) * dir;
    return aText.localeCompare(bText) * dir;
  }});
  rows.forEach(r => tbody.appendChild(r));
}}
</script>

</body>
</html>"""
