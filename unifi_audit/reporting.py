from __future__ import annotations

import html
import json
from csv import DictWriter
from dataclasses import asdict
from io import StringIO

from .models import AuditReport


def to_json(report: AuditReport) -> str:
    return json.dumps(asdict(report), indent=2, default=str)


def to_csv(report: AuditReport) -> str:
    buf = StringIO()
    fieldnames = [
        "severity",
        "category",
        "title",
        "detail",
        "recommendation",
        "cis_controls",
        "nist_controls",
        "evidence",
    ]
    writer = DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for finding in report.findings:
        writer.writerow(
            {
                "severity": finding.severity,
                "category": finding.category,
                "title": finding.title,
                "detail": finding.detail,
                "recommendation": finding.recommendation,
                "cis_controls": "; ".join(finding.cis_controls),
                "nist_controls": "; ".join(finding.nist_controls),
                "evidence": json.dumps(finding.evidence, default=str),
            }
        )
    return buf.getvalue()


def to_text(report: AuditReport) -> str:
    lines: list[str] = []
    lines.append("UniFi Backup Audit")
    lines.append(f"Backup: {report.backup_path}")
    lines.append(f"Profile: {report.profile}")
    lines.append(f"Overall score: {report.score}/100 (Grade {report.grade})")
    lines.append("")
    lines.append("Stats:")
    for key, value in report.stats.items():
        lines.append(f"  - {key}: {value}")

    if not report.findings:
        lines.append("")
        lines.append("No findings detected by current heuristic checks.")
        return "\n".join(lines)

    lines.append("")
    lines.append("Findings:")
    for finding in sorted(report.findings, key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f.severity, 3)):
        lines.append(f"  [{finding.severity}] ({finding.category}) {finding.title}")
        lines.append(f"    {finding.detail}")
        if finding.recommendation:
            lines.append(f"    Recommendation: {finding.recommendation}")
        if finding.cis_controls:
            lines.append(f"    CIS: {', '.join(finding.cis_controls)}")
        if finding.nist_controls:
            lines.append(f"    NIST: {', '.join(finding.nist_controls)}")
    return "\n".join(lines)


def to_html(report: AuditReport) -> str:
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in report.findings:
        key = finding.severity.upper()
        if key in severity_counts:
            severity_counts[key] += 1

    rows: list[str] = []
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for finding in sorted(report.findings, key=lambda f: order.get(f.severity.upper(), 3)):
        cis = ", ".join(finding.cis_controls) if finding.cis_controls else "-"
        nist = ", ".join(finding.nist_controls) if finding.nist_controls else "-"
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.severity)}</td>"
            f"<td>{html.escape(finding.category)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{html.escape(finding.detail)}</td>"
            f"<td>{html.escape(finding.recommendation or '-')}</td>"
            f"<td>{html.escape(cis)}</td>"
            f"<td>{html.escape(nist)}</td>"
            "</tr>"
        )

    if not rows:
        rows.append("<tr><td colspan='7'>No findings detected by current heuristic checks.</td></tr>")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>UniFi Backup Audit Report</title>
  <style>
    :root {{
      --bg: #f2f4f7;
      --card: #ffffff;
      --text: #12202f;
      --muted: #4d5a69;
      --border: #dbe2ea;
      --high: #b42318;
      --medium: #b54708;
      --low: #1d4ed8;
      --ok: #027a48;
    }}
    body {{
      margin: 0;
      background: linear-gradient(180deg, #e7edf3 0%, #f7f9fc 60%);
      color: var(--text);
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
    }}
    .container {{
      max-width: 1200px;
      margin: 32px auto;
      padding: 0 16px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 16px;
      box-shadow: 0 6px 24px rgba(15, 28, 45, 0.06);
    }}
    h1, h2 {{
      margin-top: 0;
      letter-spacing: 0.01em;
    }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
    }}
    .kpi {{
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      background: #fbfdff;
    }}
    .kpi b {{
      display: block;
      font-size: 1.2rem;
      margin-top: 4px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.95rem;
    }}
    th, td {{
      border-top: 1px solid var(--border);
      padding: 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: #f8fafc;
    }}
    .sev-HIGH {{ color: var(--high); font-weight: 600; }}
    .sev-MEDIUM {{ color: var(--medium); font-weight: 600; }}
    .sev-LOW {{ color: var(--low); font-weight: 600; }}
    .grade {{
      color: var(--ok);
      font-weight: 700;
    }}
    .muted {{
      color: var(--muted);
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>UniFi Backup Audit Report</h1>
      <p class="muted">Backup: {html.escape(report.backup_path)}</p>
      <p class="muted">Profile: {html.escape(report.profile)}</p>
      <p>Score: <b>{report.score}/100</b> <span class="grade">Grade {html.escape(report.grade)}</span></p>
      <div class="kpis">
        <div class="kpi">High findings<b>{severity_counts["HIGH"]}</b></div>
        <div class="kpi">Medium findings<b>{severity_counts["MEDIUM"]}</b></div>
        <div class="kpi">Low findings<b>{severity_counts["LOW"]}</b></div>
        <div class="kpi">Collections parsed<b>{report.stats.get("collections_seen", 0)}</b></div>
      </div>
    </div>
    <div class="card">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Category</th>
            <th>Title</th>
            <th>Detail</th>
            <th>Recommendation</th>
            <th>CIS Mapping</th>
            <th>NIST Mapping</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""
