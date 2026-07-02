from __future__ import annotations

import html
from datetime import datetime
from typing import Any

from win_security_audit.models import AuditReport, STATUS_META, Status


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def status_chip(status: str) -> str:
    meta = STATUS_META.get(status, STATUS_META[Status.INFO])
    return f'<span class="chip {esc(status)}"><span>{meta["icon"]}</span>{esc(meta["label"])}</span>'


def risk_label(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def render_html(report: AuditReport) -> str:
    sections_html = "\n".join(render_section(section) for section in report.sections)
    counts = report.status_counts
    generated = esc(report.generated_at)
    now = esc(datetime.now().astimezone().isoformat(timespec="seconds"))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Audit Report - {esc(report.host)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --panel-2: #f0f4f8;
      --text: #1d2430;
      --muted: #5c6675;
      --line: #d8dee8;
      --green: #117a48;
      --yellow: #946200;
      --red: #bd1e1e;
      --blue: #2457a6;
      --shadow: 0 1px 2px rgba(18, 25, 38, .08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", Arial, sans-serif;
      line-height: 1.45;
    }}
    header {{
      background: #17202e;
      color: #fff;
      padding: 28px 32px 24px;
      border-bottom: 5px solid #3aa675;
    }}
    header h1 {{
      margin: 0 0 8px;
      font-size: 28px;
      letter-spacing: 0;
    }}
    header p {{ margin: 0; color: #d6dde8; }}
    main {{ max-width: 1280px; margin: 0 auto; padding: 24px; }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(5, minmax(150px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }}
    .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      box-shadow: var(--shadow);
      min-height: 92px;
    }}
    .metric strong {{
      display: block;
      font-size: 26px;
      margin-top: 4px;
    }}
    .metric span {{ color: var(--muted); font-size: 13px; }}
    .risk strong {{ font-size: 34px; }}
    .risk.low strong {{ color: var(--green); }}
    .risk.medium strong {{ color: var(--yellow); }}
    .risk.high strong {{ color: var(--red); }}
    .section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      margin: 16px 0;
      box-shadow: var(--shadow);
      overflow: hidden;
    }}
    .section-head {{
      display: flex;
      gap: 12px;
      align-items: flex-start;
      justify-content: space-between;
      padding: 16px 18px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-2);
    }}
    .section h2 {{ margin: 0; font-size: 19px; letter-spacing: 0; }}
    .section .summary-text {{ margin: 4px 0 0; color: var(--muted); }}
    .section-body {{ padding: 16px 18px 18px; }}
    .chip {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 13px;
      font-weight: 600;
      white-space: nowrap;
      border: 1px solid var(--line);
      background: #fff;
    }}
    .chip.healthy {{ color: var(--green); }}
    .chip.review {{ color: var(--yellow); }}
    .chip.suspicious {{ color: var(--red); }}
    .chip.info {{ color: var(--blue); }}
    .findings {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 10px;
      margin-bottom: 16px;
    }}
    .finding {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
    }}
    .finding h3 {{ margin: 0 0 8px; font-size: 15px; letter-spacing: 0; }}
    .finding p {{ margin: 7px 0; color: var(--muted); }}
    .finding ul {{ margin: 8px 0 0 18px; padding: 0; color: var(--muted); }}
    .table-wrap {{ overflow-x: auto; margin-top: 14px; border: 1px solid var(--line); border-radius: 8px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; text-align: left; }}
    th {{ background: #eef2f7; color: #2d3747; position: sticky; top: 0; }}
    tr:last-child td {{ border-bottom: 0; }}
    code {{
      background: #edf1f5;
      border: 1px solid #d8dee8;
      border-radius: 5px;
      padding: 1px 5px;
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
    }}
    .note {{ color: var(--muted); font-size: 13px; margin-top: 8px; }}
    footer {{ color: var(--muted); padding: 16px 0 30px; font-size: 13px; }}
    @media (max-width: 900px) {{
      header {{ padding: 22px 18px; }}
      main {{ padding: 16px; }}
      .summary {{ grid-template-columns: repeat(2, minmax(140px, 1fr)); }}
      .section-head {{ flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Windows Security Audit Report</h1>
    <p>Host <strong>{esc(report.host)}</strong> · User <strong>{esc(report.user)}</strong> · Generated {generated}</p>
  </header>
  <main>
    <section class="summary">
      <div class="metric risk {risk_label(report.risk_score).lower()}"><span>Risk Score</span><strong>{report.risk_score}</strong><span>{risk_label(report.risk_score)} risk</span></div>
      <div class="metric"><span>Overall</span><strong>{STATUS_META[report.overall_status]["icon"]}</strong><span>{esc(STATUS_META[report.overall_status]["label"])}</span></div>
      <div class="metric"><span>Suspicious</span><strong>{counts.get(Status.SUSPICIOUS, 0)}</strong><span>red findings</span></div>
      <div class="metric"><span>Needs Review</span><strong>{counts.get(Status.REVIEW, 0)}</strong><span>yellow findings</span></div>
      <div class="metric"><span>Admin Context</span><strong>{"Yes" if report.is_admin else "No"}</strong><span>{"Fuller collection" if report.is_admin else "Some checks may be limited"}</span></div>
    </section>
    {sections_html}
    <footer>
      Generated by {esc(report.tool_name)} v{esc(report.version)}. Data is collected locally and is not uploaded anywhere. Rendered at {now}.
    </footer>
  </main>
</body>
</html>
"""


def render_section(section: Any) -> str:
    findings = "\n".join(render_finding(finding) for finding in section.findings)
    if not findings:
        findings = '<p class="note">No notable findings in this section.</p>'
    tables = "\n".join(render_table(table) for table in section.tables)
    notes = "".join(f'<p class="note">{esc(note)}</p>' for note in section.notes)
    elapsed = f"{section.elapsed_seconds:.1f}s" if section.elapsed_seconds else ""
    return f"""
    <section class="section" id="{esc(section.key)}">
      <div class="section-head">
        <div>
          <h2>{esc(section.title)}</h2>
          <p class="summary-text">{esc(section.summary)} {esc(elapsed)}</p>
        </div>
        {status_chip(section.status)}
      </div>
      <div class="section-body">
        <div class="findings">{findings}</div>
        {tables}
        {notes}
      </div>
    </section>
"""


def render_finding(finding: Any) -> str:
    evidence = ""
    if finding.evidence:
        evidence = "<ul>" + "".join(f"<li><code>{esc(item)}</code></li>" for item in finding.evidence[:8]) + "</ul>"
    recommendation = f"<p><strong>Recommendation:</strong> {esc(finding.recommendation)}</p>" if finding.recommendation else ""
    description = f"<p>{esc(finding.description)}</p>" if finding.description else ""
    return f"""
      <article class="finding">
        <h3>{status_chip(finding.status)} {esc(finding.title)}</h3>
        {description}
        {evidence}
        {recommendation}
      </article>
"""


def render_table(table: Any) -> str:
    if not table.rows:
        return ""
    header = "".join(f"<th>{esc(col)}</th>" for col in table.columns)
    rows = []
    for row in table.shown_rows:
        cells = "".join(f"<td>{esc(row.get(col, ''))}</td>" for col in table.columns)
        rows.append(f"<tr>{cells}</tr>")
    hidden = ""
    if table.hidden_count:
        hidden = f'<p class="note">Showing {len(table.shown_rows)} of {len(table.rows)} rows. {table.hidden_count} additional rows are in the JSON output.</p>'
    return f"""
      <h3>{esc(table.title)}</h3>
      <div class="table-wrap">
        <table>
          <thead><tr>{header}</tr></thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>
      {hidden}
"""
