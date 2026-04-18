"""
Bastion engine/reporter.py — HTML report generator.
Generates a self-contained, single-file HTML report with embedded diagram.
"""
import base64
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path

from jinja2 import Template

logger = logging.getLogger("reporter")

REPORT_CSS = """
body{font-family:Arial,sans-serif;margin:0;padding:0;background:#f8f9fa;color:#1a1a1a}
.cover{background:#111009;color:#c8921f;padding:80px 60px;min-height:300px}
.cover h1{font-size:48px;margin:0;letter-spacing:.05em}
.cover .subtitle{font-size:20px;color:#a0a0a0;margin-top:8px}
.cover .meta{font-size:14px;color:#6a5535;margin-top:40px}
section{padding:40px 60px;border-bottom:1px solid #e0e0e0}
h2{font-size:24px;color:#2e4057;border-bottom:2px solid #2e4057;padding-bottom:8px}
h3{font-size:18px;color:#444}
.risk-grid{display:flex;gap:16px;flex-wrap:wrap;margin:24px 0}
.risk-card{padding:20px 32px;border-radius:8px;text-align:center;min-width:120px}
.risk-card .count{font-size:40px;font-weight:bold}
.risk-card .label{font-size:13px;margin-top:4px}
.rc-crit{background:#FF00FF22;border:2px solid #FF00FF;color:#880088}
.rc-high{background:#E7716F22;border:2px solid #E7716F;color:#8B0000}
.rc-med{background:#FFC00022;border:2px solid #FFC000;color:#7A5800}
.rc-low{background:#92D05022;border:2px solid #92D050;color:#2E5A1C}
.rc-info{background:#BDD7EC22;border:2px solid #BDD7EC;color:#1A4A6A}
table{width:100%;border-collapse:collapse;margin:16px 0}
th{background:#2e4057;color:#fff;padding:10px 14px;text-align:left;font-size:13px}
td{padding:9px 14px;border-bottom:1px solid #e0e0e0;font-size:13px;vertical-align:top}
tr:nth-child(even){background:#f8f8f8}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;
       font-size:11px;font-weight:bold;letter-spacing:.04em}
.b-crit{background:#FF00FF;color:#fff}
.b-high{background:#E7716F;color:#fff}
.b-med{background:#FFC000;color:#1a1a1a}
.b-low{background:#92D050;color:#1a1a1a}
.b-info{background:#BDD7EC;color:#1a1a1a}
.finding{background:#fff;border:1px solid #ddd;border-radius:6px;
          margin:16px 0;padding:20px 24px}
.finding h4{margin:0 0 8px;font-size:15px}
.finding .meta{font-size:12px;color:#666;margin-bottom:12px}
.finding .section{margin-top:12px}
.finding .section strong{display:block;font-size:12px;
                          text-transform:uppercase;color:#888;margin-bottom:4px}
.code-block{background:#f0ead6;border-left:4px solid #c8921f;
             padding:10px 14px;font-family:monospace;font-size:12px;
             white-space:pre-wrap;word-break:break-all;margin:8px 0}
.arch-img{max-width:100%;border:1px solid #ddd;border-radius:4px}
.exec-banner{background:#fff3cd;border-left:4px solid #b8860b;
              padding:12px 20px;margin-bottom:24px;font-size:13px}
footer{text-align:center;padding:20px;font-size:12px;color:#888;
        background:#f0f0f0}
"""

_REPORT_TEMPLATE_STR = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8">
<title>Bastion Report \u2014 {{ client_name }}</title>
<style>{{ css }}</style>
</head><body>
<div class="cover">
  <h1>Bastion</h1>
  <div class="subtitle">Firewall Configuration Analysis Report</div>
  <div class="meta">
    Client: {{ client_name }}<br>
    Prepared by: {{ consultant }}<br>
    Date: {{ report_date }}<br>
    Classification: CONFIDENTIAL
  </div>
</div>
<section>
  <h2>Executive Summary</h2>
  {% if executive_profile %}<div class="exec-banner">
    &#9888; Executive Environment Profile Active \u2014 stricter thresholds applied</div>{% endif %}
  <p>This report presents the findings from a firewall configuration analysis of
  {{ config_count }} configuration file(s) submitted for review.
  {{ total_findings }} findings were identified across compliance frameworks.
  </p>
  <div class="risk-grid">
    {% for level, cls in [("Critical","crit"),("High","high"),("Medium","med"),("Low","low"),("Informational","info")] %}
    <div class="risk-card rc-{{ cls }}">
      <div class="count">{{ risk_summary.get(level, 0) }}</div>
      <div class="label">{{ level }}</div>
    </div>{% endfor %}
  </div>
</section>
{% if diagram_b64 %}
<section>
  <h2>Network Architecture</h2>
  <img class="arch-img" src="data:image/png;base64,{{ diagram_b64 }}" alt="Architecture Diagram">
</section>
{% endif %}
<section>
  <h2>Findings Summary</h2>
  <table>
    <tr><th>#</th><th>Risk</th><th>Finding</th><th>Framework</th><th>Section</th><th>Effort</th></tr>
    {% for f in findings %}
    <tr>
      <td>{{ loop.index }}</td>
      <td><span class="badge b-{{ f.get('risk','') | lower | truncate(4, True, '') }}">{{ f.get('risk','') }}</span></td>
      <td>{{ f.get('title','') }}</td>
      <td>{{ f.get('framework','') }}</td>
      <td>{{ f.get('framework_section','') }}</td>
      <td>{{ (f.get('remediation_effort','') or '') | replace("_"," ") }}</td>
    </tr>{% endfor %}
  </table>
</section>
<section>
  <h2>Detailed Findings</h2>
  {% for f in findings %}{% if not f.get('accepted') %}
  <div class="finding">
    <span class="badge b-{{ f.get('risk','') | lower | truncate(4, True, '') }}">{{ f.get('risk','') }}</span>
    <h4>{{ f.get('title','') }}</h4>
    <div class="meta">
      {{ f.get('framework','') }} {{ f.get('framework_section','') }} &middot; {{ f.get('vendor','') }} &middot;
      {% if f.get('cvss_score') %}CVSS {{ f.get('cvss_score') }}{% endif %}
    </div>
    <div class="section"><strong>Description</strong>{{ f.get('description','') }}</div>
    <div class="section"><strong>Impact</strong>{{ f.get('impact','') }}</div>
    {% if f.get('triggered_raw') %}
    <div class="section"><strong>Triggered Configuration (Line(s): {{ f.get('triggered_lines',[]) | join(", ") }})</strong>
      <div class="code-block">{{ f.get('triggered_raw',[]) | join("\\n") }}</div>
    </div>{% endif %}
    <div class="section"><strong>Recommendation</strong>{{ f.get('recommendation','') }}</div>
    {% if f.get('analyst_notes') %}
    <div class="section"><strong>Analyst Notes</strong>{{ f.get('analyst_notes','') }}</div>
    {% endif %}
  </div>{% endif %}{% endfor %}
</section>
<footer>Generated by Bastion v1.0 on {{ report_date }}. CONFIDENTIAL.</footer>
</body></html>"""

REPORT_TEMPLATE = Template(_REPORT_TEMPLATE_STR)


def generate_html_report(project_dir: str, findings_data: dict,
                          project_meta: dict) -> str:
    """
    Generate a self-contained HTML report.
    Returns path to the saved report file.
    """
    try:
        reports_dir = os.path.join(project_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        # Embed architecture diagram
        diagram_b64 = ""
        diag_path = os.path.join(project_dir, "architecture.png")
        if os.path.exists(diag_path):
            try:
                with open(diag_path, "rb") as f:
                    diagram_b64 = base64.b64encode(f.read()).decode()
            except Exception:
                pass

        findings = findings_data.get("findings", [])
        # Sort by risk
        risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
                      "Informational": 4}
        findings = sorted(findings,
                          key=lambda f: risk_order.get(f.get("risk", ""), 5))

        html = REPORT_TEMPLATE.render(
            css=REPORT_CSS,
            client_name=project_meta.get("client_name", ""),
            consultant=project_meta.get("consultant_name", ""),
            report_date=datetime.now().strftime("%Y-%m-%d"),
            executive_profile=project_meta.get("executive_profile", False),
            config_count=len(findings_data.get("config_files", [])),
            total_findings=len(findings),
            risk_summary=findings_data.get("risk_summary", {}),
            findings=findings,
            diagram_b64=diagram_b64,
        )

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        client_short = re.sub(r"[^a-zA-Z0-9_]", "",
                               project_meta.get("client_short", "bastion"))
        if not client_short:
            client_short = "bastion"
        report_path = os.path.join(reports_dir,
                                   f"{client_short}_report_{ts}.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        return report_path

    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        return ""
