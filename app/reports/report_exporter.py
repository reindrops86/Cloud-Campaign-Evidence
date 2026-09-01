from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from app.graph.evidence_graph import EvidenceGraphEngine, defang_indicator
from app.models import InvestigationReport


class CTIReportExporter:
    """Exports investigation findings to HTML and PDF-ready standalone documents."""

    def __init__(self, report: InvestigationReport) -> None:
        self.report = report

    def generate_html(self) -> str:
        r = self.report
        skeptic = r.skeptic_review
        hyp = r.hypothesis

        unsupported_html = "".join([f"<li>{claim}</li>" for claim in skeptic.unsupported_claims]) or "<li>None detected.</li>"
        contradictions_html = "".join([f"<li>{c}</li>" for c in skeptic.contradictions]) or "<li>None detected.</li>"
        warnings_html = "".join([f"<li>{w}</li>" for w in skeptic.circular_reporting_warnings]) or "<li>None detected.</li>"

        ttps_html = ""
        for ttp in r.ttp_mappings:
            ttps_html += f"""
            <div class="card">
                <h4><span class="badge">{ttp.technique_id}</span> {ttp.technique_name}</h4>
                <p><strong>Tactic:</strong> {ttp.tactic} | <strong>Platform:</strong> {ttp.cloud_platform} | <strong>Confidence:</strong> {ttp.confidence}%</p>
            </div>
            """

        timeline_html = ""
        for evt in r.graph_engine.get_timeline() if hasattr(r, 'graph_engine') and r.graph_engine else []:
            timeline_html += f"<li><code>{evt['timestamp']}</code>: {evt['summary']}</li>"

        rules_html = ""
        for rule in r.detection_rules:
            rules_html += f"""
            <div class="code-block">
                <h4>{rule.title} ({rule.format_type}) - Target: {rule.target_service}</h4>
                <pre><code>{rule.rule_content}</code></pre>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CTI Research Report - {r.investigation_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1f2937; max-width: 900px; margin: 0 auto; padding: 20px; background-color: #f9fafb; }}
        .header {{ background: #1e293b; color: #ffffff; padding: 25px; border-radius: 8px; margin-bottom: 25px; }}
        .header h1 {{ margin: 0 0 10px 0; font-size: 24px; }}
        .status-pass {{ color: #10b981; font-weight: bold; }}
        .status-fail {{ color: #ef4444; font-weight: bold; }}
        .card {{ background: #ffffff; border: 1px solid #e5e7eb; border-radius: 6px; padding: 15px; margin-bottom: 15px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
        .badge {{ background: #2563eb; color: #ffffff; padding: 3px 8px; border-radius: 4px; font-size: 12px; }}
        .code-block pre {{ background: #0f172a; color: #38bdf8; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 13px; }}
        h2 {{ border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; color: #0f172a; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Cloud Threat Intelligence Report: {r.investigation_id}</h1>
        <p><strong>Seed Indicator:</strong> <code>{defang_indicator(r.seed_indicator)}</code> ({r.seed_type}) | <strong>Date:</strong> {r.timestamp}</p>
        <p><strong>Analyst Review Status:</strong> <span class="{ 'status-pass' if skeptic.accepted else 'status-fail' }">{ 'ACCEPTED' if skeptic.accepted else 'REJECTED' }</span> | <strong>Final Confidence:</strong> {skeptic.final_confidence}%</p>
    </div>

    <h2>Executive Summary</h2>
    <div class="card">
        <p>{hyp.primary_claim}</p>
    </div>

    <h2>Skeptic & Deception Audit</h2>
    <div class="card">
        <p><strong>Feedback:</strong> {skeptic.analyst_feedback}</p>
        <p><strong>Unsupported Claims / Downgrades:</strong></p>
        <ul>{unsupported_html}</ul>
        <p><strong>Infrastructure Contradictions:</strong></p>
        <ul>{contradictions_html}</ul>
        <p><strong>Circular Reporting Warnings:</strong></p>
        <ul>{warnings_html}</ul>
    </div>

    <h2>MITRE ATT&CK for Cloud Mappings</h2>
    {ttps_html}

    <h2>Detection Rules</h2>
    {rules_html}

    <footer style="margin-top: 50px; text-align: center; color: #6b7280; font-size: 12px;">
        Generated automatically by Cloud Campaign Evidence Graph Engine | STIX 2.1 Compliant
    </footer>
</body>
</html>
"""
        return html_content
