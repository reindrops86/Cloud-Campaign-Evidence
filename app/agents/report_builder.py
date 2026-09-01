from __future__ import annotations

from typing import Any, Dict, List

from app.graph.evidence_graph import EvidenceGraphEngine, defang_indicator
from app.models import (
    CampaignHypothesis,
    CloudTTPMapping,
    DetectionRule,
    InvestigationReport,
    SkepticReview,
    utc_now_iso,
)
from app.stix.stix_exporter import STIXExporter


class ReportBuilderAgent:
    """Agent 6: Report Builder
    Synthesizes accepted findings into a polished research report, STIX 2.1 bundle,
    and actionable cloud detection rules (Sigma / KQL).
    """

    def __init__(self, graph_engine: EvidenceGraphEngine) -> None:
        self.graph_engine = graph_engine
        self.stix_exporter = STIXExporter(graph_engine)

    def generate_detection_rules(self, seed_val: str, stype: str) -> List[DetectionRule]:
        rules: List[DetectionRule] = []

        if stype == "iam_access_key":
            sigma_body = f"""title: Suspicious API Activity from Compromised Cloud Credentials
id: c1a7a0b1-4b89-4e5c-9c12-3a5678901234
status: experimental
description: Detects API calls originating from known compromised IAM access key {defang_indicator(seed_val)} across unapproved ASNs.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.accessKeyId: '{seed_val}'
  condition: selection
falsepositives:
  - Authorized cloud infrastructure automation scripts.
level: high
tags:
  - attack.initial_access
  - attack.t1078.004
"""
            rules.append(
                DetectionRule(
                    rule_id="SIGMA-AWS-IAM-001",
                    title="Suspicious API Activity from Compromised Cloud Credentials",
                    format_type="Sigma",
                    target_service="CloudTrail",
                    rule_content=sigma_body,
                )
            )

            kql_body = f"""// KQL Query for Sentinel / Defender for Cloud
AWSCloudTrail
| where AccessKeyId == "{seed_val}"
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by SourceIPAddress, EventName, UserIdentityArn
| order by Count desc
"""
            rules.append(
                DetectionRule(
                    rule_id="KQL-AWS-IAM-001",
                    title="CloudTrail IAM Key Reuse Investigation Query",
                    format_type="KQL",
                    target_service="AzureActivity / AWSCloudTrail",
                    rule_content=kql_body,
                )
            )

        else:
            sigma_body = f"""title: Communication to Malicious Campaign Infrastructure
id: d2b8b1c2-5c90-4f6d-0d23-4b6789012345
status: experimental
description: Detects network egress or DNS queries to campaign indicator {defang_indicator(seed_val)}.
logsource:
  category: dns
detection:
  selection:
    query: '{seed_val}'
  condition: selection
level: high
tags:
  - attack.command_and_control
  - attack.t1071.001
"""
            rules.append(
                DetectionRule(
                    rule_id="SIGMA-NET-001",
                    title="Communication to Malicious Campaign Infrastructure",
                    format_type="Sigma",
                    target_service="DNS Logs / Firewall",
                    rule_content=sigma_body,
                )
            )

        return rules

    def build_report(
        self,
        investigation_id: str,
        seed_val: str,
        stype: str,
        ttp_mappings: List[CloudTTPMapping],
        hypothesis: CampaignHypothesis,
        skeptic_review: SkepticReview,
    ) -> InvestigationReport:
        now = utc_now_iso()
        rules = self.generate_detection_rules(seed_val, stype)
        stix_bundle = self.stix_exporter.export_bundle(investigation_id, hypothesis, ttp_mappings)

        # Build Markdown Report
        md = []
        md.append(f"# Cloud Threat Investigation Report: {investigation_id}")
        md.append(f"**Date:** {now}  |  **Seed Indicator:** `{defang_indicator(seed_val)}` (`{stype}`)  |  **Confidence Score:** {skeptic_review.final_confidence}%")
        md.append("")
        md.append("## Executive Summary")
        md.append(hypothesis.primary_claim)
        md.append("")
        md.append("## Analytical Judgments & Skeptic Audit")
        md.append(f"**Review Status:** `{'ACCEPTED' if skeptic_review.accepted else 'NEEDS_REVISION'}`")
        md.append(f"- **Analyst Feedback:** {skeptic_review.analyst_feedback}")
        if skeptic_review.unsupported_claims:
            md.append("### Unsupported Claims / Downgrades")
            for c in skeptic_review.unsupported_claims:
                md.append(f"- {c}")
        if skeptic_review.contradictions:
            md.append("### Infrastructure Contradictions")
            for c in skeptic_review.contradictions:
                md.append(f"- {c}")
        md.append("")
        md.append("## Competing Hypotheses (ACH Analysis)")
        md.append("### Alternative Explanations Evaluated")
        for alt in hypothesis.alternative_hypotheses:
            md.append(f"- {alt}")
        md.append("")
        md.append("## MITRE ATT&CK Cloud Mappings")
        for ttp in ttp_mappings:
            md.append(f"- **[{ttp.technique_id}] {ttp.technique_name}** ({ttp.tactic}) - Platform: `{ttp.cloud_platform}` (Confidence: {ttp.confidence}%)")
        md.append("")
        md.append("## Evidence Graph & Timeline")
        for evt in self.graph_engine.get_timeline():
            md.append(f"- `{evt['timestamp']}`: {evt['summary']}")
        md.append("")
        md.append("## Detection Rules")
        for r in rules:
            md.append(f"### {r.title} ({r.format_type})")
            md.append("```yaml")
            md.append(r.rule_content)
            md.append("```")
            md.append("")

        markdown_text = "\n".join(md)

        return InvestigationReport(
            investigation_id=investigation_id,
            seed_indicator=seed_val,
            seed_type=stype,
            timestamp=now,
            indicators=list(self.graph_engine.nodes.values()),
            edges=self.graph_engine.edges,
            ttp_mappings=ttp_mappings,
            hypothesis=hypothesis,
            skeptic_review=skeptic_review,
            detection_rules=rules,
            stix_bundle=stix_bundle,
            markdown_report=markdown_text,
        )
