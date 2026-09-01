from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class IndicatorNode:
    id: str
    value: str
    indicator_type: str  # ip, domain, url, hash, iam_access_key, container_image, github_repo
    first_seen: str
    last_seen: str
    reputation_score: int  # 0 to 100 (100 = highly malicious)
    sources: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceEdge:
    source_id: str
    target_id: str
    relation_type: str  # resolved_to, hosted_on, leveraged_by, downloaded_from, used_credential, commit_by
    confidence: int  # 0 to 100
    evidence_basis: str
    first_observed: str
    last_observed: str


@dataclass
class CloudTTPMapping:
    technique_id: str  # e.g. T1078.004, T1552.005, T1098.001
    technique_name: str
    tactic: str  # Initial Access, Persistence, Privilege Escalation, Credential Access, Exfiltration
    cloud_platform: str  # AWS, Azure, GCP, Kubernetes, CI/CD
    evidence_ids: List[str]
    confidence: int


@dataclass
class CampaignHypothesis:
    hypothesis_id: str
    primary_claim: str
    supporting_evidence: List[str]
    alternative_hypotheses: List[str]
    assumed_threat_actor: Optional[str]
    initial_confidence: int


@dataclass
class SkepticReview:
    accepted: bool
    final_confidence: int
    unsupported_claims: List[str]
    circular_reporting_warnings: List[str]
    contradictions: List[str]
    analyst_feedback: str


@dataclass
class DetectionRule:
    rule_id: str
    title: str
    format_type: str  # Sigma, KQL, YARA
    target_service: str  # CloudTrail, AzureActivity, KubernetesAudit, Sysmon
    rule_content: str


@dataclass
class InvestigationReport:
    investigation_id: str
    seed_indicator: str
    seed_type: str
    timestamp: str
    indicators: List[IndicatorNode]
    edges: List[EvidenceEdge]
    ttp_mappings: List[CloudTTPMapping]
    hypothesis: CampaignHypothesis
    skeptic_review: SkepticReview
    detection_rules: List[DetectionRule]
    stix_bundle: Dict[str, Any]
    markdown_report: str
