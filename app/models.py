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
    evidence_refs: List[str] = field(default_factory=list)
    observed: bool = False  # True only when a raw telemetry record proves this edge


@dataclass
class EvidenceRecord:
    """A single raw provider telemetry record that graph edges cite as proof."""

    evidence_id: str
    provider: str  # aws, azure, gcp
    source: str  # cloudtrail_lookup_events, cloudtrail_s3_export, iam_api
    event_id: str
    event_time: str
    account_id: Optional[str]
    region: Optional[str]
    principal_arn: Optional[str]
    access_key_id: Optional[str]
    source_ip: Optional[str]
    event_source: str
    event_name: str
    event_category: str = "Management"  # Management, Data, Insight
    resources: List[Dict[str, Any]] = field(default_factory=list)
    raw_event: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IAMPrincipal:
    arn: str
    name: str
    principal_type: str  # user, role, group
    account_id: Optional[str] = None
    attached_policy_arns: List[str] = field(default_factory=list)
    inline_policy_names: List[str] = field(default_factory=list)
    group_names: List[str] = field(default_factory=list)
    permissions_boundary_arn: Optional[str] = None
    trust_policy: Optional[Dict[str, Any]] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class PolicyStatement:
    policy_arn: str
    policy_name: str
    sid: Optional[str]
    effect: str  # Allow, Deny
    actions: List[str]
    resources: List[str]
    conditions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PermissionEvaluation:
    """Result of evaluating one action against one principal."""

    principal_arn: str
    action: str
    resource_arn: str
    decision: str  # allowed, explicitDeny, implicitDeny, unresolved
    status: str  # POTENTIAL, CONFIRMED_ALLOWED, OBSERVED, BLOCKED, UNRESOLVED
    matched_statements: List[str] = field(default_factory=list)
    unresolved_conditions: List[str] = field(default_factory=list)
    evaluation_source: str = "graph"  # graph, policy_simulator, access_analyzer
    via_role_arn: Optional[str] = None  # set when the permission is only reachable after assume-role


@dataclass
class AttackPathStep:
    node_id: str
    node_type: str  # access_key, iam_user, iam_role, aws_action, resource
    label: str
    status: str  # POTENTIAL, CONFIRMED_ALLOWED, OBSERVED, BLOCKED, UNRESOLVED
    evidence_refs: List[str] = field(default_factory=list)


@dataclass
class AttackPath:
    path_id: str
    title: str
    risk_category: str  # privilege_escalation, credential_creation, secret_access, storage_access, defense_impairment
    steps: List[AttackPathStep]
    status: str  # worst/most-conservative status across all steps
    risk_score: int  # 0 to 100
    scoring_rationale: List[str] = field(default_factory=list)
    attack_technique_ids: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)


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
