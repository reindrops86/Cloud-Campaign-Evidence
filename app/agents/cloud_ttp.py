from __future__ import annotations

from typing import Any, Dict, List

from app.graph.evidence_graph import EvidenceGraphEngine
from app.models import CloudTTPMapping


class CloudTTPAnalystAgent:
    """Agent 3: Cloud-TTP Analyst
    Maps evidence graph indicators and behavior to MITRE ATT&CK for Cloud (AWS, Azure, K8s, IAM, CI/CD).
    """

    def __init__(self, graph_engine: EvidenceGraphEngine) -> None:
        self.graph_engine = graph_engine

    def map_ttps(self) -> List[CloudTTPMapping]:
        mappings: List[CloudTTPMapping] = []
        node_types = {n.indicator_type for n in self.graph_engine.nodes.values()}

        # Check for Cloud IAM credential abuse
        if "iam_access_key" in node_types or any("AssumeRole" in e.evidence_basis for e in self.graph_engine.edges):
            mappings.append(
                CloudTTPMapping(
                    technique_id="T1078.004",
                    technique_name="Valid Accounts: Cloud Accounts",
                    tactic="Initial Access / Defense Evasion",
                    cloud_platform="AWS / Azure IAM",
                    evidence_ids=[n.id for n in self.graph_engine.nodes.values() if n.indicator_type == "iam_access_key"],
                    confidence=95,
                )
            )
            mappings.append(
                CloudTTPMapping(
                    technique_id="T1552.005",
                    technique_name="Unsecured Credentials: Cloud Credentials",
                    tactic="Credential Access",
                    cloud_platform="AWS S3 / Azure Key Vault / GitHub",
                    evidence_ids=[e.source_id for e in self.graph_engine.edges if e.relation_type == "leveraged_by"],
                    confidence=90,
                )
            )

        # Check for exfiltration or storage access
        if any("S3" in e.evidence_basis or "storage" in e.evidence_basis for e in self.graph_engine.edges):
            mappings.append(
                CloudTTPMapping(
                    technique_id="T1530",
                    technique_name="Data from Cloud Storage Object",
                    tactic="Exfiltration / Collection",
                    cloud_platform="AWS S3 / Azure Blob Storage",
                    evidence_ids=[e.target_id for e in self.graph_engine.edges if "storage" in e.evidence_basis.lower()],
                    confidence=85,
                )
            )

        # Check for payload execution or malicious URL/domain hosting
        if "url" in node_types or "domain" in node_types or "hash" in node_types:
            mappings.append(
                CloudTTPMapping(
                    technique_id="T1071.001",
                    technique_name="Application Layer Protocol: Web Protocols",
                    tactic="Command and Control",
                    cloud_platform="Web / Cloud Hosting",
                    evidence_ids=[n.id for n in self.graph_engine.nodes.values() if n.indicator_type in ("domain", "url")],
                    confidence=88,
                )
            )

        # Check for CI/CD or container supply chain
        if "github_repo" in node_types or "container_image" in node_types:
            mappings.append(
                CloudTTPMapping(
                    technique_id="T1195.002",
                    technique_name="Supply Chain Compromise: Software Supply Chain",
                    tactic="Initial Access",
                    cloud_platform="CI/CD / GitHub Actions / K8s Container Registry",
                    evidence_ids=[n.id for n in self.graph_engine.nodes.values() if n.indicator_type in ("github_repo", "container_image")],
                    confidence=80,
                )
            )

        return mappings
