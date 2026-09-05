from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.collectors.aws_identity import (
    _statements_from_document,
    all_high_risk_actions,
    evaluate_from_statements,
)
from app.collectors.github_actions import (
    GitHubActionsSource,
    observed_role_actions,
    observed_web_identity_assumptions,
)
from app.collectors.k8s_rbac import K8sRBACSource, load_audit_events, observed_pod_creates
from app.graph.evidence_graph import EvidenceGraphEngine
from app.graph.federated_paths import FederatedPathAnalyzer, summarize_federated
from app.graph.federation import blast_radius, evaluate_federated_trust
from app.models import (
    AttackPath,
    EvidenceRecord,
    IAMPrincipal,
    OIDCProvider,
    WorkloadIdentity,
)


class WorkloadFederationAgent:
    """Traces attack paths from workload planes (K8s, CI) into cloud IAM.

    The unifying question: which federated trust conditions admit more workloads
    than intended, and did any of them actually get used?
    """

    def __init__(
        self,
        evidence_graph: EvidenceGraphEngine,
        federated_roles_path: str | Path,
        *,
        k8s_snapshot: Optional[str | Path] = None,
        k8s_audit_log: Optional[str | Path] = None,
        github_snapshot: Optional[str | Path] = None,
        cloudtrail_records: Optional[List[EvidenceRecord]] = None,
    ) -> None:
        self.evidence_graph = evidence_graph
        snapshot = json.loads(Path(federated_roles_path).read_text(encoding="utf-8"))

        self.providers: Dict[str, OIDCProvider] = {
            p["provider_arn"]: OIDCProvider(
                provider_arn=p["provider_arn"],
                issuer_url=p["issuer_url"],
                plane=p["plane"],
                audiences=p.get("audiences", []),
                cluster_name=p.get("cluster_name"),
            )
            for p in snapshot.get("oidc_providers", [])
        }
        self.roles: List[Dict[str, Any]] = snapshot.get("federated_roles", [])

        self.k8s = K8sRBACSource(k8s_snapshot) if k8s_snapshot else None
        self.github = GitHubActionsSource(github_snapshot) if github_snapshot else None

        self.audit_records = load_audit_events(k8s_audit_log) if k8s_audit_log else []
        self.cloudtrail_records = cloudtrail_records or []

        self.observed_assumptions = observed_web_identity_assumptions(self.cloudtrail_records)
        self.observed_role_actions = observed_role_actions(self.cloudtrail_records)
        self.observed_pods = observed_pod_creates(self.audit_records)

    def analyze(self) -> Dict[str, Any]:
        workloads = self._all_workloads()
        analyzer = FederatedPathAnalyzer(self.providers)

        paths: List[AttackPath] = []
        trusts: List[Dict[str, Any]] = []

        for workload in workloads:
            for role in self.roles:
                trust = evaluate_federated_trust(
                    workload,
                    role["Arn"],
                    role.get("AssumeRolePolicyDocument", {}),
                    self.providers,
                    self.observed_assumptions,
                )
                if not trust:
                    continue

                radius = blast_radius(trust, workloads)
                trusts.append(
                    {
                        **trust.__dict__,
                        "matched_conditions": [c.__dict__ for c in trust.matched_conditions],
                        "workload_subject": workload.subject,
                        "blast_radius": radius,
                    }
                )

                evaluations = self._role_permissions(role)
                entry_routes, entry_status, entry_label, entry_evidence = self._entry_context(
                    workload
                )

                paths.extend(
                    analyzer.build_paths(
                        workload,
                        trust,
                        evaluations,
                        entry_routes=entry_routes,
                        entry_status=entry_status,
                        entry_label=entry_label,
                        entry_evidence=entry_evidence,
                        blast_radius_ids=radius,
                        observed_actions=self.observed_role_actions.get(role["Arn"], {}),
                    )
                )

                if trust.status != "BLOCKED":
                    self._record_evidence(workload, trust)

        paths.sort(key=lambda p: -p.risk_score)

        return {
            "providers": [p.__dict__ for p in self.providers.values()],
            "workloads": [w.__dict__ for w in workloads],
            "federated_trusts": trusts,
            "federated_paths": [self._path_dict(p) for p in paths],
            "federated_summary": summarize_federated(paths),
            "overly_broad_trusts": [t for t in trusts if t["overly_broad"]],
            "k8s_audit_events": len(self.audit_records),
        }

    def _all_workloads(self) -> List[WorkloadIdentity]:
        workloads: List[WorkloadIdentity] = []
        if self.k8s:
            workloads.extend(self.k8s.service_accounts())
        if self.github:
            workloads.extend(self.github.workloads())
        return workloads

    def _role_permissions(self, role: Dict[str, Any]) -> List[Any]:
        statements = []
        for policy in role.get("AttachedPolicies", []) + role.get("InlinePolicies", []):
            statements.extend(
                _statements_from_document(
                    policy.get("PolicyDocument", {}),
                    policy.get("PolicyArn", f"inline::{policy.get('PolicyName', '')}"),
                    policy.get("PolicyName", ""),
                )
            )

        principal = IAMPrincipal(
            arn=role["Arn"], name=role["Name"], principal_type="role",
            account_id=role.get("AccountId"),
        )
        return evaluate_from_statements(principal, statements, all_high_risk_actions())

    def _entry_context(
        self, workload: WorkloadIdentity
    ) -> tuple[List[str], str, Optional[str], List[str]]:
        """Describe how an adversary reaches the workload, and whether it was seen."""
        if workload.plane == "kubernetes" and self.k8s:
            routes = self.k8s.subjects_who_can_use(workload)
            descriptions = [
                f"{s.kind} `{s.name}` — {reason}" for s, reason in routes
            ]
            evidence = self.observed_pods.get(
                f"{workload.namespace}/{workload.display_name.split('/')[-1]}", []
            )
            label = (
                f"{len(routes)} RBAC subject(s) can obtain this ServiceAccount token"
                if routes
                else "No RBAC subject can obtain this token"
            )
            return descriptions, "OBSERVED" if evidence else "POTENTIAL", label, evidence

        if workload.plane == "github_actions" and self.github:
            reasons = self.github.entry_conditions(workload)
            mitigations = self.github.mitigations(workload)
            label = workload.metadata.get("environment") or ", ".join(
                workload.metadata.get("triggers", [])
            )
            return reasons + [f"Mitigation: {m}" for m in mitigations], "POTENTIAL", label, []

        return [], "POTENTIAL", None, []

    def _record_evidence(self, workload: WorkloadIdentity, trust: Any) -> None:
        """Add the federated hop to the shared evidence graph with provenance."""
        provider = self.providers.get(trust.provider_arn)
        timestamp = "2026-08-29T00:00:00+00:00"

        workload_node = f"node-workload-{abs(hash(workload.workload_id)) % 100000}"
        self.evidence_graph.add_node(
            node_id=workload_node,
            value=workload.subject,
            indicator_type="workload_identity",
            first_seen=timestamp,
            last_seen=timestamp,
            reputation_score=40,
            source=f"{workload.plane}_snapshot",
            metadata={"plane": workload.plane, "display_name": workload.display_name},
        )

        role_node = f"node-role-{abs(hash(trust.role_arn)) % 100000}"
        self.evidence_graph.add_node(
            node_id=role_node,
            value=trust.role_arn,
            indicator_type="iam_role",
            first_seen=timestamp,
            last_seen=timestamp,
            reputation_score=40,
            source="aws_iam",
            metadata={"issuer": provider.issuer_url if provider else ""},
        )

        self.evidence_graph.add_edge(
            source_id=workload_node,
            target_id=role_node,
            relation_type="can_assume_via_oidc",
            confidence=100 if trust.status == "OBSERVED" else 60,
            evidence_basis=(
                "CloudTrail AssumeRoleWithWebIdentity confirms this assumption"
                if trust.status == "OBSERVED"
                else "Trust policy condition permits this subject"
            ),
            first_observed=timestamp,
            last_observed=timestamp,
            evidence_refs=trust.evidence_refs,
            observed=trust.status == "OBSERVED",
        )

    @staticmethod
    def _path_dict(path: AttackPath) -> Dict[str, Any]:
        return {
            "path_id": path.path_id,
            "title": path.title,
            "risk_category": path.risk_category,
            "status": path.status,
            "risk_score": path.risk_score,
            "scoring_rationale": path.scoring_rationale,
            "attack_technique_ids": path.attack_technique_ids,
            "identity_planes": path.identity_planes,
            "steps": [s.__dict__ for s in path.steps],
        }
