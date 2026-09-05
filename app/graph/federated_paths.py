from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.collectors.aws_identity import risk_category_for
from app.graph.attack_paths import CATEGORY_BASE_RISK, CATEGORY_TECHNIQUES, STATUS_RANK
from app.models import (
    AttackPath,
    AttackPathStep,
    FederatedTrust,
    K8sSubject,
    OIDCProvider,
    PermissionEvaluation,
    WorkloadIdentity,
)

# Crossing an identity plane is what makes these paths dangerous: cluster-local or
# CI-local access converts into durable cloud permissions.
PLANE_CROSSING_BONUS = 15
OVERLY_BROAD_TRUST_BONUS = 20
UNTRUSTED_ENTRY_BONUS = 15


class FederatedPathAnalyzer:
    """Builds attack paths that cross from a workload plane into cloud IAM.

    Shape: RBAC subject / CI trigger → workload identity → OIDC trust condition
    → IAM role → cloud action → resource.
    """

    def __init__(self, providers: Dict[str, OIDCProvider]) -> None:
        self.providers = providers
        self._counter = 0

    def build_paths(
        self,
        workload: WorkloadIdentity,
        trust: FederatedTrust,
        role_evaluations: List[PermissionEvaluation],
        *,
        entry_routes: Optional[List[str]] = None,
        entry_status: str = "POTENTIAL",
        entry_label: Optional[str] = None,
        entry_evidence: Optional[List[str]] = None,
        blast_radius_ids: Optional[List[str]] = None,
        observed_actions: Optional[Dict[str, List[str]]] = None,
    ) -> List[AttackPath]:
        if trust.status == "BLOCKED":
            return self._blocked_path(workload, trust)

        observed_actions = observed_actions or {}
        provider = self.providers.get(trust.provider_arn)
        paths: List[AttackPath] = []

        for evaluation in role_evaluations:
            category = risk_category_for(evaluation.action)
            if category == "other":
                continue

            self._counter += 1
            steps: List[AttackPathStep] = []

            action_evidence = observed_actions.get(evaluation.action, [])
            action_status = "OBSERVED" if action_evidence else evaluation.status

            if entry_label:
                steps.append(
                    AttackPathStep(
                        node_id=f"entry::{workload.workload_id}",
                        node_type="k8s_subject" if workload.plane == "kubernetes" else "gha_workflow",
                        label=entry_label,
                        status=entry_status,
                        evidence_refs=entry_evidence or [],
                    )
                )

            steps.append(
                AttackPathStep(
                    node_id=f"workload::{workload.workload_id}",
                    node_type="k8s_serviceaccount"
                    if workload.plane == "kubernetes"
                    else "gha_workflow",
                    label=workload.subject,
                    status=entry_status,
                    evidence_refs=entry_evidence or [],
                )
            )

            steps.append(
                AttackPathStep(
                    node_id=f"oidc::{trust.provider_arn}",
                    node_type="oidc_provider",
                    label=provider.issuer_url if provider else trust.provider_arn,
                    status=trust.status,
                    evidence_refs=trust.evidence_refs,
                )
            )

            steps.append(
                AttackPathStep(
                    node_id=f"principal::{trust.role_arn}",
                    node_type="iam_role",
                    label=trust.role_arn.rsplit("/", 1)[-1],
                    status=trust.status,
                    evidence_refs=trust.evidence_refs,
                )
            )

            steps.append(
                AttackPathStep(
                    node_id=f"action::{evaluation.action}",
                    node_type="aws_action",
                    label=evaluation.action,
                    status=action_status,
                    evidence_refs=action_evidence,
                )
            )
            steps.append(
                AttackPathStep(
                    node_id=f"resource::{evaluation.resource_arn}",
                    node_type="resource",
                    label=evaluation.resource_arn,
                    status=action_status,
                    evidence_refs=action_evidence,
                )
            )

            path_status = min(steps, key=lambda s: STATUS_RANK.get(s.status, 2)).status
            score, rationale = self._score(
                evaluation, path_status, category, trust, entry_routes or [], blast_radius_ids or []
            )

            paths.append(
                AttackPath(
                    path_id=f"FED-{self._counter:03d}",
                    title=f"{workload.display_name} → {trust.role_arn.rsplit('/', 1)[-1]} "
                    f"→ {evaluation.action}",
                    risk_category=category,
                    steps=steps,
                    status=path_status,
                    risk_score=score,
                    scoring_rationale=rationale,
                    attack_technique_ids=self._techniques(category, workload.plane),
                    identity_planes=[workload.plane, "aws"],
                )
            )

        paths.sort(key=lambda p: (-STATUS_RANK.get(p.status, 2), -p.risk_score))
        return paths

    def _blocked_path(
        self, workload: WorkloadIdentity, trust: FederatedTrust
    ) -> List[AttackPath]:
        """Record refuted paths so the report shows what was ruled out and why."""
        self._counter += 1
        return [
            AttackPath(
                path_id=f"FED-{self._counter:03d}",
                title=f"{workload.display_name} → {trust.role_arn.rsplit('/', 1)[-1]} (refuted)",
                risk_category="privilege_escalation",
                steps=[
                    AttackPathStep(
                        node_id=f"workload::{workload.workload_id}",
                        node_type="k8s_serviceaccount"
                        if workload.plane == "kubernetes"
                        else "gha_workflow",
                        label=workload.subject,
                        status="BLOCKED",
                    )
                ],
                status="BLOCKED",
                risk_score=0,
                scoring_rationale=trust.broadening_reasons,
                attack_technique_ids=[],
                identity_planes=[workload.plane, "aws"],
            )
        ]

    @staticmethod
    def _techniques(category: str, plane: str) -> List[str]:
        techniques = list(CATEGORY_TECHNIQUES.get(category, []))
        if plane == "kubernetes":
            techniques.append("T1610")  # Deploy Container
        elif plane == "github_actions":
            techniques.append("T1195.002")  # Supply Chain Compromise
        return techniques

    @staticmethod
    def _score(
        evaluation: PermissionEvaluation,
        path_status: str,
        category: str,
        trust: FederatedTrust,
        entry_routes: List[str],
        blast_radius_ids: List[str],
    ) -> tuple[int, List[str]]:
        score = CATEGORY_BASE_RISK.get(category, 40)
        rationale = [f"Base risk for {category}: {score}"]

        score += PLANE_CROSSING_BONUS
        rationale.append(
            f"Path crosses an identity plane into cloud IAM (+{PLANE_CROSSING_BONUS})"
        )

        if path_status == "OBSERVED":
            score += 25
            rationale.append("CloudTrail confirms this role was assumed via OIDC (+25)")
        elif path_status == "UNRESOLVED":
            score -= 15
            rationale.append("Trust or permission conditions could not be evaluated (-15)")
        elif path_status == "BLOCKED":
            return 0, rationale + ["Trust condition refutes this path"]

        if trust.overly_broad:
            score += OVERLY_BROAD_TRUST_BONUS
            rationale.append(
                f"Trust condition is broader than one workload (+{OVERLY_BROAD_TRUST_BONUS})"
            )
            rationale.extend(f"  - {reason}" for reason in trust.broadening_reasons)

        if blast_radius_ids:
            rationale.append(
                f"Same condition also admits {len(blast_radius_ids)} other workload(s): "
                + ", ".join(blast_radius_ids[:5])
            )

        if entry_routes:
            score += UNTRUSTED_ENTRY_BONUS
            rationale.append(
                f"Reachable entry point into the workload (+{UNTRUSTED_ENTRY_BONUS})"
            )
            rationale.extend(f"  - {route}" for route in entry_routes[:4])

        if "*" in evaluation.resource_arn:
            score += 10
            rationale.append("Wildcard resource scope broadens blast radius (+10)")

        return max(0, min(100, score)), rationale


def summarize_federated(paths: List[AttackPath]) -> Dict[str, Any]:
    return {
        "total_paths": len(paths),
        "observed": sum(1 for p in paths if p.status == "OBSERVED"),
        "potential": sum(1 for p in paths if p.status == "POTENTIAL"),
        "unresolved": sum(1 for p in paths if p.status == "UNRESOLVED"),
        "blocked": sum(1 for p in paths if p.status == "BLOCKED"),
        "cross_plane_paths": sum(1 for p in paths if len(p.identity_planes) > 1),
        "planes": sorted({plane for p in paths for plane in p.identity_planes}),
        "highest_risk_score": max((p.risk_score for p in paths), default=0),
    }
