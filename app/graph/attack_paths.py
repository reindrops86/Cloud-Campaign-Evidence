from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.collectors.aws_identity import risk_category_for
from app.graph.iam_graph import IAMGraphEngine
from app.models import AttackPath, AttackPathStep, PermissionEvaluation

# Ordered weakest to strongest claim; a path inherits its weakest step.
STATUS_RANK = {
    "BLOCKED": 0,
    "UNRESOLVED": 1,
    "POTENTIAL": 2,
    "CONFIRMED_ALLOWED": 3,
    "OBSERVED": 4,
}

CATEGORY_TECHNIQUES = {
    "credential_creation": ["T1098.001"],
    "privilege_escalation": ["T1548", "T1078.004"],
    "secret_access": ["T1552.005"],
    "storage_access": ["T1530"],
    "defense_impairment": ["T1562.008"],
}

CATEGORY_BASE_RISK = {
    "credential_creation": 70,
    "privilege_escalation": 75,
    "secret_access": 65,
    "storage_access": 55,
    "defense_impairment": 80,
    "other": 40,
}

SENSITIVE_RESOURCE_MARKERS = ("prod", "production", "payment", "customer", "secret", "key")


class AttackPathAnalyzer:
    """Derives effective-permission attack paths from the IAM graph.

    Every path carries an explicit status so an analyst can tell configuration
    possibility apart from evaluated permission and observed activity.
    """

    def __init__(self, iam_graph: IAMGraphEngine) -> None:
        self.iam_graph = iam_graph

    def analyze(
        self,
        access_key_id: str,
        principal_arn: str,
        evaluations: List[PermissionEvaluation],
        observed_actions: Optional[Dict[str, List[str]]] = None,
    ) -> List[AttackPath]:
        observed_actions = observed_actions or {}
        paths: List[AttackPath] = []

        key_node = f"key::{access_key_id}"
        principal_node = f"principal::{principal_arn}"
        principal_label = self.iam_graph.nodes.get(principal_node, {}).get("label", principal_arn)

        assumable = [
            self.iam_graph.nodes[n]
            for n in self.iam_graph.neighbors(principal_node, "can_assume")
            if n in self.iam_graph.nodes
        ]

        for index, evaluation in enumerate(evaluations):
            category = risk_category_for(evaluation.action)
            if category == "other":
                continue

            evidence_refs = observed_actions.get(evaluation.action, [])
            contradictions: List[str] = []

            # An explicit deny outranks telemetry: if we see the call anyway the
            # policy snapshot and the log disagree, and the analyst must know.
            if evidence_refs and evaluation.status == "BLOCKED":
                action_status = "BLOCKED"
                contradictions.append(
                    f"CloudTrail shows {evaluation.action} occurred, but policy evaluation "
                    f"returned explicit deny. Policy snapshot may post-date the activity, or "
                    f"the call was made by a different principal."
                )
            elif evidence_refs:
                action_status = "OBSERVED"
            else:
                action_status = evaluation.status

            steps = [
                AttackPathStep(key_node, "access_key", access_key_id, "OBSERVED"),
                AttackPathStep(principal_node, "iam_user", principal_label, "OBSERVED"),
            ]

            pivot_role = self._pivot_role_for(evaluation, assumable)
            if pivot_role:
                pivot_status = "OBSERVED" if observed_actions.get("sts:AssumeRole") else "POTENTIAL"
                steps.append(
                    AttackPathStep(
                        pivot_role["id"], "iam_role", pivot_role["label"], pivot_status
                    )
                )

            steps.append(
                AttackPathStep(
                    f"action::{evaluation.action}",
                    "aws_action",
                    evaluation.action,
                    action_status,
                    evidence_refs=evidence_refs,
                )
            )
            steps.append(
                AttackPathStep(
                    f"resource::{evaluation.resource_arn}",
                    "resource",
                    evaluation.resource_arn,
                    action_status,
                )
            )

            path_status = min(steps, key=lambda s: STATUS_RANK.get(s.status, 2)).status
            score, rationale = self._score(
                evaluation, path_status, category, bool(pivot_role)
            )

            paths.append(
                AttackPath(
                    path_id=f"PATH-{index + 1:03d}",
                    title=f"{principal_label} → {evaluation.action} on {evaluation.resource_arn}",
                    risk_category=category,
                    steps=steps,
                    status=path_status,
                    risk_score=score,
                    scoring_rationale=rationale,
                    attack_technique_ids=CATEGORY_TECHNIQUES.get(category, []),
                    contradictions=contradictions,
                )
            )

        paths.sort(key=lambda p: (-STATUS_RANK.get(p.status, 2), -p.risk_score))
        return paths

    @staticmethod
    def _pivot_role_for(
        evaluation: PermissionEvaluation, assumable: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Only paths granted through an assumed role get a role pivot step."""
        if not evaluation.via_role_arn:
            return None
        return next(
            (r for r in assumable if r.get("arn") == evaluation.via_role_arn),
            None,
        )

    @staticmethod
    def _score(
        evaluation: PermissionEvaluation,
        path_status: str,
        category: str,
        crosses_role: bool,
    ) -> tuple[int, List[str]]:
        score = CATEGORY_BASE_RISK.get(category, 40)
        rationale = [f"Base risk for {category}: {score}"]

        if path_status == "OBSERVED":
            score += 25
            rationale.append("CloudTrail confirms the action was invoked (+25)")
        elif path_status == "CONFIRMED_ALLOWED":
            score += 15
            rationale.append("IAM policy simulator evaluated the action as allowed (+15)")
        elif path_status == "UNRESOLVED":
            score -= 15
            rationale.append("Policy conditions could not be evaluated (-15)")
        elif path_status == "BLOCKED":
            score -= 50
            rationale.append("Explicit deny or permissions boundary blocks this path (-50)")

        if crosses_role:
            score += 10
            rationale.append("Path pivots through an assumable role (+10)")

        if "*" in evaluation.resource_arn:
            score += 10
            rationale.append("Wildcard resource scope broadens blast radius (+10)")

        if any(marker in evaluation.resource_arn.lower() for marker in SENSITIVE_RESOURCE_MARKERS):
            score += 10
            rationale.append("Target resource is tagged/named as sensitive (+10)")

        if evaluation.unresolved_conditions:
            rationale.append(
                "Unresolved conditions: " + ", ".join(evaluation.unresolved_conditions)
            )

        return max(0, min(100, score)), rationale


def summarize_paths(paths: List[AttackPath]) -> Dict[str, Any]:
    return {
        "total_paths": len(paths),
        "observed": sum(1 for p in paths if p.status == "OBSERVED"),
        "confirmed_allowed": sum(1 for p in paths if p.status == "CONFIRMED_ALLOWED"),
        "potential": sum(1 for p in paths if p.status == "POTENTIAL"),
        "unresolved": sum(1 for p in paths if p.status == "UNRESOLVED"),
        "blocked": sum(1 for p in paths if p.status == "BLOCKED"),
        "contradictions": sum(len(p.contradictions) for p in paths),
        "highest_risk_score": max((p.risk_score for p in paths), default=0),
    }
