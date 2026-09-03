from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.collectors.aws_cloudtrail import EvidenceSource
from app.collectors.aws_identity import (
    IdentitySource,
    all_high_risk_actions,
    evaluate_from_statements,
)
from app.graph.attack_paths import AttackPathAnalyzer, summarize_paths
from app.graph.evidence_graph import EvidenceGraphEngine
from app.graph.iam_graph import IAMGraphEngine
from app.models import AttackPath, EvidenceRecord, PermissionEvaluation


class AWSTelemetryAgent:
    """Turns raw AWS telemetry into evidence-backed graph nodes and attack paths.

    Every graph edge it creates cites the CloudTrail evidence_id that proves it,
    so an analyst can trace any conclusion back to a source event.
    """

    def __init__(
        self,
        evidence_graph: EvidenceGraphEngine,
        evidence_source: EvidenceSource,
        identity_source: Optional[IdentitySource] = None,
    ) -> None:
        self.evidence_graph = evidence_graph
        self.evidence_source = evidence_source
        self.identity_source = identity_source
        self.iam_graph = IAMGraphEngine()
        self.records: List[EvidenceRecord] = []

    def investigate(
        self,
        access_key_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        simulate: bool = False,
    ) -> Dict[str, Any]:
        end_time = end_time or datetime.now(timezone.utc)
        start_time = start_time or (end_time - timedelta(days=90))

        self.records = self.evidence_source.events_for_access_key(
            access_key_id, start_time, end_time
        )
        seed_id = self._ingest_records(access_key_id)

        result: Dict[str, Any] = {
            "access_key_id": access_key_id,
            "seed_node_id": seed_id,
            "window": {"start": start_time.isoformat(), "end": end_time.isoformat()},
            "event_count": len(self.records),
            "management_events": sum(1 for r in self.records if r.event_category == "Management"),
            "data_events": sum(1 for r in self.records if r.event_category == "Data"),
            "evidence_records": [r.__dict__ for r in self.records],
            "attack_paths": [],
            "attack_path_summary": summarize_paths([]),
            "iam_graph": {"node_count": 0, "edge_count": 0, "nodes": [], "edges": []},
        }

        if not self.identity_source:
            result["identity_note"] = "No IAM source configured; permission analysis skipped."
            return result

        principal = self.identity_source.principal_for_access_key(access_key_id)
        if not principal:
            result["identity_note"] = f"No IAM principal resolved for {access_key_id}."
            return result

        statements = self.identity_source.statements_for_principal(principal)
        roles = self.identity_source.assumable_roles(principal)
        role_statements = {
            role.arn: self.identity_source.statements_for_principal(role) for role in roles
        }

        self.iam_graph.build_from_principal(
            access_key_id, principal, statements, roles, role_statements
        )

        observed = self._observed_actions(principal.arn)
        self.iam_graph.mark_observed_actions(principal.arn, observed)

        evaluations = self._evaluate(principal, statements, role_statements, simulate)
        self.iam_graph.apply_evaluations(evaluations)

        paths = AttackPathAnalyzer(self.iam_graph).analyze(
            access_key_id, principal.arn, evaluations, observed
        )

        result.update(
            {
                "principal": principal.__dict__,
                "assumable_roles": [r.arn for r in roles],
                "observed_actions": observed,
                "permission_evaluations": [e.__dict__ for e in evaluations],
                "attack_paths": [self._path_dict(p) for p in paths],
                "attack_path_summary": summarize_paths(paths),
                "iam_graph": self.iam_graph.export_dict(),
            }
        )
        return result

    def _ingest_records(self, access_key_id: str) -> str:
        key_node = f"seed-iam_access_key-{access_key_id}"
        if not self.records:
            return key_node

        first = min(r.event_time for r in self.records)
        last = max(r.event_time for r in self.records)

        self.evidence_graph.add_node(
            node_id=key_node,
            value=access_key_id,
            indicator_type="iam_access_key",
            first_seen=first,
            last_seen=last,
            reputation_score=75,
            source="aws_cloudtrail",
            metadata={"event_count": len(self.records)},
        )

        for record in self.records:
            if record.source_ip:
                ip_node = f"node-ip-{record.source_ip.replace('.', '-')}"
                self.evidence_graph.add_node(
                    node_id=ip_node,
                    value=record.source_ip,
                    indicator_type="ip",
                    first_seen=record.event_time,
                    last_seen=record.event_time,
                    reputation_score=50,
                    source="aws_cloudtrail",
                    metadata={"account_id": record.account_id, "region": record.region},
                )
                self.evidence_graph.add_edge(
                    source_id=key_node,
                    target_id=ip_node,
                    relation_type="observed_from",
                    confidence=100,
                    evidence_basis=f"CloudTrail {record.event_name} from {record.source_ip}",
                    first_observed=record.event_time,
                    last_observed=record.event_time,
                    evidence_refs=[record.evidence_id],
                    observed=True,
                )

            action = f"{record.event_source.split('.')[0]}:{record.event_name}"
            action_node = f"node-action-{action.replace(':', '-')}"
            self.evidence_graph.add_node(
                node_id=action_node,
                value=action,
                indicator_type="aws_action",
                first_seen=record.event_time,
                last_seen=record.event_time,
                reputation_score=40,
                source="aws_cloudtrail",
                metadata={"event_category": record.event_category},
            )
            self.evidence_graph.add_edge(
                source_id=key_node,
                target_id=action_node,
                relation_type="performed",
                confidence=100,
                evidence_basis=f"CloudTrail event {record.event_id}",
                first_observed=record.event_time,
                last_observed=record.event_time,
                evidence_refs=[record.evidence_id],
                observed=True,
            )

            for resource in record.resources:
                arn = resource.get("ARN")
                if not arn:
                    continue
                resource_node = f"node-resource-{abs(hash(arn)) % 100000}"
                self.evidence_graph.add_node(
                    node_id=resource_node,
                    value=arn,
                    indicator_type="aws_resource",
                    first_seen=record.event_time,
                    last_seen=record.event_time,
                    reputation_score=30,
                    source="aws_cloudtrail",
                    metadata={"resource_type": resource.get("type", "")},
                )
                self.evidence_graph.add_edge(
                    source_id=action_node,
                    target_id=resource_node,
                    relation_type="affected",
                    confidence=100,
                    evidence_basis=f"CloudTrail {record.event_name} targeted {arn}",
                    first_observed=record.event_time,
                    last_observed=record.event_time,
                    evidence_refs=[record.evidence_id],
                    observed=True,
                )

        return key_node

    def _observed_actions(self, principal_arn: str) -> Dict[str, List[str]]:
        observed: Dict[str, List[str]] = {}
        for record in self.records:
            if record.principal_arn and record.principal_arn != principal_arn:
                continue
            action = f"{record.event_source.split('.')[0]}:{record.event_name}"
            observed.setdefault(action, []).append(record.evidence_id)
        return observed

    def _evaluate(
        self,
        principal: Any,
        statements: List[Any],
        role_statements: Dict[str, List[Any]],
        simulate: bool,
    ) -> List[PermissionEvaluation]:
        actions = all_high_risk_actions()

        if simulate and hasattr(self.identity_source, "simulate"):
            return self.identity_source.simulate(principal.arn, actions, [])

        evaluations = evaluate_from_statements(principal, statements, actions)

        # Role permissions are reachable only after a successful assume-role pivot.
        for role_arn, stmts in role_statements.items():
            for evaluation in evaluate_from_statements(principal, stmts, actions):
                evaluation.matched_statements.append(f"via-role::{role_arn}")
                evaluation.via_role_arn = role_arn
                evaluations.append(evaluation)

        return evaluations

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
            "contradictions": path.contradictions,
            "steps": [s.__dict__ for s in path.steps],
        }
