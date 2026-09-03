from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from app.models import IAMPrincipal, PermissionEvaluation, PolicyStatement

NODE_TYPES = {
    "access_key",
    "iam_user",
    "iam_group",
    "iam_role",
    "policy",
    "policy_statement",
    "aws_action",
    "resource",
    "account",
}


class IAMGraphEngine:
    """Permission graph of identities, policies, actions, and resources.

    Nodes and edges describe configuration. Whether a path is actually usable is
    decided by AttackPathAnalyzer using evaluations and observed telemetry.
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def add_node(self, node_id: str, node_type: str, label: str, **attrs: Any) -> str:
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "node_type": node_type,
                "label": label,
                **attrs,
            }
        else:
            self.nodes[node_id].update(attrs)
        return node_id

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: str,
        *,
        status: str = "POTENTIAL",
        evidence_refs: Optional[List[str]] = None,
        note: str = "",
    ) -> Dict[str, Any]:
        for edge in self.edges:
            if (
                edge["source"] == source_id
                and edge["target"] == target_id
                and edge["relationship"] == relationship
            ):
                for ref in evidence_refs or []:
                    if ref not in edge["evidence_refs"]:
                        edge["evidence_refs"].append(ref)
                return edge

        edge = {
            "source": source_id,
            "target": target_id,
            "relationship": relationship,
            "status": status,
            "evidence_refs": list(evidence_refs or []),
            "note": note,
        }
        self.edges.append(edge)
        return edge

    def build_from_principal(
        self,
        access_key_id: str,
        principal: IAMPrincipal,
        statements: List[PolicyStatement],
        assumable_roles: List[IAMPrincipal],
        role_statements: Optional[Dict[str, List[PolicyStatement]]] = None,
    ) -> None:
        key_node = self.add_node(f"key::{access_key_id}", "access_key", access_key_id)
        principal_node = self.add_node(
            f"principal::{principal.arn}",
            "iam_user" if principal.principal_type == "user" else "iam_role",
            principal.name,
            arn=principal.arn,
            account_id=principal.account_id,
        )
        self.add_edge(key_node, principal_node, "belongs_to")

        if principal.account_id:
            account_node = self.add_node(
                f"account::{principal.account_id}", "account", principal.account_id
            )
            self.add_edge(principal_node, account_node, "in_account")

        for group in principal.group_names:
            group_node = self.add_node(f"group::{group}", "iam_group", group)
            self.add_edge(principal_node, group_node, "member_of")

        self._attach_statements(principal_node, statements)

        for role in assumable_roles:
            role_node = self.add_node(
                f"principal::{role.arn}", "iam_role", role.name, arn=role.arn
            )
            self.add_edge(
                principal_node,
                role_node,
                "can_assume",
                note="policy allows sts:AssumeRole and role trust policy accepts principal",
            )
            self._attach_statements(role_node, (role_statements or {}).get(role.arn, []))

    def _attach_statements(self, principal_node: str, statements: List[PolicyStatement]) -> None:
        for stmt in statements:
            policy_node = self.add_node(
                f"policy::{stmt.policy_arn}", "policy", stmt.policy_name, arn=stmt.policy_arn
            )
            self.add_edge(principal_node, policy_node, "has_policy")

            stmt_id = f"stmt::{stmt.policy_arn}::{stmt.sid or len(self.edges)}"
            self.add_node(
                stmt_id,
                "policy_statement",
                stmt.sid or "unnamed-statement",
                effect=stmt.effect,
                conditions=stmt.conditions,
            )
            self.add_edge(policy_node, stmt_id, "contains")

            relationship = "allows" if stmt.effect == "Allow" else "denies"
            for action in stmt.actions:
                action_node = self.add_node(f"action::{action}", "aws_action", action)
                self.add_edge(stmt_id, action_node, relationship)

                for resource in stmt.resources or ["*"]:
                    resource_node = self.add_node(f"resource::{resource}", "resource", resource)
                    self.add_edge(action_node, resource_node, "targets")

    def mark_observed_actions(self, principal_arn: str, observed: Dict[str, List[str]]) -> None:
        """Flag action nodes that CloudTrail shows were actually invoked."""
        principal_node = f"principal::{principal_arn}"
        for action, evidence_refs in observed.items():
            action_node = f"action::{action}"
            if action_node not in self.nodes:
                self.add_node(action_node, "aws_action", action)
            self.nodes[action_node]["observed"] = True
            self.add_edge(
                principal_node,
                action_node,
                "performed",
                status="OBSERVED",
                evidence_refs=evidence_refs,
                note="CloudTrail record confirms this API call occurred",
            )

    def apply_evaluations(self, evaluations: List[PermissionEvaluation]) -> None:
        for evaluation in evaluations:
            action_node = self.add_node(
                f"action::{evaluation.action}", "aws_action", evaluation.action
            )
            self.add_edge(
                f"principal::{evaluation.principal_arn}",
                action_node,
                "can_perform",
                status=evaluation.status,
                note=f"{evaluation.evaluation_source}: {evaluation.decision}",
            )

    def neighbors(self, node_id: str, relationship: Optional[str] = None) -> List[str]:
        return [
            edge["target"]
            for edge in self.edges
            if edge["source"] == node_id and (relationship is None or edge["relationship"] == relationship)
        ]

    def export_dict(self) -> Dict[str, Any]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }
