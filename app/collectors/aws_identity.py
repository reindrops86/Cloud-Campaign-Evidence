from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

from app.models import IAMPrincipal, PermissionEvaluation, PolicyStatement

HIGH_RISK_ACTIONS: Dict[str, List[str]] = {
    "credential_creation": [
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
    ],
    "privilege_escalation": [
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PassRole",
        "sts:AssumeRole",
    ],
    "secret_access": [
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",
        "kms:Decrypt",
    ],
    "storage_access": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutBucketPolicy",
    ],
    "defense_impairment": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "guardduty:DeleteDetector",
    ],
}


def all_high_risk_actions() -> List[str]:
    return [action for actions in HIGH_RISK_ACTIONS.values() for action in actions]


def risk_category_for(action: str) -> str:
    for category, actions in HIGH_RISK_ACTIONS.items():
        if action in actions:
            return category
    return "other"


def _statements_from_document(
    document: Dict[str, Any], policy_arn: str, policy_name: str
) -> List[PolicyStatement]:
    raw_statements = document.get("Statement", [])
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]

    statements: List[PolicyStatement] = []
    for stmt in raw_statements:
        actions = stmt.get("Action", stmt.get("NotAction", []))
        resources = stmt.get("Resource", stmt.get("NotResource", []))
        statements.append(
            PolicyStatement(
                policy_arn=policy_arn,
                policy_name=policy_name,
                sid=stmt.get("Sid"),
                effect=stmt.get("Effect", "Allow"),
                actions=[actions] if isinstance(actions, str) else list(actions),
                resources=[resources] if isinstance(resources, str) else list(resources),
                conditions=stmt.get("Condition", {}) or {},
            )
        )
    return statements


class IdentitySource(Protocol):
    def principal_for_access_key(self, access_key_id: str) -> Optional[IAMPrincipal]: ...
    def statements_for_principal(self, principal: IAMPrincipal) -> List[PolicyStatement]: ...
    def assumable_roles(self, principal: IAMPrincipal) -> List[IAMPrincipal]: ...


class FileIdentitySource:
    """Loads an exported IAM snapshot so identity analysis works offline."""

    def __init__(self, path: str | Path) -> None:
        self.snapshot: Dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))

    def principal_for_access_key(self, access_key_id: str) -> Optional[IAMPrincipal]:
        for entry in self.snapshot.get("access_keys", []):
            if entry.get("AccessKeyId") != access_key_id:
                continue
            return self._principal(entry.get("UserName", ""), "user")
        return None

    def _principal(self, name: str, principal_type: str) -> Optional[IAMPrincipal]:
        collection = "users" if principal_type == "user" else "roles"
        for item in self.snapshot.get(collection, []):
            if item.get("Name") != name:
                continue
            return IAMPrincipal(
                arn=item.get("Arn", ""),
                name=name,
                principal_type=principal_type,
                account_id=item.get("AccountId"),
                attached_policy_arns=[p["PolicyArn"] for p in item.get("AttachedPolicies", [])],
                inline_policy_names=[p["PolicyName"] for p in item.get("InlinePolicies", [])],
                group_names=item.get("Groups", []),
                permissions_boundary_arn=item.get("PermissionsBoundaryArn"),
                trust_policy=item.get("AssumeRolePolicyDocument"),
                tags=item.get("Tags", {}),
            )
        return None

    def statements_for_principal(self, principal: IAMPrincipal) -> List[PolicyStatement]:
        collection = "users" if principal.principal_type == "user" else "roles"
        statements: List[PolicyStatement] = []

        for item in self.snapshot.get(collection, []):
            if item.get("Name") != principal.name:
                continue
            for policy in item.get("AttachedPolicies", []) + item.get("InlinePolicies", []):
                statements.extend(
                    _statements_from_document(
                        policy.get("PolicyDocument", {}),
                        policy.get("PolicyArn", f"inline::{policy.get('PolicyName', '')}"),
                        policy.get("PolicyName", ""),
                    )
                )

        for group_name in principal.group_names:
            for group in self.snapshot.get("groups", []):
                if group.get("Name") != group_name:
                    continue
                for policy in group.get("AttachedPolicies", []) + group.get("InlinePolicies", []):
                    statements.extend(
                        _statements_from_document(
                            policy.get("PolicyDocument", {}),
                            policy.get("PolicyArn", f"inline::{policy.get('PolicyName', '')}"),
                            policy.get("PolicyName", ""),
                        )
                    )

        return statements

    def assumable_roles(self, principal: IAMPrincipal) -> List[IAMPrincipal]:
        statements = self.statements_for_principal(principal)
        allowed_targets: List[str] = []
        for stmt in statements:
            if stmt.effect != "Allow":
                continue
            if not any(a in ("sts:AssumeRole", "sts:*", "*") for a in stmt.actions):
                continue
            allowed_targets.extend(stmt.resources)

        roles: List[IAMPrincipal] = []
        for item in self.snapshot.get("roles", []):
            arn = item.get("Arn", "")
            if not any(target in ("*", arn) for target in allowed_targets):
                continue
            if not self._trust_accepts(item.get("AssumeRolePolicyDocument", {}), principal):
                continue
            role = self._principal(item.get("Name", ""), "role")
            if role:
                roles.append(role)
        return roles

    @staticmethod
    def _trust_accepts(trust_policy: Dict[str, Any], principal: IAMPrincipal) -> bool:
        raw_statements = trust_policy.get("Statement", [])
        if isinstance(raw_statements, dict):
            raw_statements = [raw_statements]

        for stmt in raw_statements:
            if stmt.get("Effect") != "Allow":
                continue
            aws_principals = (stmt.get("Principal", {}) or {}).get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for candidate in aws_principals:
                if candidate == "*" or candidate == principal.arn:
                    return True
                if principal.account_id and candidate.endswith(f":{principal.account_id}:root"):
                    return True
        return False


class AWSIdentityCollector:
    """Live IAM collection plus SimulatePrincipalPolicy evaluation."""

    def __init__(self, profile_name: Optional[str] = None) -> None:
        import boto3  # imported lazily so offline mode needs no AWS SDK

        session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
        self.iam = session.client("iam")

    def principal_for_access_key(self, access_key_id: str) -> Optional[IAMPrincipal]:
        last_used = self.iam.get_access_key_last_used(AccessKeyId=access_key_id)
        username = last_used.get("UserName")
        if not username:
            return None

        user = self.iam.get_user(UserName=username)["User"]
        attached = self.iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        inline = self.iam.list_user_policies(UserName=username)["PolicyNames"]
        groups = self.iam.list_groups_for_user(UserName=username)["Groups"]

        return IAMPrincipal(
            arn=user["Arn"],
            name=username,
            principal_type="user",
            account_id=user["Arn"].split(":")[4],
            attached_policy_arns=[p["PolicyArn"] for p in attached],
            inline_policy_names=list(inline),
            group_names=[g["GroupName"] for g in groups],
            permissions_boundary_arn=(user.get("PermissionsBoundary") or {}).get(
                "PermissionsBoundaryArn"
            ),
        )

    def statements_for_principal(self, principal: IAMPrincipal) -> List[PolicyStatement]:
        statements: List[PolicyStatement] = []

        for policy_arn in principal.attached_policy_arns:
            policy = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]
            version = self.iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]
            statements.extend(
                _statements_from_document(version["Document"], policy_arn, policy["PolicyName"])
            )

        for policy_name in principal.inline_policy_names:
            document = self.iam.get_user_policy(
                UserName=principal.name, PolicyName=policy_name
            )["PolicyDocument"]
            statements.extend(
                _statements_from_document(document, f"inline::{policy_name}", policy_name)
            )

        return statements

    def assumable_roles(self, principal: IAMPrincipal) -> List[IAMPrincipal]:
        roles: List[IAMPrincipal] = []
        for role in self.iam.list_roles()["Roles"]:
            if not FileIdentitySource._trust_accepts(
                role.get("AssumeRolePolicyDocument", {}), principal
            ):
                continue
            attached = self.iam.list_attached_role_policies(RoleName=role["RoleName"])
            roles.append(
                IAMPrincipal(
                    arn=role["Arn"],
                    name=role["RoleName"],
                    principal_type="role",
                    account_id=role["Arn"].split(":")[4],
                    attached_policy_arns=[p["PolicyArn"] for p in attached["AttachedPolicies"]],
                    trust_policy=role.get("AssumeRolePolicyDocument"),
                )
            )
        return roles

    def simulate(
        self, principal_arn: str, actions: List[str], resource_arns: List[str]
    ) -> List[PermissionEvaluation]:
        response = self.iam.simulate_principal_policy(
            PolicySourceArn=principal_arn,
            ActionNames=actions,
            ResourceArns=resource_arns or ["*"],
        )

        evaluations: List[PermissionEvaluation] = []
        for result in response.get("EvaluationResults", []):
            decision = result["EvalDecision"]
            missing = result.get("MissingContextValues", [])
            evaluations.append(
                PermissionEvaluation(
                    principal_arn=principal_arn,
                    action=result["EvalActionName"],
                    resource_arn=result.get("EvalResourceName", "*"),
                    decision=decision,
                    status=_status_from_decision(decision, bool(missing)),
                    matched_statements=[
                        s.get("SourcePolicyId", "") for s in result.get("MatchedStatements", [])
                    ],
                    unresolved_conditions=missing,
                    evaluation_source="policy_simulator",
                )
            )
        return evaluations


def _status_from_decision(decision: str, has_missing_context: bool) -> str:
    if has_missing_context:
        return "UNRESOLVED"
    if decision == "allowed":
        return "CONFIRMED_ALLOWED"
    if decision == "explicitDeny":
        return "BLOCKED"
    return "POTENTIAL"


def evaluate_from_statements(
    principal: IAMPrincipal, statements: List[PolicyStatement], actions: List[str]
) -> List[PermissionEvaluation]:
    """Graph-based evaluation used when the policy simulator is unavailable.

    Deliberately conservative: results are POTENTIAL, never CONFIRMED_ALLOWED.
    """
    evaluations: List[PermissionEvaluation] = []

    for action in actions:
        service = action.split(":")[0]
        matched: List[str] = []
        denied = False
        unresolved: List[str] = []
        resource = "*"

        for stmt in statements:
            action_match = any(
                pattern == "*" or pattern == action or pattern == f"{service}:*"
                for pattern in stmt.actions
            )
            if not action_match:
                continue
            if stmt.effect == "Deny":
                denied = True
                matched.append(f"{stmt.policy_name}:{stmt.sid or 'stmt'}")
                break
            matched.append(f"{stmt.policy_name}:{stmt.sid or 'stmt'}")
            resource = stmt.resources[0] if stmt.resources else "*"
            if stmt.conditions:
                unresolved.extend(stmt.conditions.keys())

        if denied:
            status, decision = "BLOCKED", "explicitDeny"
        elif unresolved:
            status, decision = "UNRESOLVED", "unresolved"
        elif matched:
            status, decision = "POTENTIAL", "allowed"
        else:
            continue

        evaluations.append(
            PermissionEvaluation(
                principal_arn=principal.arn,
                action=action,
                resource_arn=resource,
                decision=decision,
                status=status,
                matched_statements=matched,
                unresolved_conditions=unresolved,
                evaluation_source="graph",
            )
        )

    return evaluations
