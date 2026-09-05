from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Optional, Tuple

from app.models import (
    FederatedTrust,
    OIDCProvider,
    TrustCondition,
    WorkloadIdentity,
)

# Claim suffixes that identify the calling workload. A wildcard here is what turns
# "one service account" into "every workload behind this provider".
SUBJECT_CLAIMS = (":sub",)
AUDIENCE_CLAIMS = (":aud",)

# Subjects broad enough that the trust policy no longer constrains anything useful.
CATCH_ALL_SUBJECTS = {"*", "system:serviceaccount:*:*", "repo:*"}


def parse_trust_conditions(trust_policy: Dict[str, Any]) -> List[Tuple[str, List[TrustCondition]]]:
    """Extract (federated principal, conditions) pairs from a role trust policy."""
    statements = trust_policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    parsed: List[Tuple[str, List[TrustCondition]]] = []
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        if "sts:AssumeRoleWithWebIdentity" not in _as_list(stmt.get("Action", [])):
            continue

        federated = (stmt.get("Principal", {}) or {}).get("Federated")
        if not federated:
            continue

        conditions: List[TrustCondition] = []
        for operator, claims in (stmt.get("Condition", {}) or {}).items():
            for claim, values in claims.items():
                conditions.append(
                    TrustCondition(operator=operator, claim=claim, values=_as_list(values))
                )
        parsed.append((federated, conditions))

    return parsed


def _as_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    return list(value or [])


def _claim_matches(condition: TrustCondition, subject: str) -> bool:
    if condition.operator.endswith("StringEquals"):
        return subject in condition.values
    if condition.operator.endswith("StringLike"):
        return any(fnmatch.fnmatchcase(subject, pattern) for pattern in condition.values)
    return False


def _describe_broadening(condition: TrustCondition, workload: WorkloadIdentity) -> Optional[str]:
    """Explain why a condition grants more than the specific workload in hand."""
    if not condition.is_wildcard:
        return None

    for value in condition.values:
        if value in CATCH_ALL_SUBJECTS:
            return (
                f"`{condition.operator}` on `{condition.claim}` uses catch-all `{value}`: "
                f"every workload behind this provider can assume the role."
            )

        if workload.plane == "kubernetes" and value.startswith("system:serviceaccount:"):
            parts = value.split(":")
            namespace = parts[2] if len(parts) > 2 else ""
            account = parts[3] if len(parts) > 3 else ""
            if namespace == "*" and account == "*":
                return (
                    f"`{value}` matches any ServiceAccount in any namespace: "
                    f"pod-create rights anywhere in the cluster grant this role."
                )
            if namespace == "*":
                return (
                    f"`{value}` is namespace-wildcarded: a ServiceAccount named "
                    f"`{account}` in any namespace assumes this role."
                )
            if account == "*":
                return (
                    f"`{value}` matches any ServiceAccount in namespace `{namespace}`: "
                    f"pod-create rights in that namespace grant this role."
                )

        if workload.plane == "github_actions" and value.startswith("repo:"):
            if ":ref:" not in value and ":environment:" not in value and ":pull_request" not in value:
                return (
                    f"`{value}` constrains the repository but not the ref: any branch, "
                    f"tag, or pull-request workflow can assume this role."
                )
            if "/*" in value.split(":")[1]:
                return (
                    f"`{value}` is org-wildcarded: any repository in the organization "
                    f"can assume this role."
                )

    return (
        f"`{condition.operator}` on `{condition.claim}` uses wildcard "
        f"{condition.values}: the trust boundary is wider than one workload."
    )


def evaluate_federated_trust(
    workload: WorkloadIdentity,
    role_arn: str,
    trust_policy: Dict[str, Any],
    providers: Dict[str, OIDCProvider],
    observed_assumptions: Optional[Dict[str, List[str]]] = None,
) -> Optional[FederatedTrust]:
    """Decide whether `workload` may assume `role_arn` through OIDC federation.

    Returns None when the trust policy has no federated statement for the
    workload's provider, so absence of a match is never scored as a finding.
    """
    observed_assumptions = observed_assumptions or {}

    for federated_arn, conditions in parse_trust_conditions(trust_policy):
        provider = providers.get(federated_arn)
        if not provider or provider.plane != workload.plane:
            continue

        subject_conditions = [
            c for c in conditions if any(c.claim.endswith(s) for s in SUBJECT_CLAIMS)
        ]

        # No subject condition at all is the worst case: the provider alone is the boundary.
        if not subject_conditions:
            return FederatedTrust(
                workload_id=workload.workload_id,
                role_arn=role_arn,
                provider_arn=federated_arn,
                status="POTENTIAL",
                matched_conditions=[],
                overly_broad=True,
                broadening_reasons=[
                    "Trust policy has no `:sub` condition: any workload holding a token "
                    "from this provider can assume the role."
                ],
            )

        matched = [c for c in subject_conditions if _claim_matches(c, workload.subject)]
        if not matched:
            return FederatedTrust(
                workload_id=workload.workload_id,
                role_arn=role_arn,
                provider_arn=federated_arn,
                status="BLOCKED",
                matched_conditions=[],
                broadening_reasons=[
                    f"Subject `{workload.subject}` does not satisfy any `:sub` condition."
                ],
            )

        # An unverifiable audience is a gap in the evaluation, not a pass.
        audience_conditions = [
            c for c in conditions if any(c.claim.endswith(a) for a in AUDIENCE_CLAIMS)
        ]
        if audience_conditions and not provider.audiences:
            return FederatedTrust(
                workload_id=workload.workload_id,
                role_arn=role_arn,
                provider_arn=federated_arn,
                status="UNRESOLVED",
                matched_conditions=matched,
                broadening_reasons=[
                    "Audience condition present but the provider's registered audience "
                    "list is unknown; cannot confirm the token would be accepted."
                ],
            )

        reasons = [r for c in matched if (r := _describe_broadening(c, workload))]
        evidence = observed_assumptions.get(f"{workload.subject}|{role_arn}", [])

        return FederatedTrust(
            workload_id=workload.workload_id,
            role_arn=role_arn,
            provider_arn=federated_arn,
            status="OBSERVED" if evidence else "POTENTIAL",
            matched_conditions=matched,
            overly_broad=bool(reasons),
            broadening_reasons=reasons,
            evidence_refs=evidence,
        )

    return None


def blast_radius(trust: FederatedTrust, workloads: List[WorkloadIdentity]) -> List[str]:
    """List every other workload the same matched conditions would also admit."""
    if not trust.overly_broad or not trust.matched_conditions:
        return []

    return [
        w.workload_id
        for w in workloads
        if w.workload_id != trust.workload_id
        and any(_claim_matches(c, w.subject) for c in trust.matched_conditions)
    ]
