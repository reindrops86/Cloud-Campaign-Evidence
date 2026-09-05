from __future__ import annotations

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.agents.workload_federation import WorkloadFederationAgent
from app.collectors.github_actions import (
    GitHubActionsSource,
    observed_role_actions,
    observed_web_identity_assumptions,
)
from app.collectors.k8s_rbac import K8sRBACSource, load_audit_events, observed_pod_creates
from app.graph.evidence_graph import EvidenceGraphEngine
from app.graph.federation import (
    blast_radius,
    evaluate_federated_trust,
    parse_trust_conditions,
)
from app.main import _federation_cloudtrail_records
from app.models import OIDCProvider, WorkloadIdentity

ROOT = Path(__file__).resolve().parent.parent
FED = ROOT / "data" / "federation"
ROLES = FED / "aws_federated_roles.json"
K8S = FED / "k8s_cluster_prod_east.json"
K8S_AUDIT = FED / "k8s_audit_prod_east.json"
GITHUB = FED / "github_org_example.json"
CLOUDTRAIL = FED / "cloudtrail_web_identity.json"

EKS_ISSUER = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
EKS_PROVIDER = f"arn:aws:iam::111122223333:oidc-provider/{EKS_ISSUER}"
GHA_PROVIDER = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"


def _agent() -> WorkloadFederationAgent:
    return WorkloadFederationAgent(
        EvidenceGraphEngine(),
        ROLES,
        k8s_snapshot=K8S,
        k8s_audit_log=K8S_AUDIT,
        github_snapshot=GITHUB,
        cloudtrail_records=_federation_cloudtrail_records(str(CLOUDTRAIL), "file"),
    )


def _providers():
    return {
        EKS_PROVIDER: OIDCProvider(EKS_PROVIDER, f"https://{EKS_ISSUER}", "kubernetes",
                                   ["sts.amazonaws.com"], "prod-east"),
        GHA_PROVIDER: OIDCProvider(GHA_PROVIDER, "https://token.actions.githubusercontent.com",
                                   "github_actions", ["sts.amazonaws.com"]),
    }


def test_trust_conditions_parse_operator_and_claim():
    import json

    roles = json.loads(ROLES.read_text(encoding="utf-8"))["federated_roles"]
    payments = next(r for r in roles if r["Name"] == "eks-payments-irsa")

    parsed = parse_trust_conditions(payments["AssumeRolePolicyDocument"])
    assert len(parsed) == 1

    federated, conditions = parsed[0]
    assert federated == EKS_PROVIDER

    sub = next(c for c in conditions if c.claim.endswith(":sub"))
    assert sub.operator == "StringLike"
    assert sub.is_wildcard is True
    assert sub.is_exact_match is False


def test_exact_match_condition_is_not_flagged_broad():
    import json

    roles = json.loads(ROLES.read_text(encoding="utf-8"))["federated_roles"]
    logging_role = next(r for r in roles if r["Name"] == "eks-logging-irsa")

    workload = WorkloadIdentity(
        "k8s::observability/fluentbit-sa", "kubernetes",
        "system:serviceaccount:observability:fluentbit-sa", "observability/fluentbit-sa",
        namespace="observability",
    )

    trust = evaluate_federated_trust(
        workload, logging_role["Arn"], logging_role["AssumeRolePolicyDocument"], _providers()
    )
    assert trust.status == "POTENTIAL"
    assert trust.overly_broad is False


def test_wildcard_subject_admits_unintended_workloads():
    """system:serviceaccount:*:* means every SA in the cluster, not just the intended one."""
    import json

    roles = json.loads(ROLES.read_text(encoding="utf-8"))["federated_roles"]
    payments = next(r for r in roles if r["Name"] == "eks-payments-irsa")

    intruder = WorkloadIdentity(
        "k8s::ci/build-runner-sa", "kubernetes",
        "system:serviceaccount:ci:build-runner-sa", "ci/build-runner-sa", namespace="ci",
    )

    trust = evaluate_federated_trust(
        intruder, payments["Arn"], payments["AssumeRolePolicyDocument"], _providers()
    )
    assert trust.status == "POTENTIAL"
    assert trust.overly_broad is True
    assert any("catch-all" in r for r in trust.broadening_reasons)


def test_non_matching_subject_is_blocked():
    import json

    roles = json.loads(ROLES.read_text(encoding="utf-8"))["federated_roles"]
    logging_role = next(r for r in roles if r["Name"] == "eks-logging-irsa")

    other = WorkloadIdentity(
        "k8s::payments/payments-sa", "kubernetes",
        "system:serviceaccount:payments:payments-sa", "payments/payments-sa",
        namespace="payments",
    )

    trust = evaluate_federated_trust(
        other, logging_role["Arn"], logging_role["AssumeRolePolicyDocument"], _providers()
    )
    assert trust.status == "BLOCKED"


def test_provider_plane_mismatch_returns_none():
    """A GitHub workload must not match an EKS trust policy."""
    import json

    roles = json.loads(ROLES.read_text(encoding="utf-8"))["federated_roles"]
    payments = next(r for r in roles if r["Name"] == "eks-payments-irsa")

    gha = WorkloadIdentity(
        "gha::example-org/x/y.yml", "github_actions",
        "repo:example-org/x:ref:refs/heads/main", "example-org/x",
    )

    assert evaluate_federated_trust(
        gha, payments["Arn"], payments["AssumeRolePolicyDocument"], _providers()
    ) is None


def test_org_wildcard_admits_every_repo():
    import json

    roles = json.loads(ROLES.read_text(encoding="utf-8"))["federated_roles"]
    deploy = next(r for r in roles if r["Name"] == "gha-deploy-role")

    workload = WorkloadIdentity(
        "gha::example-org/web-frontend/pr-preview.yml", "github_actions",
        "repo:example-org/web-frontend:pull_request", "example-org/web-frontend",
    )

    trust = evaluate_federated_trust(
        workload, deploy["Arn"], deploy["AssumeRolePolicyDocument"], _providers()
    )
    assert trust.overly_broad is True


def test_blast_radius_lists_other_admitted_workloads():
    import json

    roles = json.loads(ROLES.read_text(encoding="utf-8"))["federated_roles"]
    payments = next(r for r in roles if r["Name"] == "eks-payments-irsa")

    k8s = K8sRBACSource(K8S)
    workloads = k8s.service_accounts()
    target = next(w for w in workloads if "payments-sa" in w.workload_id)

    trust = evaluate_federated_trust(
        target, payments["Arn"], payments["AssumeRolePolicyDocument"], _providers()
    )
    radius = blast_radius(trust, workloads)

    assert len(radius) == 2
    assert target.workload_id not in radius


def test_k8s_subject_can_reach_serviceaccount_via_pod_create():
    k8s = K8sRBACSource(K8S)
    payments_sa = next(w for w in k8s.service_accounts() if "payments-sa" in w.workload_id)

    routes = k8s.subjects_who_can_use(payments_sa)
    reasons = [reason for _, reason in routes]

    assert routes
    assert any("create pods" in r for r in reasons)


def test_github_subject_claim_reflects_trigger_and_environment():
    gh = GitHubActionsSource(GITHUB)
    workloads = {w.display_name: w for w in gh.workloads()}

    pr = workloads["example-org/web-frontend / pr-preview.yml"]
    assert pr.subject == "repo:example-org/web-frontend:pull_request"

    release = workloads["example-org/release-pipeline / release.yml"]
    assert release.subject == "repo:example-org/release-pipeline:environment:production"


def test_untrusted_trigger_and_unpinned_action_are_flagged():
    gh = GitHubActionsSource(GITHUB)
    pr = next(w for w in gh.workloads() if "pr-preview" in w.workload_id)

    reasons = gh.entry_conditions(pr)
    assert any("pull_request_target" in r for r in reasons)
    assert any("Unpinned" in r for r in reasons)


def test_sha_pinned_action_is_not_flagged():
    gh = GitHubActionsSource(GITHUB)
    release = next(w for w in gh.workloads() if "release.yml" in w.workload_id)

    assert release.metadata["unpinned_actions"] == []
    assert gh.mitigations(release)


def test_audit_log_proves_pod_ran_as_serviceaccount():
    records = load_audit_events(K8S_AUDIT)
    observed = observed_pod_creates(records)

    assert "payments/payments-sa" in observed
    assert observed["payments/payments-sa"]


def test_web_identity_assumption_keyed_by_subject_and_role():
    records = _federation_cloudtrail_records(str(CLOUDTRAIL), "file")
    observed = observed_web_identity_assumptions(records)

    key = "system:serviceaccount:payments:payments-sa|arn:aws:iam::111122223333:role/eks-payments-irsa"
    assert key in observed


def test_observed_role_actions_attributed_to_assumed_role():
    records = _federation_cloudtrail_records(str(CLOUDTRAIL), "file")
    actions = observed_role_actions(records)

    role = "arn:aws:iam::111122223333:role/eks-payments-irsa"
    assert "secretsmanager:GetSecretValue" in actions[role]


def test_end_to_end_observed_path_spans_both_planes():
    result = _agent().analyze()

    observed = [p for p in result["federated_paths"] if p["status"] == "OBSERVED"]
    assert observed

    path = observed[0]
    assert path["identity_planes"] == ["kubernetes", "aws"]
    assert "GetSecretValue" in path["title"]

    node_types = [s["node_type"] for s in path["steps"]]
    assert "oidc_provider" in node_types
    assert "iam_role" in node_types


def test_blocked_trust_yields_zero_risk_refuted_path():
    result = _agent().analyze()

    blocked = [p for p in result["federated_paths"] if p["status"] == "BLOCKED"]
    assert blocked
    assert all(p["risk_score"] == 0 for p in blocked)
    assert all("refuted" in p["title"] for p in blocked)


def test_overly_broad_trusts_are_reported():
    result = _agent().analyze()

    broad = result["overly_broad_trusts"]
    assert broad
    assert all(t["broadening_reasons"] for t in broad)


def test_federated_edges_cite_evidence_when_observed():
    graph = EvidenceGraphEngine()
    WorkloadFederationAgent(
        graph,
        ROLES,
        k8s_snapshot=K8S,
        k8s_audit_log=K8S_AUDIT,
        github_snapshot=GITHUB,
        cloudtrail_records=_federation_cloudtrail_records(str(CLOUDTRAIL), "file"),
    ).analyze()

    observed_edges = [e for e in graph.edges if e.observed]
    assert observed_edges
    assert all(e.evidence_refs for e in observed_edges)


def test_summary_reports_both_planes():
    result = _agent().analyze()
    summary = result["federated_summary"]

    assert set(summary["planes"]) == {"aws", "kubernetes", "github_actions"}
    assert summary["cross_plane_paths"] == summary["total_paths"]


TESTS = [
    test_trust_conditions_parse_operator_and_claim,
    test_exact_match_condition_is_not_flagged_broad,
    test_wildcard_subject_admits_unintended_workloads,
    test_non_matching_subject_is_blocked,
    test_provider_plane_mismatch_returns_none,
    test_org_wildcard_admits_every_repo,
    test_blast_radius_lists_other_admitted_workloads,
    test_k8s_subject_can_reach_serviceaccount_via_pod_create,
    test_github_subject_claim_reflects_trigger_and_environment,
    test_untrusted_trigger_and_unpinned_action_are_flagged,
    test_sha_pinned_action_is_not_flagged,
    test_audit_log_proves_pod_ran_as_serviceaccount,
    test_web_identity_assumption_keyed_by_subject_and_role,
    test_observed_role_actions_attributed_to_assumed_role,
    test_end_to_end_observed_path_spans_both_planes,
    test_blocked_trust_yields_zero_risk_refuted_path,
    test_overly_broad_trusts_are_reported,
    test_federated_edges_cite_evidence_when_observed,
    test_summary_reports_both_planes,
]


if __name__ == "__main__":
    print("[*] Running workload federation tests...")
    for test in TESTS:
        test()
        print(f"    PASS  {test.__name__}")
    print(f"[+] All {len(TESTS)} workload federation tests PASSED.")
