from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.agents.aws_telemetry import AWSTelemetryAgent
from app.collectors.aws_cloudtrail import FileCloudTrailSource
from app.collectors.aws_identity import (
    FileIdentitySource,
    all_high_risk_actions,
    evaluate_from_statements,
    risk_category_for,
)
from app.graph.evidence_graph import EvidenceGraphEngine
from app.main import run_pipeline

ROOT = Path(__file__).resolve().parent.parent
COMPROMISED = ROOT / "data" / "cloudtrail_samples" / "compromised_key.json"
BENIGN = ROOT / "data" / "cloudtrail_samples" / "benign_automation.json"
IAM_SNAPSHOT = ROOT / "data" / "iam_snapshots" / "account_111122223333.json"

WINDOW_START = datetime(2026, 8, 1, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 9, 1, tzinfo=timezone.utc)


def test_cloudtrail_file_source_filters_by_access_key():
    source = FileCloudTrailSource(COMPROMISED)
    records = source.events_for_access_key("AKIACOMPROMISEDKEY01", WINDOW_START, WINDOW_END)

    assert len(records) == 6
    assert all(r.access_key_id == "AKIACOMPROMISEDKEY01" for r in records)
    assert all(r.evidence_id.startswith("cloudtrail-") for r in records)
    assert all(r.event_category == "Management" for r in records)

    empty = source.events_for_access_key("AKIADOESNOTEXIST", WINDOW_START, WINDOW_END)
    assert empty == []


def test_cloudtrail_time_window_is_enforced():
    source = FileCloudTrailSource(COMPROMISED)
    records = source.events_for_access_key(
        "AKIACOMPROMISEDKEY01",
        datetime(2020, 1, 1, tzinfo=timezone.utc),
        datetime(2020, 2, 1, tzinfo=timezone.utc),
    )
    assert records == []


def test_identity_source_resolves_principal_and_roles():
    identity = FileIdentitySource(IAM_SNAPSHOT)
    principal = identity.principal_for_access_key("AKIACOMPROMISEDKEY01")

    assert principal is not None
    assert principal.name == "deploy-svc"
    assert "deployers" in principal.group_names

    roles = identity.assumable_roles(principal)
    assert [r.name for r in roles] == ["prod-data-reader"]


def test_untrusted_principal_cannot_assume_role():
    identity = FileIdentitySource(IAM_SNAPSHOT)
    principal = identity.principal_for_access_key("AKIABENIGNEXAMPLE001")

    assert principal is not None
    assert identity.assumable_roles(principal) == []


def test_explicit_deny_beats_allow():
    identity = FileIdentitySource(IAM_SNAPSHOT)
    principal = identity.principal_for_access_key("AKIACOMPROMISEDKEY01")
    statements = identity.statements_for_principal(principal)

    evaluations = evaluate_from_statements(principal, statements, ["cloudtrail:StopLogging"])
    assert [e.status for e in evaluations] == ["BLOCKED"]


def test_unevaluated_condition_yields_unresolved():
    identity = FileIdentitySource(IAM_SNAPSHOT)
    principal = identity.principal_for_access_key("AKIACOMPROMISEDKEY01")
    statements = identity.statements_for_principal(principal)

    evaluations = evaluate_from_statements(principal, statements, ["ssm:GetParameter"])
    assert evaluations[0].status == "UNRESOLVED"
    assert "Bool" in evaluations[0].unresolved_conditions


def test_graph_evaluation_never_claims_confirmed():
    """Only the IAM simulator may return CONFIRMED_ALLOWED."""
    identity = FileIdentitySource(IAM_SNAPSHOT)
    principal = identity.principal_for_access_key("AKIACOMPROMISEDKEY01")
    statements = identity.statements_for_principal(principal)

    evaluations = evaluate_from_statements(principal, statements, all_high_risk_actions())
    assert all(e.status != "CONFIRMED_ALLOWED" for e in evaluations)


def test_every_observed_edge_cites_evidence():
    graph = EvidenceGraphEngine()
    agent = AWSTelemetryAgent(
        graph, FileCloudTrailSource(COMPROMISED), FileIdentitySource(IAM_SNAPSHOT)
    )
    agent.investigate("AKIACOMPROMISEDKEY01", WINDOW_START, WINDOW_END)

    observed_edges = [e for e in graph.edges if e.observed]
    assert observed_edges
    assert all(e.evidence_refs for e in observed_edges)

    known_ids = {r.evidence_id for r in agent.records}
    for edge in observed_edges:
        assert set(edge.evidence_refs).issubset(known_ids)


def test_compromised_key_produces_observed_attack_paths():
    graph = EvidenceGraphEngine()
    agent = AWSTelemetryAgent(
        graph, FileCloudTrailSource(COMPROMISED), FileIdentitySource(IAM_SNAPSHOT)
    )
    result = agent.investigate("AKIACOMPROMISEDKEY01", WINDOW_START, WINDOW_END)

    summary = result["attack_path_summary"]
    assert summary["observed"] >= 3
    assert summary["blocked"] >= 1
    assert summary["highest_risk_score"] >= 90

    statuses = {p["title"]: p["status"] for p in result["attack_paths"]}
    assume = next(k for k in statuses if "sts:AssumeRole" in k)
    assert statuses[assume] == "OBSERVED"


def test_observed_activity_does_not_override_explicit_deny():
    graph = EvidenceGraphEngine()
    agent = AWSTelemetryAgent(
        graph, FileCloudTrailSource(COMPROMISED), FileIdentitySource(IAM_SNAPSHOT)
    )
    result = agent.investigate("AKIACOMPROMISEDKEY01", WINDOW_START, WINDOW_END)

    stop_logging = next(
        p for p in result["attack_paths"] if "cloudtrail:StopLogging" in p["title"]
    )
    assert stop_logging["status"] == "BLOCKED"
    assert stop_logging["contradictions"], "deny + observed event must be flagged"


def test_role_pivot_step_only_on_role_granted_paths():
    graph = EvidenceGraphEngine()
    agent = AWSTelemetryAgent(
        graph, FileCloudTrailSource(COMPROMISED), FileIdentitySource(IAM_SNAPSHOT)
    )
    result = agent.investigate("AKIACOMPROMISEDKEY01", WINDOW_START, WINDOW_END)

    secret_path = next(
        p for p in result["attack_paths"] if "secretsmanager:GetSecretValue" in p["title"]
    )
    assert any(s["node_type"] == "iam_role" for s in secret_path["steps"])

    key_path = next(p for p in result["attack_paths"] if "iam:CreateAccessKey" in p["title"])
    assert not any(s["node_type"] == "iam_role" for s in key_path["steps"])


def test_benign_key_produces_no_observed_high_risk_paths():
    graph = EvidenceGraphEngine()
    agent = AWSTelemetryAgent(
        graph, FileCloudTrailSource(BENIGN), FileIdentitySource(IAM_SNAPSHOT)
    )
    result = agent.investigate("AKIABENIGNEXAMPLE001", WINDOW_START, WINDOW_END)

    summary = result["attack_path_summary"]
    assert summary["observed"] == 0
    assert summary["highest_risk_score"] < 70
    assert result["assumable_roles"] == []


def test_data_events_are_not_inferred_from_management_events():
    """Management-only telemetry must never be counted as data-event proof."""
    graph = EvidenceGraphEngine()
    agent = AWSTelemetryAgent(
        graph, FileCloudTrailSource(COMPROMISED), FileIdentitySource(IAM_SNAPSHOT)
    )
    result = agent.investigate("AKIACOMPROMISEDKEY01", WINDOW_START, WINDOW_END)

    assert result["data_events"] == 0
    assert result["management_events"] == result["event_count"]


def test_risk_category_lookup():
    assert risk_category_for("iam:CreateAccessKey") == "credential_creation"
    assert risk_category_for("sts:AssumeRole") == "privilege_escalation"
    assert risk_category_for("cloudtrail:StopLogging") == "defense_impairment"
    assert risk_category_for("ec2:DescribeInstances") == "other"


def test_pipeline_integrates_aws_telemetry():
    result = run_pipeline(
        "AKIACOMPROMISEDKEY01",
        "iam_access_key",
        source_mode="file",
        cloudtrail_file=str(COMPROMISED),
        iam_snapshot=str(IAM_SNAPSHOT),
        start_time=WINDOW_START,
        end_time=WINDOW_END,
    )

    assert "aws_telemetry" in result
    assert result["aws_telemetry"]["event_count"] == 6
    assert result["stix_bundle"]["type"] == "bundle"


TESTS = [
    test_cloudtrail_file_source_filters_by_access_key,
    test_cloudtrail_time_window_is_enforced,
    test_identity_source_resolves_principal_and_roles,
    test_untrusted_principal_cannot_assume_role,
    test_explicit_deny_beats_allow,
    test_unevaluated_condition_yields_unresolved,
    test_graph_evaluation_never_claims_confirmed,
    test_every_observed_edge_cites_evidence,
    test_compromised_key_produces_observed_attack_paths,
    test_observed_activity_does_not_override_explicit_deny,
    test_role_pivot_step_only_on_role_granted_paths,
    test_benign_key_produces_no_observed_high_risk_paths,
    test_data_events_are_not_inferred_from_management_events,
    test_risk_category_lookup,
    test_pipeline_integrates_aws_telemetry,
]


if __name__ == "__main__":
    print("[*] Running AWS telemetry & attack path tests...")
    for test in TESTS:
        test()
        print(f"    PASS  {test.__name__}")
    print(f"[+] All {len(TESTS)} AWS telemetry tests PASSED.")
