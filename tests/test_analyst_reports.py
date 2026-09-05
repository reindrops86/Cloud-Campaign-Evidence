"""Analyst report generation: claim typing, proportional response, and rendering."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.main import run_pipeline
from app.reports.analyst_reports import (
    REPORT_BUILDERS,
    RESPONSE_LADDER,
    classify_claims,
    evidence_gaps,
    executive_brief,
    investigation_report,
    recommend_actions,
    response_memo,
    threat_intel_report,
    write_analyst_reports,
)

DATA = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(scope="module")
def telemetry_result():
    """A run backed by CloudTrail, so observed and inferred findings both exist."""
    return run_pipeline(
        "AKIACOMPROMISEDKEY01",
        "iam_access_key",
        source_mode="file",
        cloudtrail_file=str(DATA / "cloudtrail_samples" / "compromised_key.json"),
        iam_snapshot=str(DATA / "iam_snapshots" / "account_111122223333.json"),
    )


@pytest.fixture(scope="module")
def synthetic_result():
    """A run with no telemetry, so nothing may be reported as observed."""
    return run_pipeline("AKIAIOSFODNN7EXAMPLE", "iam_access_key")


def test_claims_are_split_into_three_kinds(telemetry_result) -> None:
    claims = classify_claims(telemetry_result)
    assert set(claims) == {"observation", "inference", "attribution"}
    assert claims["observation"]
    assert claims["inference"]


def test_observations_are_backed_by_telemetry_records(telemetry_result) -> None:
    for claim in classify_claims(telemetry_result)["observation"]:
        assert claim.confidence == 1.0
        assert claim.provenance, f"observation without provenance: {claim.statement}"


def test_inferences_carry_confidence_below_certainty(telemetry_result) -> None:
    for claim in classify_claims(telemetry_result)["inference"]:
        assert 0.0 <= claim.confidence < 1.0
        assert claim.basis


def test_attribution_is_refused(telemetry_result) -> None:
    attribution = classify_claims(telemetry_result)["attribution"]
    assert len(attribution) == 1
    assert attribution[0].confidence == 0.0
    assert "No identity attribution is made" in attribution[0].statement


def test_reachable_paths_are_never_reported_as_observed(telemetry_result) -> None:
    observed = " ".join(c.statement for c in classify_claims(telemetry_result)["observation"])
    inferred = " ".join(c.statement for c in classify_claims(telemetry_result)["inference"])
    assert "was not observed being used" not in observed
    assert "was not observed being used" in inferred


def test_run_without_telemetry_produces_no_observations(synthetic_result) -> None:
    claims = classify_claims(synthetic_result)
    assert claims["observation"] == []
    assert claims["inference"]
    gaps = evidence_gaps(synthetic_result)
    assert any("No CloudTrail telemetry" in gap for gap in gaps)


def test_response_tier_escalates_only_on_observed_activity(telemetry_result, synthetic_result) -> None:
    observed_tier = max(a["tier"] for a in recommend_actions(telemetry_result))
    inferred_tier = max(a["tier"] for a in recommend_actions(synthetic_result))
    assert observed_tier > inferred_tier
    assert inferred_tier <= 1, "reachability alone must not justify credential action"


def test_irreversible_actions_require_human_approval(telemetry_result) -> None:
    for action in recommend_actions(telemetry_result):
        assert action["scope"] is not None
        assert action["rationale"]
        assert action["proportionality"]
        if action["tier"] >= 3:
            assert action["requires_human_approval"] is True


def test_response_ladder_is_ordered_by_blast_radius() -> None:
    tiers = [entry["tier"] for entry in RESPONSE_LADDER]
    assert tiers == sorted(tiers)
    assert RESPONSE_LADDER[0]["reversible"] is True
    assert RESPONSE_LADDER[-1]["reversible"] is False


def test_evidence_gaps_are_always_stated(telemetry_result) -> None:
    gaps = evidence_gaps(telemetry_result)
    assert gaps
    assert any("data-event" in gap or "ownership is unconfirmed" in gap for gap in gaps)


def test_investigation_report_has_required_sections(telemetry_result) -> None:
    report = investigation_report(telemetry_result)
    for heading in (
        "## 2. Observations",
        "## 3. Inferences",
        "## 4. Attribution position",
        "## 6. Competing explanations",
        "## 7. Skeptic audit",
        "## 8. Evidence gaps",
        "## 9. Recommended response",
        "## 10. Limitations",
    ):
        assert heading in report


def test_network_indicators_are_defanged_in_narrative(telemetry_result) -> None:
    """Free-text evidence descriptions leak raw IPs unless defanged explicitly."""
    report = investigation_report(telemetry_result)
    assert "198.51.100.45" not in report
    assert "198[\\.]51[\\.]100[\\.]45" in report


def test_detection_rule_content_is_left_intact(telemetry_result) -> None:
    """Defanging a rule body would stop it matching; only prose is defanged."""
    report = threat_intel_report(telemetry_result)
    rule_bodies = "".join(r["content"] for r in telemetry_result["detection_rules"])
    assert rule_bodies.strip() in report or all(
        line.strip() in report for line in rule_bodies.splitlines() if line.strip()
    )


def test_threat_intel_report_includes_detection_logic(telemetry_result) -> None:
    report = threat_intel_report(telemetry_result)
    assert "## Detection logic" in report
    assert "```yaml" in report
    assert "## Collection gaps" in report


def test_executive_brief_states_the_cost_of_being_wrong(telemetry_result) -> None:
    brief = executive_brief(telemetry_result)
    assert "## What it costs us to be wrong" in brief
    assert "linkage assessment" in brief
    assert len(brief.splitlines()) < 60, "an executive one-pager must stay one page"


def test_response_memo_documents_rollback(telemetry_result) -> None:
    memo = response_memo(telemetry_result)
    assert "## Rollback" in memo
    assert "## Before acting" in memo


def test_all_reports_are_written(tmp_path, telemetry_result) -> None:
    written = write_analyst_reports(telemetry_result, tmp_path)
    assert len(written) == len(REPORT_BUILDERS)
    for path in written:
        assert path.exists()
        assert path.stat().st_size > 0
        assert path.name.startswith(telemetry_result["investigation_id"])
