from __future__ import annotations

from typing import Any, Dict, List

from app.graph.evidence_graph import EvidenceGraphEngine
from app.models import CampaignHypothesis, SkepticReview


class SkepticReviewerAgent:
    """Agent 5: Skeptic / Reviewer
    Audits claims for unsupported assumptions, checks for circular reporting,
    flags contradictory evidence, and enforces high standards of intelligence defensibility.
    """

    def __init__(self, graph_engine: EvidenceGraphEngine) -> None:
        self.graph_engine = graph_engine

    def review(self, hypothesis: CampaignHypothesis) -> SkepticReview:
        unsupported_claims: List[str] = []
        circular_reporting_warnings: List[str] = []
        contradictions: List[str] = []

        # Check for circular reporting in sources
        sources = []
        for n in self.graph_engine.nodes.values():
            sources.extend(n.sources)
        if len(sources) > 0 and len(set(sources)) == 1:
            circular_reporting_warnings.append(
                f"Single-source dependency detected ({sources[0]}). Cross-source verification advised to rule out vendor circular reporting."
            )

        # Audit node confidence & edge strength
        weak_edges = [e for e in self.graph_engine.edges if e.confidence < 60]
        if weak_edges:
            for we in weak_edges:
                unsupported_claims.append(
                    f"Relationship {we.source_id} -> {we.target_id} has low confidence ({we.confidence}%). Demoting attribution strength."
                )

        # Check for infrastructure location contradiction
        asns = [n.metadata.get("asn") for n in self.graph_engine.nodes.values() if n.metadata.get("asn")]
        if len(set(asns)) > 2:
            contradictions.append(
                f"Infrastructure spans multiple distinct ASNs ({', '.join(set(asns))}). Indicates proxy/VPN rotation rather than fixed adversary hosting."
            )

        # Decide final confidence score
        penalty = (len(unsupported_claims) * 10) + (len(circular_reporting_warnings) * 10) + (len(contradictions) * 5)
        final_conf = max(30, hypothesis.initial_confidence - penalty)
        accepted = final_conf >= 60

        feedback = (
            f"Review complete. Status: {'ACCEPTED' if accepted else 'NEEDS_REVISION'}. "
            f"Final Confidence: {final_conf}%. Audited {len(self.graph_engine.nodes)} nodes and {len(self.graph_engine.edges)} edges."
        )

        return SkepticReview(
            accepted=accepted,
            final_confidence=final_conf,
            unsupported_claims=unsupported_claims,
            circular_reporting_warnings=circular_reporting_warnings,
            contradictions=contradictions,
            analyst_feedback=feedback,
        )
