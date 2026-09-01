from __future__ import annotations

from typing import Any, Dict, List

from app.graph.evidence_graph import EvidenceGraphEngine
from app.models import CampaignHypothesis, CloudTTPMapping


class HypothesisAnalystAgent:
    """Agent 4: Hypothesis Analyst
    Generates primary campaign hypotheses and explicitly lists alternative hypotheses
    following Analysis of Competing Hypotheses (ACH) threat intelligence standards.
    """

    def __init__(self, graph_engine: EvidenceGraphEngine) -> None:
        self.graph_engine = graph_engine

    def generate_hypothesis(self, ttp_mappings: List[CloudTTPMapping]) -> CampaignHypothesis:
        evidence_list = [f"{e.source_id} -> {e.target_id} ({e.relation_type}: {e.evidence_basis})" for e in self.graph_engine.edges]
        node_vals = [n.value for n in self.graph_engine.nodes.values()]

        primary_claim = (
            f"Adversary activity cluster leveraging compromised cloud assets ({', '.join(node_vals[:2])}) "
            f"to execute automated recon, credential access, and potential storage exfiltration across targeted cloud tenants."
        )

        alternative_hypotheses = [
            "Legitimate developer key leakage without malicious exploitation (false positive alert trigger).",
            "Third-party CI/CD automation tool misconfiguration exposing public read permissions.",
            "Independent opportunistic scanner activity reusing public cloud infrastructure rather than a single coordinated campaign.",
        ]

        return CampaignHypothesis(
            hypothesis_id="HYP-2026-CLOUD-01",
            primary_claim=primary_claim,
            supporting_evidence=evidence_list,
            alternative_hypotheses=alternative_hypotheses,
            assumed_threat_actor="UNC-CLOUD-HARVESTER",
            initial_confidence=85,
        )
