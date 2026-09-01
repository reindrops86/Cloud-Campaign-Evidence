from __future__ import annotations

import json
from typing import Any, Dict, List

from app.graph.evidence_graph import EvidenceGraphEngine
from app.models import CampaignHypothesis, CloudTTPMapping


class OpenCTIGraphQLConverter:
    """Converts STIX 2.1 bundles & evidence graphs into OpenCTI GraphQL mutations for direct platform intake."""

    def __init__(self, graph_engine: EvidenceGraphEngine) -> None:
        self.graph_engine = graph_engine

    def convert_stix_to_graphql_mutations(
        self, stix_bundle: Dict[str, Any], hypothesis: CampaignHypothesis
    ) -> List[Dict[str, Any]]:
        mutations: List[Dict[str, Any]] = []

        # 1. Threat Actor Mutation
        actor_name = hypothesis.assumed_threat_actor or "UNC-CLOUD-HARVESTER"
        mutations.append(
            {
                "query": """mutation ThreatActorAdd($input: ThreatActorAddInput!) {
  threatActorAdd(input: $input) {
    id
    name
    description
    confidence
  }
}""",
                "variables": {
                    "input": {
                        "name": actor_name,
                        "description": hypothesis.primary_claim,
                        "confidence": hypothesis.initial_confidence,
                    }
                },
            }
        )

        # 2. Indicator Mutations for Nodes
        for node in self.graph_engine.nodes.values():
            mutations.append(
                {
                    "query": """mutation IndicatorAdd($input: IndicatorAddInput!) {
  indicatorAdd(input: $input) {
    id
    name
    pattern_type
    indicator_types
  }
}""",
                    "variables": {
                        "input": {
                            "name": f"{node.indicator_type.upper()}: {node.value}",
                            "pattern": f"[{node.indicator_type}:value = '{node.value}']",
                            "pattern_type": "stix",
                            "indicator_types": ["malicious-activity"],
                            "confidence": node.reputation_score,
                        }
                    },
                }
            )

        return mutations

    def export_mutation_payload_json(
        self, stix_bundle: Dict[str, Any], hypothesis: CampaignHypothesis
    ) -> Dict[str, Any]:
        mutations = self.convert_stix_to_graphql_mutations(stix_bundle, hypothesis)
        return {
            "platform": "OpenCTI",
            "version": "6.x",
            "mutation_count": len(mutations),
            "mutations": mutations,
        }
