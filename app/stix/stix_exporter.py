from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from app.graph.evidence_graph import EvidenceGraphEngine
from app.models import CampaignHypothesis, CloudTTPMapping, utc_now_iso


class STIXExporter:
    """Exports EvidenceGraphEngine state and analytical judgments into a valid STIX 2.1 JSON bundle."""

    def __init__(self, graph_engine: EvidenceGraphEngine) -> None:
        self.graph_engine = graph_engine

    def stix_pattern_for_node(self, indicator_type: str, value: str) -> str:
        if indicator_type == "ip":
            return f"[ipv4-addr:value = '{value}']"
        elif indicator_type in ("domain", "url"):
            return f"[domain-name:value = '{value}']"
        elif indicator_type == "hash":
            return f"[file:hashes.'SHA-256' = '{value}']"
        elif indicator_type == "iam_access_key":
            return f"[user-account:user_id = '{value}']"
        else:
            return f"[artifact:payload_bin = '{value}']"

    def export_bundle(
        self,
        investigation_id: str,
        hypothesis: CampaignHypothesis,
        ttp_mappings: List[CloudTTPMapping],
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        objects: List[Dict[str, Any]] = []

        # 1. Threat Actor SDO
        actor_id = f"threat-actor--{hash(hypothesis.assumed_threat_actor or 'UNC-CLOUD') & 0xFFFFFFFF:08x}-1111-4000-8000-000000000000"
        objects.append(
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": now,
                "modified": now,
                "name": hypothesis.assumed_threat_actor or "UNC-CLOUD-HARVESTER",
                "description": hypothesis.primary_claim,
                "threat_actor_types": ["crime-syndicate", "cyberespionage"],
                "confidence": hypothesis.initial_confidence,
            }
        )

        # 2. Attack Patterns SDOs
        attack_pattern_ids: Dict[str, str] = {}
        for ttp in ttp_mappings:
            ap_id = f"attack-pattern--{hash(ttp.technique_id) & 0xFFFFFFFF:08x}-2222-4000-8000-000000000000"
            attack_pattern_ids[ttp.technique_id] = ap_id
            objects.append(
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "created": now,
                    "modified": now,
                    "name": ttp.technique_name,
                    "description": f"MITRE ATT&CK Cloud Technique {ttp.technique_id} ({ttp.tactic})",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": ttp.technique_id,
                            "url": f"https://attack.mitre.org/techniques/{ttp.technique_id.replace('.', '/')}/",
                        }
                    ],
                }
            )

        # 3. Indicator SDOs & Observed-Data SROs
        stix_indicator_ids: Dict[str, str] = {}
        for node in self.graph_engine.nodes.values():
            stix_ind_id = f"indicator--{hash(node.id) & 0xFFFFFFFF:08x}-3333-4000-8000-000000000000"
            stix_indicator_ids[node.id] = stix_ind_id
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": stix_ind_id,
                    "created": node.first_seen,
                    "modified": node.last_seen,
                    "name": f"{node.indicator_type.upper()}: {node.value}",
                    "indicator_types": ["malicious-activity", "anomalous-activity"],
                    "pattern": self.stix_pattern_for_node(node.indicator_type, node.value),
                    "pattern_type": "stix",
                    "valid_from": node.first_seen,
                    "confidence": node.reputation_score,
                }
            )

            # Relationship: Threat Actor uses Indicator
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{hash(node.id + 'uses') & 0xFFFFFFFF:08x}-4444-4000-8000-000000000000",
                    "created": now,
                    "modified": now,
                    "relationship_type": "uses",
                    "source_ref": actor_id,
                    "target_ref": stix_ind_id,
                }
            )

        # 4. Graph Relationship SROs
        for edge in self.graph_engine.edges:
            if edge.source_id in stix_indicator_ids and edge.target_id in stix_indicator_ids:
                objects.append(
                    {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": f"relationship--{hash(edge.source_id + edge.target_id) & 0xFFFFFFFF:08x}-5555-4000-8000-000000000000",
                        "created": edge.first_observed,
                        "modified": edge.last_observed,
                        "relationship_type": edge.relation_type,
                        "source_ref": stix_indicator_ids[edge.source_id],
                        "target_ref": stix_indicator_ids[edge.target_id],
                        "description": edge.evidence_basis,
                        "confidence": edge.confidence,
                    }
                )

        # 5. Relationship: Threat Actor uses Attack Patterns
        for ap_id in attack_pattern_ids.values():
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{hash(ap_id + 'uses_ap') & 0xFFFFFFFF:08x}-6666-4000-8000-000000000000",
                    "created": now,
                    "modified": now,
                    "relationship_type": "uses",
                    "source_ref": actor_id,
                    "target_ref": ap_id,
                }
            )

        bundle_id = f"bundle--{hash(investigation_id) & 0xFFFFFFFF:08x}-7777-4000-8000-000000000000"
        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": objects,
        }
