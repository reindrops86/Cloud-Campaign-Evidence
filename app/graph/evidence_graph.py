from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.models import EvidenceEdge, IndicatorNode, utc_now_iso

HALF_LIFE_DAYS = 90.0


def defang_indicator(value: str) -> str:
    """Safely defang IPs, URLs, and domains for safe report rendering."""
    val = value.strip()
    val = val.replace("http://", "hXXp://").replace("https://", "hXXps://")
    val = re.sub(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", r"\1[\.]\2[\.]\3[\.]\4", val)
    return val


def parse_iso(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def calculate_half_life_decay(initial_confidence: int, last_seen_iso: str, as_of: Optional[datetime] = None) -> int:
    """Calculate decayed confidence as an indicator or cluster goes quiet."""
    as_of = as_of or datetime.now(timezone.utc)
    last_seen_dt = parse_iso(last_seen_iso)
    days_quiet = max(0.0, (as_of - last_seen_dt).total_seconds() / 86400.0)
    decay_factor = 0.5 ** (days_quiet / HALF_LIFE_DAYS)
    return max(10, int(initial_confidence * decay_factor))


class EvidenceGraphEngine:
    """Deterministic evidence graph builder, graph timeline maintainer, and linkage scorer."""

    def __init__(self) -> None:
        self.nodes: Dict[str, IndicatorNode] = {}
        self.edges: List[EvidenceEdge] = []

    def add_node(
        self,
        node_id: str,
        value: str,
        indicator_type: str,
        first_seen: str,
        last_seen: str,
        reputation_score: int = 50,
        source: str = "collector",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> IndicatorNode:
        if node_id in self.nodes:
            existing = self.nodes[node_id]
            existing.first_seen = min(existing.first_seen, first_seen)
            existing.last_seen = max(existing.last_seen, last_seen)
            existing.reputation_score = max(existing.reputation_score, reputation_score)
            if source not in existing.sources:
                existing.sources.append(source)
            if metadata:
                existing.metadata.update(metadata)
            return existing
        else:
            node = IndicatorNode(
                id=node_id,
                value=value,
                indicator_type=indicator_type,
                first_seen=first_seen,
                last_seen=last_seen,
                reputation_score=reputation_score,
                sources=[source],
                metadata=metadata or {},
            )
            self.nodes[node_id] = node
            return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation_type: str,
        confidence: int,
        evidence_basis: str,
        first_observed: str,
        last_observed: str,
    ) -> EvidenceEdge:
        # Avoid exact duplicate edges
        for edge in self.edges:
            if (
                edge.source_id == source_id
                and edge.target_id == target_id
                and edge.relation_type == relation_type
            ):
                edge.confidence = max(edge.confidence, confidence)
                edge.last_observed = max(edge.last_observed, last_observed)
                return edge

        edge = EvidenceEdge(
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            confidence=confidence,
            evidence_basis=evidence_basis,
            first_observed=first_observed,
            last_observed=last_observed,
        )
        self.edges.append(edge)
        return edge

    def get_timeline(self) -> List[Dict[str, Any]]:
        """Extract a chronological timeline of all observed nodes and evidence edges."""
        events: List[Dict[str, Any]] = []

        for node in self.nodes.values():
            events.append(
                {
                    "timestamp": node.first_seen,
                    "event_type": "indicator_first_seen",
                    "id": node.id,
                    "summary": f"First observed {node.indicator_type} ({defang_indicator(node.value)})",
                    "sources": node.sources,
                }
            )

        for edge in self.edges:
            src_val = self.nodes[edge.source_id].value if edge.source_id in self.nodes else edge.source_id
            tgt_val = self.nodes[edge.target_id].value if edge.target_id in self.nodes else edge.target_id
            events.append(
                {
                    "timestamp": edge.first_observed,
                    "event_type": "relationship_observed",
                    "id": f"{edge.source_id}->{edge.target_id}",
                    "summary": f"Relationship [{edge.relation_type}]: {defang_indicator(src_val)} -> {defang_indicator(tgt_val)} ({edge.evidence_basis})",
                    "confidence": edge.confidence,
                }
            )

        events.sort(key=lambda x: x["timestamp"])
        return events

    def export_graph_dict(self) -> Dict[str, Any]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [
                {
                    "id": n.id,
                    "value": n.value,
                    "defanged_value": defang_indicator(n.value),
                    "indicator_type": n.indicator_type,
                    "first_seen": n.first_seen,
                    "last_seen": n.last_seen,
                    "reputation_score": n.reputation_score,
                    "decayed_reputation": calculate_half_life_decay(n.reputation_score, n.last_seen),
                    "sources": n.sources,
                    "metadata": n.metadata,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source_id": e.source_id,
                    "target_id": e.target_id,
                    "relation_type": e.relation_type,
                    "confidence": e.confidence,
                    "evidence_basis": e.evidence_basis,
                    "first_observed": e.first_observed,
                    "last_observed": e.last_observed,
                }
                for e in self.edges
            ],
            "timeline": self.get_timeline(),
        }
