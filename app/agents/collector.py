from __future__ import annotations

import re
from typing import Any, Dict, List

from app.graph.evidence_graph import EvidenceGraphEngine, defang_indicator
from app.models import utc_now_iso


class CollectorAgent:
    """Agent 1: Collector
    Ingests seed indicators, normalizes IOC types, deduplicates entities,
    and initializes evidence nodes in the EvidenceGraphEngine.
    """

    def __init__(self, graph_engine: EvidenceGraphEngine) -> None:
        self.graph_engine = graph_engine

    def detect_type(self, seed: str) -> str:
        s = seed.strip()
        if s.startswith("AKIA") or s.startswith("ASIA"):
            return "iam_access_key"
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s):
            return "ip"
        elif re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", s):
            return "hash"
        elif s.startswith("http://") or s.startswith("https://"):
            return "url"
        elif "github.com/" in s:
            return "github_repo"
        elif ":" in s or "docker.io/" in s or "quay.io/" in s:
            return "container_image"
        else:
            return "domain"

    def collect(self, seed_indicator: str, seed_type: str | None = None) -> Dict[str, Any]:
        stype = seed_type or self.detect_type(seed_indicator)
        now = utc_now_iso()

        node_id = f"seed-{stype}-{hash(seed_indicator) % 10000:04d}"
        seed_node = self.graph_engine.add_node(
            node_id=node_id,
            value=seed_indicator,
            indicator_type=stype,
            first_seen=now,
            last_seen=now,
            reputation_score=75,
            source="seed_collector",
            metadata={"seed_role": "primary_investigation_target"},
        )

        return {
            "status": "collected",
            "seed_id": seed_node.id,
            "seed_indicator": seed_indicator,
            "defanged_indicator": defang_indicator(seed_indicator),
            "seed_type": stype,
            "collected_at": now,
        }
