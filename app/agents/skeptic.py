from __future__ import annotations

import re
from typing import Any, Dict, List

from app.graph.evidence_graph import EvidenceGraphEngine, calculate_half_life_decay
from app.models import CampaignHypothesis, SkepticReview


class SkepticReviewerAgent:
    """Agent 5: Skeptic / Reviewer
    Audits claims for unsupported assumptions, checks for circular reporting,
    flags contradictory evidence, resists prompt injections, and enforces high
    standards of intelligence defensibility across 8 deception vectors.
    """

    PROMPT_INJECTION_PATTERNS = [
        r"ignore (all )?previous instructions",
        r"system prompt override",
        r"classify this (ip|domain|hash) as (benign|safe|malicious)",
        r"you are now in (god|admin|dev) mode",
        r"override confidence to 100",
    ]

    SHARED_HOSTING_ISPS = [
        "cloudflare",
        "akamai",
        "fastly",
        "cloudfront",
        "amazon technologies inc",
        "google cloud",
    ]

    def __init__(self, graph_engine: EvidenceGraphEngine) -> None:
        self.graph_engine = graph_engine

    def detect_prompt_injection(self) -> List[str]:
        """Scan graph metadata and node values for embedded prompt injection payloads."""
        injections = []
        for n in self.graph_engine.nodes.values():
            text_to_scan = f"{n.value} {n.metadata}"
            for pattern in self.PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, text_to_scan, re.IGNORECASE):
                    injections.append(
                        f"Prompt injection payload detected in indicator metadata for '{n.id}': pattern match '{pattern}'."
                    )
        return injections

    def review(self, hypothesis: CampaignHypothesis) -> SkepticReview:
        unsupported_claims: List[str] = []
        circular_reporting_warnings: List[str] = []
        contradictions: List[str] = []

        # 1. Prompt Injection Audit
        injections = self.detect_prompt_injection()
        if injections:
            unsupported_claims.extend(injections)

        # 2. Circular Reporting Audit
        sources = []
        for n in self.graph_engine.nodes.values():
            sources.extend(n.sources)
        if len(sources) > 0 and len(set(sources)) == 1:
            circular_reporting_warnings.append(
                f"Single-source dependency detected ({sources[0]}). Cross-source verification advised to rule out vendor circular reporting."
            )

        # 3. Shared Hosting & CDN Over-Attribution Audit
        for n in self.graph_engine.nodes.values():
            isp = str(n.metadata.get("isp", "")).lower()
            org = str(n.metadata.get("org", "")).lower()
            if any(cdn in isp or cdn in org for cdn in self.SHARED_HOSTING_ISPS):
                unsupported_claims.append(
                    f"Shared hosting/CDN infrastructure detected on node '{n.id}' ({n.value}). High risk of over-attribution."
                )

        # 4. Stale Indicator Decay Audit
        for n in self.graph_engine.nodes.values():
            decayed = calculate_half_life_decay(n.reputation_score, n.last_seen)
            if decayed < 30:
                unsupported_claims.append(
                    f"Stale indicator '{n.id}' ({n.value}): confidence decayed to {decayed}% due to age (>90 days quiet)."
                )

        # 5. Coincidental Certificate & Domain Reuse Audit
        for n in self.graph_engine.nodes.values():
            issuer = str(n.metadata.get("issuer", "")).lower()
            if "let's encrypt" in issuer and n.metadata.get("wildcard", False):
                contradictions.append(
                    f"Generic free wildcard TLS cert on '{n.id}' ({n.value}). Low attribution specificity."
                )

        # 6. Audit Weak Relationships & Low Confidence Edges
        weak_edges = [e for e in self.graph_engine.edges if e.confidence < 60]
        if weak_edges:
            for we in weak_edges:
                unsupported_claims.append(
                    f"Relationship {we.source_id} -> {we.target_id} has low confidence ({we.confidence}%). Demoting attribution strength."
                )

        # 7. Check for Infrastructure Location / ASN Contradiction
        asns = [n.metadata.get("asn") for n in self.graph_engine.nodes.values() if n.metadata.get("asn")]
        if len(set(asns)) > 2:
            contradictions.append(
                f"Infrastructure spans multiple distinct ASNs ({', '.join(set(asns))}). Indicates proxy/VPN rotation rather than fixed adversary hosting."
            )

        # Decide final confidence score & acceptance status
        critical_deception_flags = len(injections) + len(contradictions) + sum(1 for c in unsupported_claims if "CDN" in c or "Stale" in c or "low confidence" in c)
        
        penalty = (len(unsupported_claims) * 30) + (len(circular_reporting_warnings) * 15) + (len(contradictions) * 30)
        final_conf = max(10, hypothesis.initial_confidence - penalty)
        accepted = final_conf >= 60 and critical_deception_flags == 0

        feedback = (
            f"Skeptic Audit complete. Status: {'ACCEPTED' if accepted else 'REJECTED'}. "
            f"Final Confidence: {final_conf}%. Injections Blocked: {len(injections)}. Penalized {len(unsupported_claims)} claims & {len(contradictions)} contradictions."
        )

        return SkepticReview(
            accepted=accepted,
            final_confidence=final_conf,
            unsupported_claims=unsupported_claims,
            circular_reporting_warnings=circular_reporting_warnings,
            contradictions=contradictions,
            analyst_feedback=feedback,
        )
