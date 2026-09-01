from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# Add parent app directory to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.agents.cloud_ttp import CloudTTPAnalystAgent
from app.agents.collector import CollectorAgent
from app.agents.enrichment import EnrichmentAnalystAgent
from app.agents.hypothesis import HypothesisAnalystAgent
from app.agents.report_builder import ReportBuilderAgent
from app.agents.skeptic import SkepticReviewerAgent
from app.graph.evidence_graph import EvidenceGraphEngine


def run_deception_eval(cases_path: str, output_path: str) -> Dict[str, Any]:
    with open(cases_path, "r", encoding="utf-8") as f:
        deception_cases = json.load(f)

    total_cases = len(deception_cases)
    injections_blocked = 0
    circular_sources_detected = 0
    over_attributions_avoided = 0
    provenance_preserved_count = 0
    observation_inference_separated_count = 0

    case_results: List[Dict[str, Any]] = []

    for case in deception_cases:
        t0 = time.time()
        graph_engine = EvidenceGraphEngine()

        collector = CollectorAgent(graph_engine)
        enricher = EnrichmentAnalystAgent(graph_engine)
        cloud_ttp = CloudTTPAnalystAgent(graph_engine)
        hypothesis_agent = HypothesisAnalystAgent(graph_engine)
        skeptic = SkepticReviewerAgent(graph_engine)

        coll_res = collector.collect(case["seed_indicator"], case["seed_type"])
        enr_res = enricher.enrich(coll_res["seed_id"])

        # Inject mock metadata for deception testing
        mock_meta = case.get("mock_metadata", {})
        if "source" in mock_meta:
            for n in graph_engine.nodes.values():
                n.sources = [mock_meta["source"]]

        seed_node = graph_engine.nodes.get(coll_res["seed_id"])
        if seed_node:
            if "last_seen" in mock_meta:
                seed_node.last_seen = mock_meta["last_seen"]
            if "reputation_score" in mock_meta:
                seed_node.reputation_score = mock_meta["reputation_score"]
            if "isp" in mock_meta:
                seed_node.metadata["isp"] = mock_meta["isp"]
            if "org" in mock_meta:
                seed_node.metadata["org"] = mock_meta["org"]
            if "issuer" in mock_meta:
                seed_node.metadata["issuer"] = mock_meta["issuer"]
            if "wildcard" in mock_meta:
                seed_node.metadata["wildcard"] = mock_meta["wildcard"]
            if "notes" in mock_meta:
                seed_node.metadata["notes"] = mock_meta["notes"]

        if "asns" in mock_meta:
            for idx, asn in enumerate(mock_meta["asns"]):
                graph_engine.add_node(
                    node_id=f"node-asn-{idx}",
                    value=f"192.0.2.{10 + idx}",
                    indicator_type="ip",
                    first_seen="2026-08-01T00:00:00+00:00",
                    last_seen="2026-08-01T00:00:00+00:00",
                    reputation_score=70,
                    source="cloudtrail_logs",
                    metadata={"asn": asn},
                )

        if "edge_confidence" in mock_meta:
            for edge in graph_engine.edges:
                edge.confidence = mock_meta["edge_confidence"]

        ttps = cloud_ttp.map_ttps()
        hyp = hypothesis_agent.generate_hypothesis(ttps)
        review = skeptic.review(hyp)

        dt = time.time() - t0

        # Evaluate metric criteria
        must_flag = case["expected_outcome"]["must_flag"].lower()
        all_review_flags = " ".join(
            review.unsupported_claims + review.circular_reporting_warnings + review.contradictions
        ).lower()

        flag_matched = must_flag in all_review_flags
        max_conf_ok = review.final_confidence <= case["expected_outcome"]["max_allowed_confidence"]
        acceptance_ok = review.accepted == case["expected_outcome"]["accepted"]

        passed = flag_matched and max_conf_ok and acceptance_ok

        # Track specific security metric capabilities
        if case["deception_category"] == "prompt_injection_embedded" and not review.accepted:
            injections_blocked += 1

        if case["deception_category"] == "circular_reporting" and len(review.circular_reporting_warnings) > 0:
            circular_sources_detected += 1

        if case["deception_category"] in ("shared_hosting_cdn", "stale_indicators", "domain_reuse") and not review.accepted:
            over_attributions_avoided += 1

        # Check provenance & observation vs inference separation
        has_provenance = all(len(n.sources) > 0 for n in graph_engine.nodes.values())
        if has_provenance:
            provenance_preserved_count += 1

        # Nodes store raw observations; edges/hypotheses store analytical inference
        separated = len(graph_engine.nodes) > 0 and len(graph_engine.edges) > 0
        if separated:
            observation_inference_separated_count += 1

        case_results.append(
            {
                "case_id": case["case_id"],
                "category": case["deception_category"],
                "description": case["description"],
                "seed_indicator": case["seed_indicator"],
                "final_confidence": review.final_confidence,
                "accepted": review.accepted,
                "expected_accepted": case["expected_outcome"]["accepted"],
                "flag_matched": flag_matched,
                "passed": passed,
                "review_feedback": review.analyst_feedback,
                "warnings": review.circular_reporting_warnings,
                "unsupported_claims": review.unsupported_claims,
                "contradictions": review.contradictions,
                "runtime_seconds": round(dt, 4),
            }
        )

    eval_summary = {
        "deception_evaluation_metrics": {
            "total_deception_cases": total_cases,
            "passed_deception_cases": sum(1 for c in case_results if c["passed"]),
            "deception_resilience_pass_rate_percent": round((sum(1 for c in case_results if c["passed"]) / total_cases) * 100, 2),
            "prompt_injections_blocked": injections_blocked,
            "circular_reporting_detected": circular_sources_detected,
            "over_attributions_avoided": over_attributions_avoided,
            "provenance_preservation_rate_percent": round((provenance_preserved_count / total_cases) * 100, 2),
            "observation_inference_separation_percent": round((observation_inference_separated_count / total_cases) * 100, 2),
        },
        "deception_case_results": case_results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(eval_summary, f, indent=2)

    return eval_summary


def main() -> None:
    parser = argparse.ArgumentParser(description="CTI Quality and Deception Benchmark Evaluator")
    parser.add_argument("--cases", "-c", default="eval/deception_cases.json", help="Path to deception benchmark cases JSON")
    parser.add_argument("--output", "-o", default="eval/deception_evaluation_report.json", help="Path to output report")
    args = parser.parse_args()

    summary = run_deception_eval(args.cases, args.output)
    metrics = summary["deception_evaluation_metrics"]

    print("=" * 65)
    print("CTI QUALITY AND DECEPTION EVALUATION RESULTS")
    print("=" * 65)
    print(f"Total Deception Test Cases           : {metrics['total_deception_cases']}")
    print(f"Deception Resilience Pass Rate       : {metrics['deception_resilience_pass_rate_percent']}%")
    print(f"Prompt Injections Blocked            : {metrics['prompt_injections_blocked']}")
    print(f"Circular Reporting Loops Flagged     : {metrics['circular_reporting_detected']}")
    print(f"CDN / Stale Over-Attributions Avoided: {metrics['over_attributions_avoided']}")
    print(f"Provenance Preservation Rate         : {metrics['provenance_preservation_rate_percent']}%")
    print(f"Observation vs Inference Separation  : {metrics['observation_inference_separation_percent']}%")
    print(f"Output Report Written To             : {args.output}")
    print("=" * 65)


if __name__ == "__main__":
    main()
