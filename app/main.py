from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

# Add parent directory to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.agents.cloud_ttp import CloudTTPAnalystAgent
from app.agents.collector import CollectorAgent
from app.agents.enrichment import EnrichmentAnalystAgent
from app.agents.hypothesis import HypothesisAnalystAgent
from app.agents.report_builder import ReportBuilderAgent
from app.agents.skeptic import SkepticReviewerAgent
from app.graph.evidence_graph import EvidenceGraphEngine, defang_indicator


def run_pipeline(seed_indicator: str, seed_type: str | None = None) -> Dict[str, Any]:
    graph_engine = EvidenceGraphEngine()

    collector = CollectorAgent(graph_engine)
    enricher = EnrichmentAnalystAgent(graph_engine)
    cloud_ttp = CloudTTPAnalystAgent(graph_engine)
    hypothesis_agent = HypothesisAnalystAgent(graph_engine)
    skeptic = SkepticReviewerAgent(graph_engine)
    report_builder = ReportBuilderAgent(graph_engine)

    # Step 1: Collection
    coll_res = collector.collect(seed_indicator, seed_type)

    # Step 2: Enrichment & Infrastructure Relationship Discovery
    enr_res = enricher.enrich(coll_res["seed_id"])

    # Step 3: Cloud-TTP ATT&CK Mapping
    ttps = cloud_ttp.map_ttps()

    # Step 4: Campaign Hypothesis Generation
    hyp = hypothesis_agent.generate_hypothesis(ttps)

    # Step 5: Skeptic Audit & Provenance Verification
    review = skeptic.review(hyp)

    # Step 6: Report, Detection Rules, & STIX 2.1 Export
    investigation_id = f"INV-2026-{hash(seed_indicator) % 10000:04d}"
    report = report_builder.build_report(
        investigation_id=investigation_id,
        seed_val=seed_indicator,
        stype=coll_res["seed_type"],
        ttp_mappings=ttps,
        hypothesis=hyp,
        skeptic_review=review,
    )

    return {
        "investigation_id": report.investigation_id,
        "seed_indicator": seed_indicator,
        "defanged_indicator": defang_indicator(seed_indicator),
        "seed_type": coll_res["seed_type"],
        "timestamp": report.timestamp,
        "evidence_graph": graph_engine.export_graph_dict(),
        "ttp_mappings": [
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "tactic": t.tactic,
                "platform": t.cloud_platform,
                "confidence": t.confidence,
            }
            for t in ttps
        ],
        "hypothesis": {
            "id": hyp.hypothesis_id,
            "primary_claim": hyp.primary_claim,
            "alternative_hypotheses": hyp.alternative_hypotheses,
            "threat_actor": hyp.assumed_threat_actor,
        },
        "skeptic_review": {
            "accepted": review.accepted,
            "final_confidence": review.final_confidence,
            "unsupported_claims": review.unsupported_claims,
            "circular_reporting_warnings": review.circular_reporting_warnings,
            "contradictions": review.contradictions,
            "feedback": review.analyst_feedback,
        },
        "detection_rules": [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "format": r.format_type,
                "target": r.target_service,
                "content": r.rule_content,
            }
            for r in report.detection_rules
        ],
        "stix_bundle": report.stix_bundle,
        "markdown_report": report.markdown_report,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Cloud Campaign Evidence Graph - Pipeline Runner")
    parser.add_argument("--seed", "-s", required=True, help="Seed indicator (IAM Access Key, IP, Domain, Hash, URL, Container, Repo)")
    parser.add_argument("--seed-type", "-t", choices=["iam_access_key", "ip", "domain", "url", "hash", "container_image", "github_repo"], help="Explicit indicator type")
    parser.add_argument("--output", "-o", default="data/investigation_output.json", help="Path to write investigation JSON output")
    parser.add_argument("--export-stix", help="Path to write STIX 2.1 JSON bundle")
    parser.add_argument("--export-markdown", help="Path to write Markdown research report")
    args = parser.parse_args()

    print(f"[*] Starting Cloud Campaign Evidence Graph Investigation for seed: {defang_indicator(args.seed)}...")
    result = run_pipeline(args.seed, args.seed_type)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"[+] Investigation JSON output written to {args.output}")

    if args.export_stix:
        stix_path = Path(args.export_stix)
        stix_path.parent.mkdir(parents=True, exist_ok=True)
        with open(stix_path, "w", encoding="utf-8") as f:
            json.dump(result["stix_bundle"], f, indent=2)
        print(f"[+] STIX 2.1 Bundle written to {args.export_stix}")

    if args.export_markdown:
        md_path = Path(args.export_markdown)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(result["markdown_report"])
        print(f"[+] Markdown Research Report written to {args.export_markdown}")

    print("\n" + "=" * 60)
    print("INVESTIGATION SUMMARY")
    print("=" * 60)
    print(f"Investigation ID : {result['investigation_id']}")
    print(f"Seed Indicator   : {result['defanged_indicator']} ({result['seed_type']})")
    print(f"Confidence Score : {result['skeptic_review']['final_confidence']}%")
    print(f"Skeptic Status   : {'ACCEPTED' if result['skeptic_review']['accepted'] else 'REJECTED'}")
    print(f"Graph Entities   : {result['evidence_graph']['node_count']} nodes, {result['evidence_graph']['edge_count']} edges")
    print(f"ATT&CK Mappings  : {len(result['ttp_mappings'])} cloud techniques mapped")
    print("=" * 60)


if __name__ == "__main__":
    main()
