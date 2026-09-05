from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Add parent directory to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.agents.aws_telemetry import AWSTelemetryAgent
from app.agents.cloud_ttp import CloudTTPAnalystAgent
from app.agents.collector import CollectorAgent
from app.agents.enrichment import EnrichmentAnalystAgent
from app.agents.hypothesis import HypothesisAnalystAgent
from app.agents.report_builder import ReportBuilderAgent
from app.agents.skeptic import SkepticReviewerAgent
from app.agents.workload_federation import WorkloadFederationAgent
from app.collectors.aws_cloudtrail import FileCloudTrailSource, build_source
from app.collectors.aws_identity import AWSIdentityCollector, FileIdentitySource
from app.graph.evidence_graph import EvidenceGraphEngine, defang_indicator
from app.reports.analyst_reports import write_analyst_reports


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def run_aws_investigation(
    access_key_id: str,
    graph_engine: EvidenceGraphEngine,
    *,
    source_mode: str,
    cloudtrail_file: Optional[str],
    iam_snapshot: Optional[str],
    profile: Optional[str],
    region: str,
    start_time: Optional[datetime],
    end_time: Optional[datetime],
    simulate: bool,
) -> Dict[str, Any]:
    evidence_source = build_source(
        source_mode, file_path=cloudtrail_file, profile_name=profile, region=region
    )

    if source_mode == "aws":
        identity_source = AWSIdentityCollector(profile_name=profile)
    elif iam_snapshot:
        identity_source = FileIdentitySource(iam_snapshot)
    else:
        identity_source = None

    agent = AWSTelemetryAgent(graph_engine, evidence_source, identity_source)
    return agent.investigate(access_key_id, start_time, end_time, simulate=simulate)


def run_pipeline(
    seed_indicator: str,
    seed_type: str | None = None,
    *,
    source_mode: str = "synthetic",
    cloudtrail_file: Optional[str] = None,
    iam_snapshot: Optional[str] = None,
    profile: Optional[str] = None,
    region: str = "us-east-1",
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    simulate: bool = False,
    federated_roles: Optional[str] = None,
    k8s_snapshot: Optional[str] = None,
    k8s_audit_log: Optional[str] = None,
    github_snapshot: Optional[str] = None,
) -> Dict[str, Any]:
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
    aws_result: Dict[str, Any] = {}
    if source_mode in ("file", "aws"):
        aws_result = run_aws_investigation(
            seed_indicator,
            graph_engine,
            source_mode=source_mode,
            cloudtrail_file=cloudtrail_file,
            iam_snapshot=iam_snapshot,
            profile=profile,
            region=region,
            start_time=start_time,
            end_time=end_time,
            simulate=simulate,
        )
    else:
        enricher.enrich(coll_res["seed_id"])

    federation_result: Dict[str, Any] = {}
    if federated_roles:
        federation_agent = WorkloadFederationAgent(
            graph_engine,
            federated_roles,
            k8s_snapshot=k8s_snapshot,
            k8s_audit_log=k8s_audit_log,
            github_snapshot=github_snapshot,
            cloudtrail_records=_federation_cloudtrail_records(cloudtrail_file, source_mode),
        )
        federation_result = federation_agent.analyze()

    # Step 3: Cloud-TTP ATT&CK Mapping
    ttps = cloud_ttp.map_ttps()

    # Step 4: Campaign Hypothesis Generation
    hyp = hypothesis_agent.generate_hypothesis(ttps)

    # Step 5: Skeptic Audit & Provenance Verification
    review = skeptic.review(hyp)

    # Step 6: Report, Detection Rules, & STIX 2.1 Export
    # Stable across runs: Python's builtin hash() is randomized per process.
    seed_digest = hashlib.sha256(seed_indicator.encode("utf-8")).hexdigest()
    investigation_id = f"INV-2026-{int(seed_digest[:8], 16) % 10000:04d}"
    report = report_builder.build_report(
        investigation_id=investigation_id,
        seed_val=seed_indicator,
        stype=coll_res["seed_type"],
        ttp_mappings=ttps,
        hypothesis=hyp,
        skeptic_review=review,
    )

    result: Dict[str, Any] = {
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

    if aws_result:
        result["aws_telemetry"] = aws_result

    if federation_result:
        result["workload_federation"] = federation_result

    return result


def _federation_cloudtrail_records(cloudtrail_file: Optional[str], source_mode: str):
    """Load CloudTrail records so federated trusts can be marked OBSERVED."""
    if source_mode != "file" or not cloudtrail_file:
        return []
    source = FileCloudTrailSource(cloudtrail_file)
    return [
        _normalize_all(raw)
        for raw in source._load_raw_events()  # federation needs every event, not one key
    ]


def _normalize_all(raw: Dict[str, Any]):
    from app.collectors.aws_cloudtrail import _normalize

    return _normalize(raw, provider_source="cloudtrail_file_export", region=None)


def main() -> None:
    parser = argparse.ArgumentParser(description="Cloud Campaign Evidence Graph - Pipeline Runner")
    parser.add_argument("--seed", "-s", required=True, help="Seed indicator (IAM Access Key, IP, Domain, Hash, URL, Container, Repo)")
    parser.add_argument("--seed-type", "-t", choices=["iam_access_key", "ip", "domain", "url", "hash", "container_image", "github_repo"], help="Explicit indicator type")
    parser.add_argument("--source", choices=["synthetic", "file", "aws"], default="synthetic", help="Evidence source: synthetic demo data, exported CloudTrail JSON, or live AWS")
    parser.add_argument("--cloudtrail-file", help="Path to exported CloudTrail JSON (required for --source file)")
    parser.add_argument("--iam-snapshot", help="Path to exported IAM snapshot JSON for offline permission analysis")
    parser.add_argument("--profile", help="AWS profile name resolved via the standard credential chain")
    parser.add_argument("--region", default="us-east-1", help="AWS region for CloudTrail LookupEvents")
    parser.add_argument("--start-time", help="ISO-8601 window start, e.g. 2026-08-01T00:00:00Z")
    parser.add_argument("--end-time", help="ISO-8601 window end, e.g. 2026-09-01T00:00:00Z")
    parser.add_argument("--simulate", action="store_true", help="Use IAM SimulatePrincipalPolicy instead of graph-only evaluation")
    parser.add_argument("--federated-roles", help="Path to OIDC provider + federated role snapshot JSON")
    parser.add_argument("--k8s-snapshot", help="Path to Kubernetes RBAC/ServiceAccount snapshot JSON")
    parser.add_argument("--k8s-audit-log", help="Path to Kubernetes audit log export JSON")
    parser.add_argument("--github-snapshot", help="Path to GitHub org/workflow snapshot JSON")
    parser.add_argument("--output", "-o", default="data/investigation_output.json", help="Path to write investigation JSON output")
    parser.add_argument("--export-stix", help="Path to write STIX 2.1 JSON bundle")
    parser.add_argument("--export-markdown", help="Path to write Markdown research report")
    parser.add_argument("--export-reports", help="Directory to write the investigation, response, threat-intel, and executive reports")
    args = parser.parse_args()

    print(f"[*] Starting Cloud Campaign Evidence Graph Investigation for seed: {defang_indicator(args.seed)}...")
    result = run_pipeline(
        args.seed,
        args.seed_type,
        source_mode=args.source,
        cloudtrail_file=args.cloudtrail_file,
        iam_snapshot=args.iam_snapshot,
        profile=args.profile,
        region=args.region,
        start_time=_parse_time(args.start_time),
        end_time=_parse_time(args.end_time),
        simulate=args.simulate,
        federated_roles=args.federated_roles,
        k8s_snapshot=args.k8s_snapshot,
        k8s_audit_log=args.k8s_audit_log,
        github_snapshot=args.github_snapshot,
    )

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

    if args.export_reports:
        for path in write_analyst_reports(result, args.export_reports):
            print(f"[+] Analyst report written to {path}")

    print("\n" + "=" * 60)
    print("INVESTIGATION SUMMARY")
    print("=" * 60)
    print(f"Investigation ID : {result['investigation_id']}")
    print(f"Seed Indicator   : {result['defanged_indicator']} ({result['seed_type']})")
    print(f"Confidence Score : {result['skeptic_review']['final_confidence']}%")
    print(f"Skeptic Status   : {'ACCEPTED' if result['skeptic_review']['accepted'] else 'REJECTED'}")
    print(f"Graph Entities   : {result['evidence_graph']['node_count']} nodes, {result['evidence_graph']['edge_count']} edges")
    print(f"ATT&CK Mappings  : {len(result['ttp_mappings'])} cloud techniques mapped")

    aws = result.get("aws_telemetry")
    if aws:
        summary = aws["attack_path_summary"]
        print("-" * 60)
        print(f"CloudTrail Events: {aws['event_count']} ({aws['management_events']} management, {aws['data_events']} data)")
        print(f"Identity Paths   : {summary['total_paths']} total | {summary['observed']} OBSERVED | {summary['potential']} POTENTIAL | {summary['blocked']} BLOCKED")
        print(f"Highest Risk     : {summary['highest_risk_score']}/100")

    federation = result.get("workload_federation")
    if federation:
        fed = federation["federated_summary"]
        print("-" * 60)
        print(f"Identity Planes  : {', '.join(fed['planes'])}")
        print(f"Workloads        : {len(federation['workloads'])} | Trust edges: {len(federation['federated_trusts'])}")
        print(f"Overly-Broad     : {len(federation['overly_broad_trusts'])} trust condition(s) wider than one workload")
        print(f"Federated Paths  : {fed['total_paths']} total | {fed['observed']} OBSERVED | {fed['potential']} POTENTIAL | {fed['blocked']} BLOCKED")
        print(f"Highest Risk     : {fed['highest_risk_score']}/100")
    print("=" * 60)


if __name__ == "__main__":
    main()
