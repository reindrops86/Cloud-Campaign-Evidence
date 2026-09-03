from __future__ import annotations

import json
import sys
from pathlib import Path

import streamlit as st

# Add parent app directory to path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.main import run_pipeline


def main() -> None:
    st.set_page_config(
        page_title="Cloud Campaign Evidence Graph - Analyst Console",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ Cloud Campaign Evidence Graph Analyst Console")
    st.caption("Agentic Cloud Threat Investigation, Skeptic Audit, & STIX 2.1 Generation")

    # Sidebar setup
    st.sidebar.header("Investigation Controls")
    seed = st.sidebar.text_input("Seed Indicator", value="AKIACOMPROMISEDKEY01")
    seed_type = st.sidebar.selectbox(
        "Indicator Type",
        options=["auto", "iam_access_key", "ip", "domain", "url", "hash", "container_image", "github_repo"],
    )

    st.sidebar.divider()
    st.sidebar.subheader("Evidence Source")
    source_mode = st.sidebar.radio(
        "Telemetry Source",
        options=["synthetic", "file", "aws"],
        help="synthetic = demo data, file = exported CloudTrail JSON, aws = live LookupEvents",
    )

    cloudtrail_file = None
    iam_snapshot = None
    profile = None
    region = "us-east-1"
    simulate = False

    if source_mode == "file":
        cloudtrail_file = st.sidebar.text_input(
            "CloudTrail JSON Path", value="data/cloudtrail_samples/compromised_key.json"
        )
        iam_snapshot = st.sidebar.text_input(
            "IAM Snapshot Path", value="data/iam_snapshots/account_111122223333.json"
        )
    elif source_mode == "aws":
        profile = st.sidebar.text_input("AWS Profile", value="investigation-readonly")
        region = st.sidebar.text_input("Region", value="us-east-1")
        simulate = st.sidebar.checkbox("Use IAM Policy Simulator", value=True)
        st.sidebar.caption(
            "Credentials resolve through the AWS credential chain (SSO or assumed role). "
            "This tool never accepts a secret access key."
        )

    run_button = st.sidebar.button("Run Campaign Investigation", type="primary")

    if run_button or seed:
        st_type = None if seed_type == "auto" else seed_type
        with st.spinner("Executing agentic investigation pipeline..."):
            res = run_pipeline(
                seed,
                st_type,
                source_mode=source_mode,
                cloudtrail_file=cloudtrail_file,
                iam_snapshot=iam_snapshot,
                profile=profile,
                region=region,
                simulate=simulate,
            )

        # Overview Header
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Investigation ID", res["investigation_id"])
        col2.metric("Seed Type", res["seed_type"])
        col3.metric("Final Confidence", f"{res['skeptic_review']['final_confidence']}%")
        col4.metric("Skeptic Status", "ACCEPTED" if res['skeptic_review']['accepted'] else "REJECTED")

        st.divider()

        # Tabs
        (
            tab_summary,
            tab_paths,
            tab_graph,
            tab_ttps,
            tab_skeptic,
            tab_stix,
            tab_rules,
        ) = st.tabs(
            [
                "📋 Research Report",
                "🔑 Identity Attack Paths",
                "🕸️ Evidence Graph",
                "🎯 ATT&CK Mappings",
                "🔍 Skeptic Audit",
                "📦 STIX 2.1 Bundle",
                "⚡ Detection Rules",
            ]
        )

        with tab_summary:
            st.markdown(res["markdown_report"])

        with tab_paths:
            aws = res.get("aws_telemetry")
            if not aws:
                st.info(
                    "No AWS telemetry loaded. Choose the `file` or `aws` evidence source "
                    "in the sidebar to run effective-permission analysis."
                )
            else:
                summary = aws["attack_path_summary"]
                c1, c2, c3, c4, c5 = st.columns(5)
                c1.metric("OBSERVED", summary["observed"], help="CloudTrail proves the action occurred")
                c2.metric("CONFIRMED", summary["confirmed_allowed"], help="IAM simulator evaluated as allowed")
                c3.metric("POTENTIAL", summary["potential"], help="Policy configuration permits it")
                c4.metric("UNRESOLVED", summary["unresolved"], help="Conditions could not be evaluated")
                c5.metric("BLOCKED", summary["blocked"], help="Explicit deny or boundary")

                st.caption(
                    f"{aws['event_count']} CloudTrail events "
                    f"({aws['management_events']} management, {aws['data_events']} data). "
                    "Management-only telemetry cannot prove object-level data access."
                )

                for path in aws["attack_paths"]:
                    badge = {
                        "OBSERVED": "🔴",
                        "CONFIRMED_ALLOWED": "🟠",
                        "POTENTIAL": "🟡",
                        "UNRESOLVED": "⚪",
                        "BLOCKED": "🟢",
                    }.get(path["status"], "⚪")

                    with st.expander(
                        f"{badge} [{path['status']}] {path['title']} — risk {path['risk_score']}/100"
                    ):
                        st.write(" → ".join(f"`{s['label']}`" for s in path["steps"]))

                        for contradiction in path["contradictions"]:
                            st.error(f"⚠️ {contradiction}")

                        st.write("**Scoring rationale:**")
                        for reason in path["scoring_rationale"]:
                            st.write(f"- {reason}")

                        refs = [r for s in path["steps"] for r in s["evidence_refs"]]
                        if refs:
                            st.write("**Evidence references:**")
                            st.code("\n".join(refs))

                        st.write(f"**ATT&CK:** {', '.join(path['attack_technique_ids']) or 'n/a'}")

                if aws.get("iam_graph", {}).get("node_count"):
                    st.subheader("Permission Graph")
                    st.dataframe(aws["iam_graph"]["edges"], use_container_width=True)

        with tab_graph:
            st.subheader("Evidence Graph & Timeline")
            graph_data = res["evidence_graph"]
            st.write(f"**Total Entities:** {graph_data['node_count']} nodes | **Total Edges:** {graph_data['edge_count']} relationships")

            st.subheader("Discovered Nodes")
            st.dataframe(graph_data["nodes"], use_container_width=True)

            st.subheader("Evidence Edges")
            st.dataframe(graph_data["edges"], use_container_width=True)

            st.subheader("Chronological Timeline")
            for event in graph_data["timeline"]:
                st.info(f"**{event['timestamp']}**: {event['summary']}")

        with tab_ttps:
            st.subheader("MITRE ATT&CK for Cloud Mappings")
            for ttp in res["ttp_mappings"]:
                with st.expander(f"[{ttp['technique_id']}] {ttp['technique_name']} - Confidence: {ttp['confidence']}%"):
                    st.write(f"**Tactic:** {ttp['tactic']}")
                    st.write(f"**Cloud Platform:** {ttp['platform']}")

        with tab_skeptic:
            st.subheader("Skeptic Reviewer Audit Results")
            rev = res["skeptic_review"]
            st.write(f"**Analyst Feedback:** {rev['feedback']}")

            if rev["unsupported_claims"]:
                st.warning("⚠️ **Unsupported Claims & Downgrades:**")
                for claim in rev["unsupported_claims"]:
                    st.write(f"- {claim}")

            if rev["contradictions"]:
                st.error("🚨 **Infrastructure Contradictions:**")
                for contradiction in rev["contradictions"]:
                    st.write(f"- {contradiction}")

            if rev["circular_reporting_warnings"]:
                st.warning("🔄 **Circular Reporting Warnings:**")
                for warn in rev["circular_reporting_warnings"]:
                    st.write(f"- {warn}")

            st.subheader("Competing Hypotheses Evaluated (ACH)")
            hyp = res["hypothesis"]
            st.write(f"**Primary Claim:** {hyp['primary_claim']}")
            st.write("**Alternative Explanations:**")
            for alt in hyp["alternative_hypotheses"]:
                st.write(f"- {alt}")

        with tab_stix:
            st.subheader("Generated STIX 2.1 JSON Bundle")
            st.json(res["stix_bundle"])

        with tab_rules:
            st.subheader("Generated Sigma & KQL Detection Rules")
            for rule in res["detection_rules"]:
                st.markdown(f"### {rule['title']} (`{rule['format']}`)")
                st.code(rule["content"], language="yaml" if rule["format"] == "Sigma" else "kql")


if __name__ == "__main__":
    main()
