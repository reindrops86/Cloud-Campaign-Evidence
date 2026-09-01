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
    seed = st.sidebar.text_input("Seed Indicator", value="AKIAIOSFODNN7EXAMPLE")
    seed_type = st.sidebar.selectbox(
        "Indicator Type",
        options=["auto", "iam_access_key", "ip", "domain", "url", "hash", "container_image", "github_repo"],
    )

    run_button = st.sidebar.button("Run Campaign Investigation", type="primary")

    if run_button or seed:
        st_type = None if seed_type == "auto" else seed_type
        with st.spinner("Executing agentic investigation pipeline..."):
            res = run_pipeline(seed, st_type)

        # Overview Header
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Investigation ID", res["investigation_id"])
        col2.metric("Seed Type", res["seed_type"])
        col3.metric("Final Confidence", f"{res['skeptic_review']['final_confidence']}%")
        col4.metric("Skeptic Status", "ACCEPTED" if res['skeptic_review']['accepted'] else "REJECTED")

        st.divider()

        # Tabs
        tab_summary, tab_graph, tab_ttps, tab_skeptic, tab_stix, tab_rules = st.tabs(
            ["📋 Research Report", "🕸️ Evidence Graph", "🎯 ATT&CK Mappings", "🔍 Skeptic Audit", "📦 STIX 2.1 Bundle", "⚡ Detection Rules"]
        )

        with tab_summary:
            st.markdown(res["markdown_report"])

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
