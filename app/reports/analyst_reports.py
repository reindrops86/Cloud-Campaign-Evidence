"""Analyst-facing report generation for a completed investigation.

Four documents are rendered from one pipeline result, so they cannot disagree
with each other:

* investigation report - the full analytic record
* response memo        - proportional, evidence-tiered containment actions
* threat-intel report  - behaviours, infrastructure, and detection logic
* executive brief      - one page for a decision maker

The central discipline is that this module never blurs three claim kinds:

* observation - proven by a raw telemetry record. In this codebase that means
  an edge with ``observed=True`` or an attack-path step at status ``OBSERVED``.
* inference   - a permission evaluation, a graph relationship, or a TTP mapping
  that is reasoned rather than witnessed. Carries an explicit confidence.
* attribution - a claim about who is responsible. This system does not make
  them; ``assumed_threat_actor`` is an internal cluster label, nothing more.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Sequence

OBSERVED_STATUSES = {"OBSERVED"}
REACHABLE_STATUSES = {"CONFIRMED_ALLOWED", "POTENTIAL"}

_IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_SCHEME_RE = re.compile(r"(?i)\bhttps?://")


def defang_text(text: str) -> str:
    """Defang addresses embedded in free text, which node-level defanging misses."""
    if not text:
        return ""
    defanged = _IPV4_RE.sub(lambda m: "[\\.]".join(m.groups()), str(text))
    return _SCHEME_RE.sub(lambda m: m.group(0).replace("://", "[://]"), defanged)

# Cloud containment actions ordered by blast radius. Tier is selected from the
# strength of evidence held, not from the severity of the worst-case story.
RESPONSE_LADDER: List[Dict[str, Any]] = [
    {
        "tier": 0,
        "action": "monitor_and_collect",
        "reversible": True,
        "description": "Keep collecting; add the principal and infrastructure to a watchlist. No user-visible change.",
    },
    {
        "tier": 1,
        "action": "tighten_trust_and_scope",
        "reversible": True,
        "description": "Narrow overly broad trust conditions and scope permissive policy statements.",
    },
    {
        "tier": 2,
        "action": "rotate_credential",
        "reversible": True,
        "description": "Rotate the exposed access key and re-issue to the legitimate workload.",
    },
    {
        "tier": 3,
        "action": "revoke_sessions_and_disable_key",
        "reversible": True,
        "description": "Deactivate the access key and revoke active role sessions issued before the cut-off.",
    },
    {
        "tier": 4,
        "action": "isolate_principal",
        "reversible": False,
        "description": "Detach policies and quarantine the principal. Breaks any legitimate workload still using it.",
    },
]


@dataclass
class Claim:
    kind: str  # observation | inference | attribution
    statement: str
    confidence: float
    provenance: List[str] = field(default_factory=list)
    basis: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "statement": self.statement,
            "confidence": round(self.confidence, 3),
            "provenance": self.provenance,
            "basis": self.basis,
        }


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    if not rows:
        return "_None recorded._"
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        cells = [defang_text(str(cell)).replace("|", "\\|").replace("\n", " ") for cell in row]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _graph(result: Dict[str, Any]) -> Dict[str, Any]:
    return result.get("evidence_graph") or {}


def _node_label(result: Dict[str, Any], node_id: str) -> str:
    for node in _graph(result).get("nodes", []):
        if node.get("id") == node_id:
            return node.get("defanged_value") or node.get("value") or node_id
    return node_id


def _attack_paths(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    paths = list((result.get("aws_telemetry") or {}).get("attack_paths", []))
    paths.extend((result.get("workload_federation") or {}).get("federated_paths", []))
    return paths


def classify_claims(result: Dict[str, Any]) -> Dict[str, List[Claim]]:
    """Split everything the pipeline produced into observation / inference / attribution."""
    review = result.get("skeptic_review") or {}
    final_confidence = review.get("final_confidence", 0) / 100.0

    observations: List[Claim] = []
    inferences: List[Claim] = []

    for edge in _graph(result).get("edges", []):
        source = _node_label(result, edge.get("source_id", ""))
        target = _node_label(result, edge.get("target_id", ""))
        statement = f"{source} -> {target} ({edge.get('relation_type')}): {edge.get('evidence_basis')}"
        if edge.get("observed"):
            observations.append(
                Claim(
                    kind="observation",
                    statement=statement,
                    confidence=1.0,
                    provenance=list(edge.get("evidence_refs", [])),
                )
            )
        else:
            inferences.append(
                Claim(
                    kind="inference",
                    statement=statement,
                    confidence=edge.get("confidence", 0) / 100.0,
                    basis=["graph relationship without a corroborating raw event"],
                )
            )

    for path in _attack_paths(result):
        steps = path.get("steps", [])
        refs = [ref for step in steps for ref in step.get("evidence_refs", [])]
        if path.get("status") in OBSERVED_STATUSES:
            observations.append(
                Claim(
                    kind="observation",
                    statement=f"{path.get('title')} was exercised (risk {path.get('risk_score')}/100).",
                    confidence=1.0,
                    provenance=refs,
                )
            )
        elif path.get("status") in REACHABLE_STATUSES:
            inferences.append(
                Claim(
                    kind="inference",
                    statement=f"{path.get('title')} is reachable but was not observed being used.",
                    confidence=path.get("risk_score", 0) / 100.0,
                    basis=list(path.get("scoring_rationale", []))[:2] or ["permission evaluation"],
                )
            )

    for ttp in result.get("ttp_mappings", []):
        inferences.append(
            Claim(
                kind="inference",
                statement=f"[{ttp.get('technique_id')}] {ttp.get('technique_name')} ({ttp.get('tactic')}).",
                confidence=ttp.get("confidence", 0) / 100.0,
                basis=[f"platform: {ttp.get('platform')}"],
            )
        )

    hypothesis = result.get("hypothesis") or {}
    if hypothesis.get("primary_claim"):
        inferences.append(
            Claim(
                kind="inference",
                statement=hypothesis["primary_claim"],
                confidence=final_confidence,
                basis=["campaign hypothesis after skeptic audit"],
            )
        )

    actor = hypothesis.get("threat_actor")
    attribution = [
        Claim(
            kind="attribution",
            statement=(
                f"No identity attribution is made. '{actor}' is an internal cluster label for this "
                "activity, not a claim about a named group, and carries no assertion about who "
                "controls the infrastructure."
                if actor
                else "No identity attribution is made."
            ),
            confidence=0.0,
            basis=["policy: clustering is not identification"],
        )
    ]

    return {"observation": observations, "inference": inferences, "attribution": attribution}


def evidence_gaps(result: Dict[str, Any]) -> List[str]:
    """What the investigation does not know, stated alongside what it does."""
    review = result.get("skeptic_review") or {}
    aws = result.get("aws_telemetry") or {}
    federation = result.get("workload_federation") or {}
    gaps: List[str] = []

    if not aws:
        gaps.append(
            "No CloudTrail telemetry was supplied, so every relationship in this report is inferred "
            "rather than witnessed. Re-run with --source file or --source aws to confirm."
        )
    elif not aws.get("data_events"):
        gaps.append(
            "Only management events were available. Object-level access to storage cannot be "
            "confirmed or excluded without data-event logging."
        )

    summary = aws.get("attack_path_summary") or {}
    if summary.get("potential") and not summary.get("observed"):
        gaps.append(
            f"{summary['potential']} identity path(s) are reachable on paper but none were observed "
            "being used. Reachability is not evidence of use."
        )

    for claim in review.get("unsupported_claims", []):
        gaps.append(f"Claim demoted during skeptic audit: {claim}")
    for warning in review.get("circular_reporting_warnings", []):
        gaps.append(f"Single-source dependency: {warning}")
    for contradiction in review.get("contradictions", []):
        gaps.append(f"Unresolved contradiction: {contradiction}")

    if federation.get("overly_broad_trusts"):
        gaps.append(
            f"{len(federation['overly_broad_trusts'])} federated trust condition(s) are wider than one "
            "workload, so the true set of principals able to assume the role is larger than observed."
        )

    gaps.append(
        "Infrastructure ownership is unconfirmed. Shared hosting, CDNs, and rented ranges can place "
        "unrelated tenants behind the same address."
    )
    return gaps


def recommend_actions(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Select a response tier from the strength of evidence, not the worst-case story."""
    review = result.get("skeptic_review") or {}
    confidence = review.get("final_confidence", 0)
    aws = result.get("aws_telemetry") or {}
    federation = result.get("workload_federation") or {}
    summary = aws.get("attack_path_summary") or {}

    observed_paths = summary.get("observed", 0)
    highest_risk = summary.get("highest_risk_score", 0)
    seed = result.get("defanged_indicator", "the seed indicator")
    seed_type = result.get("seed_type", "indicator")

    if observed_paths and highest_risk >= 70 and review.get("accepted"):
        tier = 3
    elif observed_paths:
        tier = 2
    elif summary.get("potential") or federation.get("overly_broad_trusts"):
        tier = 1
    else:
        tier = 0

    chosen = RESPONSE_LADDER[tier]
    actions: List[Dict[str, Any]] = [
        {
            **chosen,
            "scope": [seed],
            "rationale": (
                f"Skeptic confidence {confidence}% ({'accepted' if review.get('accepted') else 'not accepted'}). "
                f"{observed_paths} identity path(s) observed in telemetry, "
                f"{summary.get('potential', 0)} reachable but unobserved. "
                "The tier is set by what was witnessed, not by the most severe reachable outcome."
            ),
            "proportionality": (
                "Reachable-but-unobserved paths justify hardening, not credential destruction."
                if tier <= 1
                else "Containment is limited to the principal with observed misuse."
            ),
            "requires_human_approval": tier >= 3,
        }
    ]

    if federation.get("overly_broad_trusts"):
        actions.append(
            {
                **RESPONSE_LADDER[1],
                "scope": [t.get("role_arn", "unknown role") for t in federation["overly_broad_trusts"]][:5],
                "rationale": "Trust conditions match more workloads than intended, widening who can assume the role.",
                "proportionality": "Configuration change only; no credential impact.",
                "requires_human_approval": False,
            }
        )

    if summary.get("potential") and tier < 1:
        actions.append(
            {
                **RESPONSE_LADDER[1],
                "scope": [seed],
                "rationale": "Reachable privilege paths exist even though none were exercised.",
                "proportionality": "Reduces future blast radius without disrupting current workloads.",
                "requires_human_approval": False,
            }
        )

    actions.append(
        {
            "tier": 0,
            "action": "detection_deployment",
            "reversible": True,
            "description": "Deploy the generated Sigma and KQL rules in monitor-only mode for two weeks.",
            "scope": [r.get("rule_id", "") for r in result.get("detection_rules", [])],
            "rationale": f"Converts this investigation into durable coverage for {seed_type} reuse.",
            "proportionality": "Detection-only; no user-visible impact.",
            "requires_human_approval": False,
        }
    )
    return actions


def investigation_report(result: Dict[str, Any]) -> str:
    claims = classify_claims(result)
    review = result.get("skeptic_review") or {}
    graph = _graph(result)
    aws = result.get("aws_telemetry") or {}
    summary = aws.get("attack_path_summary") or {}

    lines: List[str] = []
    lines.append(f"# Investigation report {result.get('investigation_id')}")
    lines.append("")
    lines.append(f"**Seed indicator:** `{result.get('defanged_indicator')}` ({result.get('seed_type')})  ")
    lines.append(f"**Date:** {result.get('timestamp')}  ")
    lines.append(f"**Skeptic status:** {'ACCEPTED' if review.get('accepted') else 'NOT ACCEPTED'}  ")
    lines.append(f"**Assessed confidence:** {review.get('final_confidence', 0)}%")
    lines.append("")
    lines.append("> Indicators are defanged. This report separates what was observed in telemetry from "
                 "what was inferred, and makes no identity attribution.")
    lines.append("")

    lines.append("## 1. Summary")
    lines.append("")
    hypothesis = result.get("hypothesis") or {}
    lines.append(defang_text(hypothesis.get("primary_claim", "No hypothesis was generated.")))
    lines.append("")
    lines.append(
        f"The evidence graph holds {graph.get('node_count', 0)} entities and "
        f"{graph.get('edge_count', 0)} relationships. Across relationships, attack paths, and "
        f"technique mappings, {len(claims['observation'])} finding(s) are backed by a raw telemetry "
        f"record and {len(claims['inference'])} are reasoned."
    )
    lines.append("")

    lines.append("## 2. Observations")
    lines.append("")
    lines.append("Each row below is proven by a specific telemetry record.")
    lines.append("")
    lines.append(
        _md_table(
            ["Statement", "Evidence records"],
            [[c.statement, ", ".join(c.provenance[:3]) or "-"] for c in claims["observation"][:25]],
        )
    )
    lines.append("")

    lines.append("## 3. Inferences")
    lines.append("")
    lines.append("Each row below is a conclusion, not a record. Confidence is stated explicitly.")
    lines.append("")
    lines.append(
        _md_table(
            ["Statement", "Confidence", "Basis"],
            [[c.statement, f"{c.confidence:.2f}", "; ".join(c.basis) or "-"] for c in claims["inference"][:25]],
        )
    )
    lines.append("")

    lines.append("## 4. Attribution position")
    lines.append("")
    for claim in claims["attribution"]:
        lines.append(f"- {claim.statement}")
    lines.append("")

    if summary:
        lines.append("## 5. Identity attack paths")
        lines.append("")
        lines.append(
            _md_table(
                ["Path", "Category", "Status", "Risk", "Rationale"],
                [
                    [
                        p.get("title"),
                        p.get("risk_category"),
                        p.get("status"),
                        f"{p.get('risk_score')}/100",
                        "; ".join(p.get("scoring_rationale", [])[:2]),
                    ]
                    for p in sorted(_attack_paths(result), key=lambda p: -p.get("risk_score", 0))[:12]
                ],
            )
        )
        lines.append("")
        lines.append(
            f"_{summary.get('observed', 0)} observed, {summary.get('potential', 0)} reachable but "
            f"unobserved, {summary.get('blocked', 0)} blocked._"
        )
        lines.append("")

    lines.append("## 6. Competing explanations")
    lines.append("")
    alternatives = hypothesis.get("alternative_hypotheses", [])
    lines.append(_md_table(["Alternative explanation"], [[alt] for alt in alternatives]))
    lines.append("")

    lines.append("## 7. Skeptic audit")
    lines.append("")
    lines.append(defang_text(review.get("feedback", "No audit recorded.")))
    lines.append("")
    for label, key in (
        ("Demoted claims", "unsupported_claims"),
        ("Circular reporting warnings", "circular_reporting_warnings"),
        ("Contradictions", "contradictions"),
    ):
        entries = review.get(key, [])
        if entries:
            lines.append(f"**{label}**")
            lines.append("")
            for entry in entries:
                lines.append(f"- {defang_text(entry)}")
            lines.append("")

    lines.append("## 8. Evidence gaps")
    lines.append("")
    for gap in evidence_gaps(result):
        lines.append(f"- {defang_text(gap)}")
    lines.append("")

    lines.append("## 9. Recommended response")
    lines.append("")
    lines.append(
        _md_table(
            ["Tier", "Action", "Scope", "Reversible", "Approval", "Rationale"],
            [
                [
                    a["tier"],
                    a["action"],
                    ", ".join(str(s) for s in a["scope"])[:48] or "-",
                    "yes" if a["reversible"] else "no",
                    "required" if a["requires_human_approval"] else "not required",
                    a["rationale"],
                ]
                for a in recommend_actions(result)
            ],
        )
    )
    lines.append("")

    lines.append("## 10. Limitations")
    lines.append("")
    lines.append("- Confidence is a rule-based score, not a calibrated probability.")
    lines.append("- Reachability is computed from policy evaluation and may miss conditions that only "
                 "resolve at request time.")
    lines.append("- Absence of an observation is not evidence of absence; it may reflect logging coverage.")
    lines.append("")
    return "\n".join(lines)


def response_memo(result: Dict[str, Any]) -> str:
    review = result.get("skeptic_review") or {}
    lines = [f"# Response recommendation - {result.get('investigation_id')}", ""]
    lines.append(f"**Seed:** `{result.get('defanged_indicator')}` ({result.get('seed_type')})  ")
    lines.append(f"**Assessed confidence:** {review.get('final_confidence', 0)}%")
    lines.append("")
    lines.append("Response tier is selected from the strength of evidence held, not from the most severe "
                 "reachable outcome. Reachable-but-unobserved paths justify hardening, never credential "
                 "destruction.")
    lines.append("")

    for action in recommend_actions(result):
        lines.append(f"## Tier {action['tier']} - {action['action']}")
        lines.append("")
        lines.append(f"- **What it does:** {action['description']}")
        lines.append(f"- **Scope:** {defang_text(', '.join(str(s) for s in action['scope'])) or 'n/a'}")
        lines.append(f"- **Rationale:** {defang_text(action['rationale'])}")
        lines.append(f"- **Proportionality:** {action['proportionality']}")
        lines.append(f"- **Reversible:** {'yes' if action['reversible'] else 'no'}")
        lines.append(
            f"- **Human approval:** {'required' if action['requires_human_approval'] else 'not required'}"
        )
        lines.append("")

    lines.append("## Before acting")
    lines.append("")
    lines.append("- Confirm the principal is not serving a production workload; key deactivation is "
                 "reversible but the outage it causes is not.")
    lines.append("- Preserve CloudTrail records and the evidence graph before any rotation, so the "
                 "investigation remains reproducible.")
    lines.append("- Record who approved each tier 3 or higher action and when.")
    lines.append("")
    lines.append("## Rollback")
    lines.append("")
    lines.append("- Key rotation: re-issue to the legitimate workload and monitor for failed calls.")
    lines.append("- Trust tightening: revert the condition block from version control.")
    lines.append("- Detections: disable the rule; logic is versioned in this repository.")
    lines.append("")
    return "\n".join(lines)


def threat_intel_report(result: Dict[str, Any]) -> str:
    graph = _graph(result)
    hypothesis = result.get("hypothesis") or {}
    lines = [f"# Threat intelligence report - {result.get('investigation_id')}", ""]
    lines.append(f"**Activity cluster:** {hypothesis.get('threat_actor') or 'unnamed'} "
                 "(internal label, not an attribution)  ")
    lines.append(f"**Confidence:** {(result.get('skeptic_review') or {}).get('final_confidence', 0)}%")
    lines.append("")

    lines.append("## Techniques observed or inferred")
    lines.append("")
    lines.append(
        _md_table(
            ["Technique", "Name", "Tactic", "Platform", "Confidence"],
            [
                [t.get("technique_id"), t.get("technique_name"), t.get("tactic"), t.get("platform"), f"{t.get('confidence')}%"]
                for t in result.get("ttp_mappings", [])
            ],
        )
    )
    lines.append("")

    lines.append("## Infrastructure (defanged)")
    lines.append("")
    lines.append(
        _md_table(
            ["Indicator", "Type", "Reputation", "Decayed", "First seen", "Sources"],
            [
                [
                    n.get("defanged_value"),
                    n.get("indicator_type"),
                    n.get("reputation_score"),
                    n.get("decayed_reputation"),
                    n.get("first_seen"),
                    ", ".join(n.get("sources", []))[:32],
                ]
                for n in graph.get("nodes", [])[:25]
            ],
        )
    )
    lines.append("")
    lines.append("_Decayed reputation reflects half-life ageing. Prefer it over the raw score when "
                 "deciding whether an indicator is still actionable._")
    lines.append("")

    lines.append("## Detection logic")
    lines.append("")
    for rule in result.get("detection_rules", []):
        lines.append(f"### {rule.get('title')} ({rule.get('format')}, {rule.get('target')})")
        lines.append("")
        lines.append("```yaml")
        lines.append(str(rule.get("content", "")).rstrip())
        lines.append("```")
        lines.append("")

    lines.append("## Collection gaps")
    lines.append("")
    for gap in evidence_gaps(result):
        lines.append(f"- {defang_text(gap)}")
    lines.append("")
    return "\n".join(lines)


def executive_brief(result: Dict[str, Any]) -> str:
    review = result.get("skeptic_review") or {}
    claims = classify_claims(result)
    aws = result.get("aws_telemetry") or {}
    summary = aws.get("attack_path_summary") or {}
    actions = recommend_actions(result)
    top = max(actions, key=lambda a: a["tier"])

    lines = ["# Executive one-pager", ""]
    lines.append(f"**{result.get('investigation_id')} - cloud credential misuse investigation**")
    lines.append("")
    lines.append("## What happened")
    lines.append("")
    lines.append(defang_text((result.get("hypothesis") or {}).get("primary_claim", "No hypothesis was generated.")))
    lines.append("")

    lines.append("## How strongly we believe it")
    lines.append("")
    lines.append(f"- Assessed confidence **{review.get('final_confidence', 0)}%** after an automated "
                 f"skeptic audit that penalises weak, stale, and single-source evidence.")
    lines.append(f"- **{len(claims['observation'])}** findings are proven by raw telemetry records; "
                 f"**{len(claims['inference'])}** are inferred and carry lower confidence.")
    if summary:
        lines.append(f"- **{summary.get('observed', 0)}** privilege path(s) were actually exercised; "
                     f"**{summary.get('potential', 0)}** were reachable but never used.")
    lines.append("- We do not claim to know who is responsible. This is a linkage assessment.")
    lines.append("")

    lines.append("## What we recommend")
    lines.append("")
    for action in actions:
        lines.append(f"- **{action['action'].replace('_', ' ')}** (tier {action['tier']}) - {action['proportionality']}")
    lines.append("")

    lines.append("## What it costs us to be wrong")
    lines.append("")
    if top["tier"] >= 3:
        lines.append("- The highest recommended action disables a credential. If the principal serves "
                     "production, this causes an outage, so it requires named human approval.")
    else:
        lines.append("- The highest recommended action is a configuration change with no credential "
                     "impact, so the cost of being wrong is low.")
    lines.append(f"- {len(review.get('unsupported_claims', []))} claim(s) were demoted and "
                 f"{len(review.get('contradictions', []))} contradiction(s) remain unresolved.")
    lines.append(f"- {len(evidence_gaps(result))} evidence gap(s) are recorded and none are hidden.")
    lines.append("")

    lines.append("## What changes as a result")
    lines.append("")
    lines.append(f"- {len(result.get('detection_rules', []))} detection rule(s) drafted for monitor-only deployment.")
    lines.append("- The evidence graph and STIX bundle are retained so the assessment is reproducible.")
    lines.append("")
    return "\n".join(lines)


REPORT_BUILDERS = {
    "investigation": investigation_report,
    "response-memo": response_memo,
    "threat-intel": threat_intel_report,
    "executive-brief": executive_brief,
}


def write_analyst_reports(result: Dict[str, Any], out_dir: str | Path) -> List[Path]:
    """Render all four documents into ``out_dir`` and return the paths written."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    investigation_id = result.get("investigation_id", "INV-UNKNOWN")

    written: List[Path] = []
    for name, builder in REPORT_BUILDERS.items():
        path = directory / f"{investigation_id}-{name}.md"
        path.write_text(builder(result), encoding="utf-8")
        written.append(path)
    return written
