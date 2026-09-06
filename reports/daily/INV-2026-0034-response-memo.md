# Response recommendation - INV-2026-0034

**Seed:** `AKIAIOSFODNN7EXAMPLE` (iam_access_key)  
**Assessed confidence:** 85%

Response tier is selected from the strength of evidence held, not from the most severe reachable outcome. Reachable-but-unobserved paths justify hardening, never credential destruction.

## Tier 0 - monitor_and_collect

- **What it does:** Keep collecting; add the principal and infrastructure to a watchlist. No user-visible change.
- **Scope:** AKIAIOSFODNN7EXAMPLE
- **Rationale:** Skeptic confidence 85% (accepted). 0 identity path(s) observed in telemetry, 0 reachable but unobserved. The tier is set by what was witnessed, not by the most severe reachable outcome.
- **Proportionality:** Reachable-but-unobserved paths justify hardening, not credential destruction.
- **Reversible:** yes
- **Human approval:** not required

## Tier 0 - detection_deployment

- **What it does:** Deploy the generated Sigma and KQL rules in monitor-only mode for two weeks.
- **Scope:** SIGMA-AWS-IAM-001, KQL-AWS-IAM-001
- **Rationale:** Converts this investigation into durable coverage for iam_access_key reuse.
- **Proportionality:** Detection-only; no user-visible impact.
- **Reversible:** yes
- **Human approval:** not required

## Before acting

- Confirm the principal is not serving a production workload; key deactivation is reversible but the outage it causes is not.
- Preserve CloudTrail records and the evidence graph before any rotation, so the investigation remains reproducible.
- Record who approved each tier 3 or higher action and when.

## Rollback

- Key rotation: re-issue to the legitimate workload and monitor for failed calls.
- Trust tightening: revert the condition block from version control.
- Detections: disable the rule; logic is versioned in this repository.
