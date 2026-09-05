# Response recommendation - INV-2026-6941

**Seed:** `AKIACOMPROMISEDKEY01` (iam_access_key)  
**Assessed confidence:** 85%

Response tier is selected from the strength of evidence held, not from the most severe reachable outcome. Reachable-but-unobserved paths justify hardening, never credential destruction.

## Tier 3 - revoke_sessions_and_disable_key

- **What it does:** Deactivate the access key and revoke active role sessions issued before the cut-off.
- **Scope:** AKIACOMPROMISEDKEY01
- **Rationale:** Skeptic confidence 85% (accepted). 3 identity path(s) observed in telemetry, 3 reachable but unobserved. The tier is set by what was witnessed, not by the most severe reachable outcome.
- **Proportionality:** Containment is limited to the principal with observed misuse.
- **Reversible:** yes
- **Human approval:** required

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
