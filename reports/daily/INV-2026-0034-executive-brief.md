# Executive one-pager

**INV-2026-0034 - cloud credential misuse investigation**

## What happened

Adversary activity cluster leveraging compromised cloud assets (AKIAIOSFODNN7EXAMPLE, 198[\.]51[\.]100[\.]45) to execute automated recon, credential access, and potential storage exfiltration across targeted cloud tenants.

## How strongly we believe it

- Assessed confidence **85%** after an automated skeptic audit that penalises weak, stale, and single-source evidence.
- **0** findings are proven by raw telemetry records; **8** are inferred and carry lower confidence.
- We do not claim to know who is responsible. This is a linkage assessment.

## What we recommend

- **monitor and collect** (tier 0) - Reachable-but-unobserved paths justify hardening, not credential destruction.
- **detection deployment** (tier 0) - Detection-only; no user-visible impact.

## What it costs us to be wrong

- The highest recommended action is a configuration change with no credential impact, so the cost of being wrong is low.
- 0 claim(s) were demoted and 0 contradiction(s) remain unresolved.
- 2 evidence gap(s) are recorded and none are hidden.

## What changes as a result

- 2 detection rule(s) drafted for monitor-only deployment.
- The evidence graph and STIX bundle are retained so the assessment is reproducible.
