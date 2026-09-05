# Executive one-pager

**INV-2026-2971 - cloud credential misuse investigation**

## What happened

Adversary activity cluster leveraging compromised cloud assets (AKIACOMPROMISEDKEY01, AKIACOMPROMISEDKEY01) to execute automated recon, credential access, and potential storage exfiltration across targeted cloud tenants.

## How strongly we believe it

- Assessed confidence **85%** after an automated skeptic audit that penalises weak, stale, and single-source evidence.
- **14** findings are proven by raw telemetry records; **6** are inferred and carry lower confidence.
- **3** privilege path(s) were actually exercised; **3** were reachable but never used.
- We do not claim to know who is responsible. This is a linkage assessment.

## What we recommend

- **revoke sessions and disable key** (tier 3) - Containment is limited to the principal with observed misuse.
- **detection deployment** (tier 0) - Detection-only; no user-visible impact.

## What it costs us to be wrong

- The highest recommended action disables a credential. If the principal serves production, this causes an outage, so it requires named human approval.
- 0 claim(s) were demoted and 0 contradiction(s) remain unresolved.
- 2 evidence gap(s) are recorded and none are hidden.

## What changes as a result

- 2 detection rule(s) drafted for monitor-only deployment.
- The evidence graph and STIX bundle are retained so the assessment is reproducible.
