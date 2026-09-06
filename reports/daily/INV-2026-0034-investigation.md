# Investigation report INV-2026-0034

**Seed indicator:** `AKIAIOSFODNN7EXAMPLE` (iam_access_key)  
**Date:** 2026-09-06T21:10:05+00:00  
**Skeptic status:** ACCEPTED  
**Assessed confidence:** 85%

> Indicators are defanged. This report separates what was observed in telemetry from what was inferred, and makes no identity attribution.

## 1. Summary

Adversary activity cluster leveraging compromised cloud assets (AKIAIOSFODNN7EXAMPLE, 198[\.]51[\.]100[\.]45) to execute automated recon, credential access, and potential storage exfiltration across targeted cloud tenants.

The evidence graph holds 4 entities and 3 relationships. Across relationships, attack paths, and technique mappings, 0 finding(s) are backed by a raw telemetry record and 8 are reasoned.

## 2. Observations

Each row below is proven by a specific telemetry record.

_None recorded._

## 3. Inferences

Each row below is a conclusion, not a record. Confidence is stated explicitly.

| Statement | Confidence | Basis |
|---|---|---|
| AKIAIOSFODNN7EXAMPLE -> 198[\.]51[\.]100[\.]45 (leveraged_by): CloudTrail AssumeRole / GetCallerIdentity API calls from IP | 0.95 | graph relationship without a corroborating raw event |
| 198[\.]51[\.]100[\.]45 -> exfil-cloud-storage.net (resolved_to): Passive DNS resolution & TLS cert colocation | 0.85 | graph relationship without a corroborating raw event |
| AKIAIOSFODNN7EXAMPLE -> 203[\.]0[\.]113[\.]88 (leveraged_by): CloudTrail S3 GetObject & PutBucketPolicy calls | 0.90 | graph relationship without a corroborating raw event |
| [T1078.004] Valid Accounts: Cloud Accounts (Initial Access / Defense Evasion). | 0.95 | platform: AWS / Azure IAM |
| [T1552.005] Unsecured Credentials: Cloud Credentials (Credential Access). | 0.90 | platform: AWS S3 / Azure Key Vault / GitHub |
| [T1530] Data from Cloud Storage Object (Exfiltration / Collection). | 0.85 | platform: AWS S3 / Azure Blob Storage |
| [T1071.001] Application Layer Protocol: Web Protocols (Command and Control). | 0.88 | platform: Web / Cloud Hosting |
| Adversary activity cluster leveraging compromised cloud assets (AKIAIOSFODNN7EXAMPLE, 198[\.]51[\.]100[\.]45) to execute automated recon, credential access, and potential storage exfiltration across targeted cloud tenants. | 0.85 | campaign hypothesis after skeptic audit |

## 4. Attribution position

- No identity attribution is made. 'UNC-CLOUD-HARVESTER' is an internal cluster label for this activity, not a claim about a named group, and carries no assertion about who controls the infrastructure.

## 6. Competing explanations

| Alternative explanation |
|---|
| Legitimate developer key leakage without malicious exploitation (false positive alert trigger). |
| Third-party CI/CD automation tool misconfiguration exposing public read permissions. |
| Independent opportunistic scanner activity reusing public cloud infrastructure rather than a single coordinated campaign. |

## 7. Skeptic audit

Skeptic Audit complete. Status: ACCEPTED. Final Confidence: 85%. Injections Blocked: 0. Penalized 0 claims & 0 contradictions.

## 8. Evidence gaps

- No CloudTrail telemetry was supplied, so every relationship in this report is inferred rather than witnessed. Re-run with --source file or --source aws to confirm.
- Infrastructure ownership is unconfirmed. Shared hosting, CDNs, and rented ranges can place unrelated tenants behind the same address.

## 9. Recommended response

| Tier | Action | Scope | Reversible | Approval | Rationale |
|---|---|---|---|---|---|
| 0 | monitor_and_collect | AKIAIOSFODNN7EXAMPLE | yes | not required | Skeptic confidence 85% (accepted). 0 identity path(s) observed in telemetry, 0 reachable but unobserved. The tier is set by what was witnessed, not by the most severe reachable outcome. |
| 0 | detection_deployment | SIGMA-AWS-IAM-001, KQL-AWS-IAM-001 | yes | not required | Converts this investigation into durable coverage for iam_access_key reuse. |

## 10. Limitations

- Confidence is a rule-based score, not a calibrated probability.
- Reachability is computed from policy evaluation and may miss conditions that only resolve at request time.
- Absence of an observation is not evidence of absence; it may reflect logging coverage.
