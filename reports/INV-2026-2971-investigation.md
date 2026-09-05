# Investigation report INV-2026-2971

**Seed indicator:** `AKIACOMPROMISEDKEY01` (iam_access_key)  
**Date:** 2026-09-05T21:34:38+00:00  
**Skeptic status:** ACCEPTED  
**Assessed confidence:** 85%

> Indicators are defanged. This report separates what was observed in telemetry from what was inferred, and makes no identity attribution.

## 1. Summary

Adversary activity cluster leveraging compromised cloud assets (AKIACOMPROMISEDKEY01, AKIACOMPROMISEDKEY01) to execute automated recon, credential access, and potential storage exfiltration across targeted cloud tenants.

The evidence graph holds 13 entities and 11 relationships. Across relationships, attack paths, and technique mappings, 14 finding(s) are backed by a raw telemetry record and 6 are reasoned.

## 2. Observations

Each row below is proven by a specific telemetry record.

| Statement | Evidence records |
|---|---|
| AKIACOMPROMISEDKEY01 -> 198[\.]51[\.]100[\.]45 (observed_from): CloudTrail GetCallerIdentity from 198[\.]51[\.]100[\.]45 | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000001, cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000002 |
| AKIACOMPROMISEDKEY01 -> sts:GetCallerIdentity (performed): CloudTrail event c9d3e5a7-2222-4b3c-8d4e-000000000001 | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000001 |
| AKIACOMPROMISEDKEY01 -> iam:ListAttachedUserPolicies (performed): CloudTrail event c9d3e5a7-2222-4b3c-8d4e-000000000002 | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000002 |
| AKIACOMPROMISEDKEY01 -> 203[\.]0[\.]113[\.]88 (observed_from): CloudTrail AssumeRole from 203[\.]0[\.]113[\.]88 | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000003, cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000004, cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000005 |
| AKIACOMPROMISEDKEY01 -> sts:AssumeRole (performed): CloudTrail event c9d3e5a7-2222-4b3c-8d4e-000000000003 | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000003 |
| sts:AssumeRole -> arn:aws:iam::111122223333:role/prod-data-reader (affected): CloudTrail AssumeRole targeted arn:aws:iam::111122223333:role/prod-data-reader | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000003 |
| AKIACOMPROMISEDKEY01 -> secretsmanager:GetSecretValue (performed): CloudTrail event c9d3e5a7-2222-4b3c-8d4e-000000000004 | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000004 |
| secretsmanager:GetSecretValue -> arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db/master-AbC123 (affected): CloudTrail GetSecretValue targeted arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db/master-AbC123 | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000004 |
| AKIACOMPROMISEDKEY01 -> iam:CreateAccessKey (performed): CloudTrail event c9d3e5a7-2222-4b3c-8d4e-000000000005 | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000005 |
| AKIACOMPROMISEDKEY01 -> cloudtrail:StopLogging (performed): CloudTrail event c9d3e5a7-2222-4b3c-8d4e-000000000006 | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000006 |
| cloudtrail:StopLogging -> arn:aws:cloudtrail:us-east-1:111122223333:trail/org-audit-trail (affected): CloudTrail StopLogging targeted arn:aws:cloudtrail:us-east-1:111122223333:trail/org-audit-trail | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000006 |
| deploy-svc → sts:AssumeRole on arn:aws:iam::111122223333:role/prod-data-reader was exercised (risk 100/100). | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000003 |
| deploy-svc → secretsmanager:GetSecretValue on arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/* was exercised (risk 100/100). | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000004 |
| deploy-svc → iam:CreateAccessKey on arn:aws:iam::111122223333:user/deploy-svc was exercised (risk 95/100). | cloudtrail-c9d3e5a7-2222-4b3c-8d4e-000000000005 |

## 3. Inferences

Each row below is a conclusion, not a record. Confidence is stated explicitly.

| Statement | Confidence | Basis |
|---|---|---|
| deploy-svc → kms:Decrypt on arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/* is reachable but was not observed being used. | 0.95 | Base risk for secret_access: 65; Path pivots through an assumable role (+10) |
| deploy-svc → s3:GetObject on arn:aws:s3:::prod-artifacts/* is reachable but was not observed being used. | 0.75 | Base risk for storage_access: 55; Wildcard resource scope broadens blast radius (+10) |
| deploy-svc → s3:ListBucket on arn:aws:s3:::prod-artifacts/* is reachable but was not observed being used. | 0.75 | Base risk for storage_access: 55; Wildcard resource scope broadens blast radius (+10) |
| [T1078.004] Valid Accounts: Cloud Accounts (Initial Access / Defense Evasion). | 0.95 | platform: AWS / Azure IAM |
| [T1552.005] Unsecured Credentials: Cloud Credentials (Credential Access). | 0.90 | platform: AWS S3 / Azure Key Vault / GitHub |
| Adversary activity cluster leveraging compromised cloud assets (AKIACOMPROMISEDKEY01, AKIACOMPROMISEDKEY01) to execute automated recon, credential access, and potential storage exfiltration across targeted cloud tenants. | 0.85 | campaign hypothesis after skeptic audit |

## 4. Attribution position

- No identity attribution is made. 'UNC-CLOUD-HARVESTER' is an internal cluster label for this activity, not a claim about a named group, and carries no assertion about who controls the infrastructure.

## 5. Identity attack paths

| Path | Category | Status | Risk | Rationale |
|---|---|---|---|---|
| deploy-svc → sts:AssumeRole on arn:aws:iam::111122223333:role/prod-data-reader | privilege_escalation | OBSERVED | 100/100 | Base risk for privilege_escalation: 75; CloudTrail confirms the action was invoked (+25) |
| deploy-svc → secretsmanager:GetSecretValue on arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/* | secret_access | OBSERVED | 100/100 | Base risk for secret_access: 65; CloudTrail confirms the action was invoked (+25) |
| deploy-svc → iam:CreateAccessKey on arn:aws:iam::111122223333:user/deploy-svc | credential_creation | OBSERVED | 95/100 | Base risk for credential_creation: 70; CloudTrail confirms the action was invoked (+25) |
| deploy-svc → kms:Decrypt on arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/* | secret_access | POTENTIAL | 95/100 | Base risk for secret_access: 65; Path pivots through an assumable role (+10) |
| deploy-svc → s3:GetObject on arn:aws:s3:::prod-artifacts/* | storage_access | POTENTIAL | 75/100 | Base risk for storage_access: 55; Wildcard resource scope broadens blast radius (+10) |
| deploy-svc → s3:ListBucket on arn:aws:s3:::prod-artifacts/* | storage_access | POTENTIAL | 75/100 | Base risk for storage_access: 55; Wildcard resource scope broadens blast radius (+10) |
| deploy-svc → ssm:GetParameter on arn:aws:ssm:us-east-1:111122223333:parameter/deploy/* | secret_access | UNRESOLVED | 60/100 | Base risk for secret_access: 65; Policy conditions could not be evaluated (-15) |
| deploy-svc → cloudtrail:StopLogging on * | defense_impairment | BLOCKED | 40/100 | Base risk for defense_impairment: 80; Explicit deny or permissions boundary blocks this path (-50) |
| deploy-svc → cloudtrail:DeleteTrail on * | defense_impairment | BLOCKED | 40/100 | Base risk for defense_impairment: 80; Explicit deny or permissions boundary blocks this path (-50) |

_3 observed, 3 reachable but unobserved, 2 blocked._

## 6. Competing explanations

| Alternative explanation |
|---|
| Legitimate developer key leakage without malicious exploitation (false positive alert trigger). |
| Third-party CI/CD automation tool misconfiguration exposing public read permissions. |
| Independent opportunistic scanner activity reusing public cloud infrastructure rather than a single coordinated campaign. |

## 7. Skeptic audit

Skeptic Audit complete. Status: ACCEPTED. Final Confidence: 85%. Injections Blocked: 0. Penalized 0 claims & 0 contradictions.

## 8. Evidence gaps

- Only management events were available. Object-level access to storage cannot be confirmed or excluded without data-event logging.
- Infrastructure ownership is unconfirmed. Shared hosting, CDNs, and rented ranges can place unrelated tenants behind the same address.

## 9. Recommended response

| Tier | Action | Scope | Reversible | Approval | Rationale |
|---|---|---|---|---|---|
| 3 | revoke_sessions_and_disable_key | AKIACOMPROMISEDKEY01 | yes | required | Skeptic confidence 85% (accepted). 3 identity path(s) observed in telemetry, 3 reachable but unobserved. The tier is set by what was witnessed, not by the most severe reachable outcome. |
| 0 | detection_deployment | SIGMA-AWS-IAM-001, KQL-AWS-IAM-001 | yes | not required | Converts this investigation into durable coverage for iam_access_key reuse. |

## 10. Limitations

- Confidence is a rule-based score, not a calibrated probability.
- Reachability is computed from policy evaluation and may miss conditions that only resolve at request time.
- Absence of an observation is not evidence of absence; it may reflect logging coverage.
