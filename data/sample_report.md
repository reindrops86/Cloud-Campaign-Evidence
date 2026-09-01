# Cloud Threat Investigation Report: INV-2026-7361
**Date:** 2026-09-01T22:00:29+00:00  |  **Seed Indicator:** `AKIAIOSFODNN7EXAMPLE` (`iam_access_key`)  |  **Confidence Score:** 85%

## Executive Summary
Adversary activity cluster leveraging compromised cloud assets (AKIAIOSFODNN7EXAMPLE, 198.51.100.45) to execute automated recon, credential access, and potential storage exfiltration across targeted cloud tenants.

## Analytical Judgments & Skeptic Audit
**Review Status:** `ACCEPTED`
- **Analyst Feedback:** Review complete. Status: ACCEPTED. Final Confidence: 85%. Audited 4 nodes and 3 edges.

## Competing Hypotheses (ACH Analysis)
### Alternative Explanations Evaluated
- Legitimate developer key leakage without malicious exploitation (false positive alert trigger).
- Third-party CI/CD automation tool misconfiguration exposing public read permissions.
- Independent opportunistic scanner activity reusing public cloud infrastructure rather than a single coordinated campaign.

## MITRE ATT&CK Cloud Mappings
- **[T1078.004] Valid Accounts: Cloud Accounts** (Initial Access / Defense Evasion) - Platform: `AWS / Azure IAM` (Confidence: 95%)
- **[T1552.005] Unsecured Credentials: Cloud Credentials** (Credential Access) - Platform: `AWS S3 / Azure Key Vault / GitHub` (Confidence: 90%)
- **[T1530] Data from Cloud Storage Object** (Exfiltration / Collection) - Platform: `AWS S3 / Azure Blob Storage` (Confidence: 85%)
- **[T1071.001] Application Layer Protocol: Web Protocols** (Command and Control) - Platform: `Web / Cloud Hosting` (Confidence: 88%)

## Evidence Graph & Timeline
- `2026-09-01T22:00:29+00:00`: First observed iam_access_key (AKIAIOSFODNN7EXAMPLE)
- `2026-09-01T22:00:29+00:00`: First observed ip (198[\.]51[\.]100[\.]45)
- `2026-09-01T22:00:29+00:00`: First observed ip (203[\.]0[\.]113[\.]88)
- `2026-09-01T22:00:29+00:00`: First observed domain (exfil-cloud-storage.net)
- `2026-09-01T22:00:29+00:00`: Relationship [leveraged_by]: AKIAIOSFODNN7EXAMPLE -> 198[\.]51[\.]100[\.]45 (CloudTrail AssumeRole / GetCallerIdentity API calls from IP)
- `2026-09-01T22:00:29+00:00`: Relationship [resolved_to]: 198[\.]51[\.]100[\.]45 -> exfil-cloud-storage.net (Passive DNS resolution & TLS cert colocation)
- `2026-09-01T22:00:29+00:00`: Relationship [leveraged_by]: AKIAIOSFODNN7EXAMPLE -> 203[\.]0[\.]113[\.]88 (CloudTrail S3 GetObject & PutBucketPolicy calls)

## Detection Rules
### Suspicious API Activity from Compromised Cloud Credentials (Sigma)
```yaml
title: Suspicious API Activity from Compromised Cloud Credentials
id: c1a7a0b1-4b89-4e5c-9c12-3a5678901234
status: experimental
description: Detects API calls originating from known compromised IAM access key AKIAIOSFODNN7EXAMPLE across unapproved ASNs.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.accessKeyId: 'AKIAIOSFODNN7EXAMPLE'
  condition: selection
falsepositives:
  - Authorized cloud infrastructure automation scripts.
level: high
tags:
  - attack.initial_access
  - attack.t1078.004

```

### CloudTrail IAM Key Reuse Investigation Query (KQL)
```yaml
// KQL Query for Sentinel / Defender for Cloud
AWSCloudTrail
| where AccessKeyId == "AKIAIOSFODNN7EXAMPLE"
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by SourceIPAddress, EventName, UserIdentityArn
| order by Count desc

```
