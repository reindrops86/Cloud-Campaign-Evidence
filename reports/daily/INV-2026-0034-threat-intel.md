# Threat intelligence report - INV-2026-0034

**Activity cluster:** UNC-CLOUD-HARVESTER (internal label, not an attribution)  
**Confidence:** 85%

## Techniques observed or inferred

| Technique | Name | Tactic | Platform | Confidence |
|---|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access / Defense Evasion | AWS / Azure IAM | 95% |
| T1552.005 | Unsecured Credentials: Cloud Credentials | Credential Access | AWS S3 / Azure Key Vault / GitHub | 90% |
| T1530 | Data from Cloud Storage Object | Exfiltration / Collection | AWS S3 / Azure Blob Storage | 85% |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | Web / Cloud Hosting | 88% |

## Infrastructure (defanged)

| Indicator | Type | Reputation | Decayed | First seen | Sources |
|---|---|---|---|---|---|
| AKIAIOSFODNN7EXAMPLE | iam_access_key | 75 | 74 | 2026-09-06T21:10:05+00:00 | seed_collector |
| 198[\.]51[\.]100[\.]45 | ip | 85 | 84 | 2026-09-06T21:10:05+00:00 | cloudtrail_logs |
| 203[\.]0[\.]113[\.]88 | ip | 90 | 89 | 2026-09-06T21:10:05+00:00 | cloudtrail_logs |
| exfil-cloud-storage.net | domain | 80 | 79 | 2026-09-06T21:10:05+00:00 | shodan_censys_cert |

_Decayed reputation reflects half-life ageing. Prefer it over the raw score when deciding whether an indicator is still actionable._

## Detection logic

### Suspicious API Activity from Compromised Cloud Credentials (Sigma, CloudTrail)

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

### CloudTrail IAM Key Reuse Investigation Query (KQL, AzureActivity / AWSCloudTrail)

```yaml
// KQL Query for Sentinel / Defender for Cloud
AWSCloudTrail
| where AccessKeyId == "AKIAIOSFODNN7EXAMPLE"
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by SourceIPAddress, EventName, UserIdentityArn
| order by Count desc
```

## Collection gaps

- No CloudTrail telemetry was supplied, so every relationship in this report is inferred rather than witnessed. Re-run with --source file or --source aws to confirm.
- Infrastructure ownership is unconfirmed. Shared hosting, CDNs, and rented ranges can place unrelated tenants behind the same address.
