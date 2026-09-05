# Threat intelligence report - INV-2026-6941

**Activity cluster:** UNC-CLOUD-HARVESTER (internal label, not an attribution)  
**Confidence:** 85%

## Techniques observed or inferred

| Technique | Name | Tactic | Platform | Confidence |
|---|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access / Defense Evasion | AWS / Azure IAM | 95% |
| T1552.005 | Unsecured Credentials: Cloud Credentials | Credential Access | AWS S3 / Azure Key Vault / GitHub | 90% |

## Infrastructure (defanged)

| Indicator | Type | Reputation | Decayed | First seen | Sources |
|---|---|---|---|---|---|
| AKIACOMPROMISEDKEY01 | iam_access_key | 75 | 74 | 2026-09-05T20:56:53+00:00 | seed_collector |
| AKIACOMPROMISEDKEY01 | iam_access_key | 75 | 70 | 2026-08-28T21:14:02Z | aws_cloudtrail |
| 198[\.]51[\.]100[\.]45 | ip | 50 | 47 | 2026-08-28T21:14:02Z | aws_cloudtrail |
| sts:GetCallerIdentity | aws_action | 40 | 37 | 2026-08-28T21:14:02Z | aws_cloudtrail |
| iam:ListAttachedUserPolicies | aws_action | 40 | 37 | 2026-08-28T21:16:37Z | aws_cloudtrail |
| 203[\.]0[\.]113[\.]88 | ip | 50 | 47 | 2026-08-28T21:22:15Z | aws_cloudtrail |
| sts:AssumeRole | aws_action | 40 | 37 | 2026-08-28T21:22:15Z | aws_cloudtrail |
| arn:aws:iam::111122223333:role/prod-data-reader | aws_resource | 30 | 28 | 2026-08-28T21:22:15Z | aws_cloudtrail |
| secretsmanager:GetSecretValue | aws_action | 40 | 37 | 2026-08-28T21:24:48Z | aws_cloudtrail |
| arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db/master-AbC123 | aws_resource | 30 | 28 | 2026-08-28T21:24:48Z | aws_cloudtrail |
| iam:CreateAccessKey | aws_action | 40 | 37 | 2026-08-28T21:31:09Z | aws_cloudtrail |
| cloudtrail:StopLogging | aws_action | 40 | 37 | 2026-08-28T21:38:52Z | aws_cloudtrail |
| arn:aws:cloudtrail:us-east-1:111122223333:trail/org-audit-trail | aws_resource | 30 | 28 | 2026-08-28T21:38:52Z | aws_cloudtrail |

_Decayed reputation reflects half-life ageing. Prefer it over the raw score when deciding whether an indicator is still actionable._

## Detection logic

### Suspicious API Activity from Compromised Cloud Credentials (Sigma, CloudTrail)

```yaml
title: Suspicious API Activity from Compromised Cloud Credentials
id: c1a7a0b1-4b89-4e5c-9c12-3a5678901234
status: experimental
description: Detects API calls originating from known compromised IAM access key AKIACOMPROMISEDKEY01 across unapproved ASNs.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.accessKeyId: 'AKIACOMPROMISEDKEY01'
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
| where AccessKeyId == "AKIACOMPROMISEDKEY01"
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by SourceIPAddress, EventName, UserIdentityArn
| order by Count desc
```

## Collection gaps

- Only management events were available. Object-level access to storage cannot be confirmed or excluded without data-event logging.
- Infrastructure ownership is unconfirmed. Shared hosting, CDNs, and rented ranges can place unrelated tenants behind the same address.
