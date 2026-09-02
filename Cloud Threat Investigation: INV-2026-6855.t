🚨 Cloud Threat Investigation: INV-2026-6855

I recently completed an investigation into an adversary activity cluster involving potentially compromised cloud credentials and infrastructure.

The activity included:

🔍 Automated reconnaissance
🔑 Cloud credential access and reuse
☁️ Suspicious IAM and CloudTrail activity
📦 Potential cloud-storage collection and exfiltration
🌐 Connections to external IP and domain infrastructure

Key MITRE ATT&CK techniques mapped:

• T1078.004 — Valid Accounts: Cloud Accounts
• T1552.005 — Unsecured Credentials: Cloud Credentials
• T1530 — Data from Cloud Storage Object
• T1071.001 — Application Layer Protocol: Web Protocols

Competing explanations—including accidental developer-key exposure, CI/CD misconfiguration, and unrelated opportunistic scanning—were evaluated through an Analysis of Competing Hypotheses.

Final assessment: ACCEPTED
Confidence: 85%

The investigation also produced a Sigma detection rule and a Microsoft Sentinel KQL query to identify suspicious API activity associated with reused cloud credentials.

This case reinforced an important lesson: credential exposure is only the beginning of the investigation. Identity activity, source infrastructure, API behavior, storage access, and policy changes must be correlated to understand the true scope and intent.

Indicators have been sanitized for public sharing.

#CloudSecurity #ThreatIntelligence #IncidentResponse #CyberSecurity #AWS #Azure #MITREATTACK #CloudForensics #SOC #DetectionEngineering


# Cloud Campaign Evidence Graph Analyst Console

The Cloud Campaign Evidence Graph Analyst Console is a Streamlit-based investigation workspace for analyzing a cloud threat from a seed indicator. It brings the investigation narrative, evidence relationships, MITRE ATT&CK mappings, analytic challenge process, STIX 2.1 intelligence, and detection content into one interface.

Local application: [http://localhost:8501/](http://localhost:8501/)

> **Important:** The investigation currently displayed by the application uses documentation and test indicators, including the AWS example access key `AKIAIOSFODNN7EXAMPLE` and the reserved IP address ranges `198.51.100.0/24` and `203.0.113.0/24`. Do not treat these values as live indicators of compromise without replacing them with validated case data.

## Contents

- [What the application does](#what-the-application-does)
- [Investigation controls](#investigation-controls)
- [Investigation summary cards](#investigation-summary-cards)
- [Research Report](#1-research-report)
- [Evidence Graph](#2-evidence-graph)
- [ATT&CK Mappings](#3-mitre-attck-mappings)
- [Skeptic Audit](#4-skeptic-audit)
- [STIX 2.1 Bundle](#5-stix-21-bundle)
- [Detection Rules](#6-detection-rules)
- [Recommended investigation workflow](#recommended-investigation-workflow)
- [Interpreting confidence](#interpreting-confidence)
- [Operational guidance](#operational-guidance)
- [Current example investigation](#current-example-investigation)
- [Known limitations](#known-limitations)

## What the application does

The console accepts an investigation seed, identifies or uses its indicator type, and organizes the resulting analysis into six categories:

1. A human-readable research report.
2. A graph and timeline of observed entities and relationships.
3. MITRE ATT&CK technique mappings.
4. A skeptic review using competing hypotheses.
5. A machine-readable STIX 2.1 bundle.
6. Detection content in Sigma and KQL.

The interface is designed for threat intelligence analysts, SOC investigators, incident responders, detection engineers, and cloud security teams. Its outputs should support—not replace—source-log review, indicator validation, and analyst judgment.

## Investigation controls

The left sidebar contains the inputs used to begin an investigation.

### Seed Indicator

The initial observable or identifier around which the investigation is built. Examples may include:

- IAM access key ID
- IPv4 address
- Domain name
- URL
- File hash
- Cloud resource identifier
- User or service account identifier

Enter only the identifier required for analysis. Avoid entering secrets such as secret access keys, passwords, session tokens, private keys, or authentication cookies.

### Indicator Type

Specifies how the seed should be interpreted. The current interface supports an `auto` option, which delegates classification to the application. When an explicit matching type is available, use it to reduce ambiguity. The displayed example resolves to `iam_access_key`.

### Run Campaign Investigation

Starts the investigation using the current seed and type. A completed run refreshes the investigation identifier, confidence, review status, and the six output categories.

Before running a real investigation:

1. Confirm that the seed is correctly formatted.
2. Confirm that handling the indicator complies with your organization's data-handling policy.
3. Record the source and acquisition time of the indicator outside the console if chain of custody matters.
4. Treat generated conclusions as hypotheses until corroborated by primary telemetry.

## Investigation summary cards

Four cards remain visible above the category tabs.

### Investigation ID

A case reference used to correlate the console's outputs. The current example is `INV-2026-6855`. Use the same identifier in tickets, evidence notes, detection changes, and exported intelligence to preserve traceability.

### Seed Type

The normalized type assigned to the starting indicator. The current example is `iam_access_key`.

### Final Confidence

The overall confidence assigned after analysis and skeptic review. The current example is `85%`. This score expresses analytic confidence; it is not a mathematical probability that malicious activity occurred.

### Skeptic Status

The outcome of the adversarial review. The current value, `ACCEPTED`, means the primary assessment survived the application's current review checks. It does not mean every fact is independently verified or that the case is ready for automatic containment.

## 1. Research Report

The Research Report is the primary human-readable case narrative. It consolidates the most important conclusions and supporting context for analyst review, escalation, or handoff.

### Header metadata

The report begins with:

- Investigation ID
- Generation date and time
- Seed indicator and normalized type
- Final confidence score

Use this metadata to confirm that the report belongs to the intended run before quoting or distributing it.

### Executive Summary

Summarizes the suspected activity and likely objective. In the current example, the report describes a cluster using compromised cloud assets for automated reconnaissance, credential access, and possible cloud-storage exfiltration.

The executive summary is an analytic judgment, not raw evidence. Validate its components against authentication logs, CloudTrail or equivalent control-plane telemetry, storage access logs, identity configuration, DNS evidence, and network records.

### Analytical Judgments & Skeptic Audit

Shows whether the main assessment was accepted and provides a compact audit result. The current output reports:

- Status: `ACCEPTED`
- Final confidence: `85%`
- Prompt injections blocked: `0`
- Claims penalized: `0`
- Contradictions identified: `0`

These values describe the internal review outcome. A zero count does not prove that the source material is complete, authentic, or free of hidden assumptions.

### Competing Hypotheses / ACH Analysis

Lists reasonable alternatives to the primary malicious-activity hypothesis. The current investigation evaluates:

- Accidental developer-key exposure with no malicious use.
- A third-party CI/CD configuration error that exposed public read access.
- Unrelated opportunistic scanners using public cloud infrastructure rather than one coordinated actor.

Analysts should seek evidence that discriminates among these explanations. Useful examples include API sequencing, user-agent consistency, ASN and geography changes, role-assumption history, access timing, object volume, policy edits, and whether the same infrastructure appears across tenants.

### MITRE ATT&CK Cloud Mappings

Summarizes techniques associated with the assessed behavior. Treat mappings as labels for observed or inferred behavior, not proof of actor attribution.

### Evidence Graph & Timeline

Provides a text version of the key nodes, edges, and timestamps. Use it to identify pivot points and to confirm that every asserted relationship has a stated evidence basis.

### Detection Rules

Includes the generated Sigma and KQL content for convenient review. Production deployment should follow validation and tuning as described in the Detection Rules category.

## 2. Evidence Graph

The Evidence Graph category represents entities as nodes and evidence-backed connections as edges. The current example contains four nodes and three evidence relationships.

### Discovered Nodes

Nodes are the observables or entities found during the investigation. The current example contains:

| Type | Value | Purpose |
|---|---|---|
| IAM access key | `AKIAIOSFODNN7EXAMPLE` | Investigation seed and cloud identity pivot |
| IPv4 address | `198[.]51[.]100[.]45` | Source associated with identity API activity |
| IPv4 address | `203[.]0[.]113[.]88` | Source associated with storage API activity |
| Domain | `exfil-cloud-storage.net` | Network-infrastructure pivot |

Defanged IP notation is used in narrative output to reduce accidental activation. Convert it to normal notation only inside approved investigation tools.

### Evidence Edges

Edges describe how two nodes are related. Each relationship should be read together with its evidence description and confidence.

| Source | Relationship | Target | Stated evidence |
|---|---|---|---|
| Access key | `leveraged_by` | `198[.]51[.]100[.]45` | CloudTrail `AssumeRole` and `GetCallerIdentity` calls from the IP |
| `198[.]51[.]100[.]45` | `resolved_to` | `exfil-cloud-storage.net` | Passive DNS and TLS certificate colocation |
| Access key | `leveraged_by` | `203[.]0[.]113[.]88` | CloudTrail `S3 GetObject` and `PutBucketPolicy` calls |

Relationship labels describe the application's analytic model. When exporting to another platform, confirm that the destination supports custom relationship types or translate them to an approved vocabulary.

### Chronological Timeline

The timeline places first observations and relationships in time order. Use it to reconstruct activity sequences, identify gaps, and compare events with authentication, role, network, and storage telemetry.

All current example events share the report-generation timestamp. For a real investigation, distinguish at least:

- Event occurrence time
- Log ingestion time
- First-seen time
- Last-seen time
- Enrichment or report-generation time

Avoid inferring a real attack sequence when timestamps merely represent when objects were created in the report.

## 3. MITRE ATT&CK Mappings

This category maps assessed behavior to MITRE ATT&CK techniques for cloud environments. It helps standardize reporting, identify defensive coverage, and connect observations to detection and response playbooks.

### T1078.004 — Valid Accounts: Cloud Accounts

- Tactics: Initial Access / Defense Evasion
- Platforms shown: AWS / Azure IAM
- Confidence: 95%
- Interpretation: Valid cloud credentials may have been used to authenticate or operate under a legitimate identity.
- Validate with: sign-in records, CloudTrail identity fields, role assumptions, MFA context, credential creation dates, source IPs, user agents, session names, and baseline behavior.

### T1552.005 — Unsecured Credentials: Cloud Credentials

- Tactic: Credential Access
- Platforms shown: AWS S3 / Azure Key Vault / GitHub
- Confidence: 90%
- Interpretation: Cloud credentials may have been exposed in an insecure location or obtained by the actor.
- Validate with: source repositories, build logs, secret-scanning alerts, object permissions, key-vault audit logs, credential age, and evidence of unauthorized retrieval.

### T1530 — Data from Cloud Storage Object

- Tactics shown: Exfiltration / Collection
- Platforms shown: AWS S3 / Azure Blob Storage
- Confidence: 85%
- Interpretation: The activity may have accessed or collected data stored in cloud objects.
- Validate with: `GetObject` activity, object names and sensitivity, byte counts, request volume, storage access logs, data events, bucket policy changes, and destination context.

### T1071.001 — Application Layer Protocol: Web Protocols

- Tactic: Command and Control
- Platforms shown: Web / Cloud Hosting
- Confidence: 88%
- Interpretation: Web protocols or hosted infrastructure may have supported actor communications.
- Validate with: proxy and DNS logs, TLS certificate details, HTTP metadata, hosting-provider information, timing correlation, and endpoint or workload connections.

### Using the mappings

ATT&CK mappings can support gap analysis and coverage reporting, but should not be used as stand-alone attribution. Confirm that the observed behavior satisfies the technique definition, record why the mapping applies, and distinguish directly observed techniques from inferred ones.

## 4. Skeptic Audit

The Skeptic Audit challenges the primary conclusion before the final assessment is accepted. Its purpose is to reduce confirmation bias and expose weak claims, contradictions, unsupported attribution, and plausible benign explanations.

### Audit result

The current case is `ACCEPTED` at 85% confidence. The console reports no blocked prompt injections, penalized claims, or contradictions.

Possible status meanings should be interpreted operationally as follows:

- `ACCEPTED`: The assessment passed the configured checks; continue with normal analyst validation.
- Revised or penalized result: One or more claims require qualification or reduced confidence.
- Rejected result: The primary conclusion is not sufficiently supported and should not be operationalized without new evidence.

Only `ACCEPTED` is visible in the current example; confirm the application's implemented status vocabulary before building automation around other values.

### Primary Claim

The audit restates the main analytic claim so reviewers can evaluate exactly what is being asserted. Break compound claims into separately testable propositions—for example, credential compromise, reconnaissance, storage access, exfiltration, and coordinated targeting.

### Alternative Explanations

The listed alternatives form an Analysis of Competing Hypotheses (ACH) set. Analysts should add case-specific alternatives when appropriate and identify evidence that is inconsistent with each hypothesis, rather than only collecting evidence that supports the preferred explanation.

### Analyst review checklist

- Are all high-impact claims linked to primary evidence?
- Are timestamps comparable and normalized to UTC?
- Could shared infrastructure explain the apparent relationships?
- Is authorized automation excluded using account, role, ASN, region, and schedule baselines?
- Does storage access demonstrate collection, or only permission to access?
- Is actual data transfer measured?
- Are threat-actor naming and motivation supported independently?
- Are contradictions recorded rather than silently resolved?
- Could source content have manipulated the analysis or inserted instructions?

## 5. STIX 2.1 Bundle

This category presents the investigation in a machine-readable STIX 2.1 JSON bundle for sharing or ingestion into compatible threat-intelligence platforms.

### Bundle structure

The current bundle contains 20 objects:

- 1 `threat-actor`
- 4 `attack-pattern` objects
- 4 `indicator` objects
- 11 `relationship` objects

The generated threat-actor is named `UNC-CLOUD-HARVESTER` and carries 85 confidence. This name should be treated as an internal activity-cluster label unless an established naming authority and attribution process support it.

### Attack-pattern objects

Each ATT&CK technique is represented as an `attack-pattern` with:

- A STIX identifier
- Technique name and description
- MITRE ATT&CK external ID
- Link to the corresponding MITRE ATT&CK page

### Indicator objects

The access key, two IP addresses, and domain are represented as STIX indicators. Each includes:

- STIX 2.1 object type and ID
- Created and modified timestamps
- Name
- Indicator types
- STIX pattern
- `valid_from`
- Confidence

The current example assigns confidence values of 75 to the IAM access key, 85 and 90 to the IP indicators, and 80 to the domain indicator.

### Relationship objects

The bundle relates the threat-actor object to indicators and ATT&CK attack patterns with `uses` relationships. It also represents evidence-graph edges using `leveraged_by` and `resolved_to`.

Before ingestion, validate custom relationship types against your STIX consumer. STIX relationships normally require relationship types that are meaningful for the source and target object types, and some platforms may reject or ignore unsupported custom values.

### Validation and sharing checklist

1. Validate the JSON syntax and bundle against STIX 2.1 requirements.
2. Confirm all UUIDs and object references are valid and unique.
3. Confirm timestamps use an accepted STIX timestamp format.
4. Test every indicator pattern with a STIX pattern validator.
5. Verify the semantics of every relationship.
6. Remove or mark test data before sharing.
7. Apply appropriate markings, handling caveats, or TLP labels.
8. Confirm that confidence values follow the receiving platform's scale.
9. Import into a non-production collection first.
10. Preserve the investigation ID in labels or external references if cross-system traceability is required.

## 6. Detection Rules

The Detection Rules category provides content that defenders can adapt for monitoring and hunting.

### Sigma rule

The generated Sigma rule detects CloudTrail activity where `userIdentity.accessKeyId` equals the investigated key.

Key properties:

- Product: AWS
- Service: CloudTrail
- Status: Experimental
- Severity: High
- ATT&CK tag: `attack.t1078.004`
- Known false-positive class: authorized cloud-infrastructure automation

The current selection only matches the access key. Although the description mentions unapproved ASNs, no ASN condition is present in the displayed rule. Treat the description-to-logic mismatch as a required tuning item before deployment.

Example rule:

```yaml
title: Suspicious API Activity from Compromised Cloud Credentials
id: c1a7a0b1-4b89-4e5c-9c12-3a5678901234
status: experimental
description: Detects API calls originating from a known compromised IAM access key.
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

Before production use:

- Replace the example key with a validated case indicator or parameterized watchlist.
- Confirm field mappings for the target SIEM backend.
- Add the intended approved/unapproved ASN logic or revise the description.
- Consider event names, recipient accounts, regions, user agents, error codes, role ARNs, and session context.
- Add a time-bound validity period for volatile indicators.
- Test against representative CloudTrail events.
- Document expected volume and false positives.
- Route matches through an approved triage playbook.

### KQL investigation query

The KQL query searches `AWSCloudTrail` for the access key, groups activity by source IP, API event, and user identity ARN, then reports the first and last event time and total count.

```kusto
AWSCloudTrail
| where AccessKeyId == "AKIAIOSFODNN7EXAMPLE"
| summarize
    Count = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by SourceIPAddress, EventName, UserIdentityArn
| order by Count desc
```

Use the query to answer:

- Which source IPs used the key?
- Which API calls were made?
- Which identity or role context was involved?
- When was each activity cluster first and last observed?
- Which combinations produced the highest volume?

Before using it, confirm that your Sentinel or Defender connector populates the displayed table and field names. Schema mappings vary by ingestion method. Add tenant/account, region, user agent, error code, and session issuer fields where available. Limit the time range to the relevant investigation window.

## Recommended investigation workflow

1. **Prepare the seed.** Validate its type, provenance, and handling classification.
2. **Run the investigation.** Submit the seed using `auto` or a specific indicator type.
3. **Confirm the case header.** Check the investigation ID, seed type, confidence, and audit status.
4. **Read the Research Report.** Identify the primary claim and all material subclaims.
5. **Inspect the Evidence Graph.** Verify nodes, relationships, timestamps, and evidence descriptions.
6. **Challenge the conclusion.** Use the Skeptic Audit and add missing benign or competing explanations.
7. **Validate ATT&CK mappings.** Separate observed behavior from inferred technique use.
8. **Run the KQL hunt.** Confirm identity usage, API behavior, source infrastructure, and time boundaries.
9. **Tune the Sigma rule.** Align its logic, description, environment baselines, and alert routing.
10. **Validate the STIX bundle.** Check syntax, semantics, markings, confidence, and consumer compatibility.
11. **Decide response actions.** Base containment on confirmed evidence and organizational policy, not generated confidence alone.
12. **Document disposition.** Record confirmed malicious activity, benign explanation, inconclusive result, or required follow-up.

## Interpreting confidence

Confidence appears at the investigation, technique, indicator, and relationship levels. These scores describe the strength of the application's assessment and may measure different claims.

Suggested interpretation:

| Range | Practical meaning |
|---|---|
| 0–39 | Low confidence; substantial uncertainty or weak corroboration |
| 40–69 | Moderate confidence; plausible but meaningful gaps remain |
| 70–89 | High confidence; supported by multiple consistent signals |
| 90–100 | Very high confidence; strongly corroborated, but still subject to source quality |

This scale is guidance for readers of this README, not a confirmed description of the application's internal scoring algorithm. Do not average scores or compare them across object types unless the implementation defines that behavior.

## Operational guidance

### Immediate triage for a genuinely exposed cloud credential

- Disable or rotate the credential using your approved incident-response procedure.
- Preserve identity and control-plane logs before retention windows expire.
- Identify all principals, roles, sessions, and resources reachable by the credential.
- Review recent policy, trust-policy, access-key, and storage-permission changes.
- Search for object reads, writes, listings, deletions, and bulk-transfer patterns.
- Review activity across accounts, regions, tenants, and federated identity providers.
- Compare source IPs, ASNs, geographies, and user agents with authorized automation.
- Check repositories, CI/CD systems, logs, tickets, and storage locations for the exposure source.
- Scope downstream credentials or sessions created using the compromised identity.
- Record containment times so post-containment activity can be identified.

### Safe handling

- Never paste secret key material into the seed field.
- Treat reports and STIX bundles as potentially sensitive security data.
- Defang indicators in human-facing documents when appropriate.
- Apply organizational sharing markings before external distribution.
- Avoid publishing real access key IDs, internal ARNs, tenant IDs, bucket names, or customer data.

## Current example investigation

| Field | Value |
|---|---|
| Investigation ID | `INV-2026-6855` |
| Seed indicator | `AKIAIOSFODNN7EXAMPLE` |
| Seed type | `iam_access_key` |
| Final confidence | 85% |
| Skeptic status | `ACCEPTED` |
| Evidence nodes | 4 |
| Evidence edges | 3 |
| ATT&CK mappings | 4 |
| STIX objects | 20 |
| Detection formats | Sigma and KQL |

The primary example assessment describes credential reuse, reconnaissance, possible storage collection or exfiltration, and related web infrastructure. Because the indicators are examples or reserved documentation values, this case is suitable for demonstration and workflow testing, not real-world blocking or attribution.

## Known limitations

- The visible interface does not expose the application's data-source connectors, enrichment providers, scoring formula, retention behavior, or run history.
- `ACCEPTED` indicates review completion, not independent verification of every claim.
- The example timeline uses a common timestamp and should not be treated as a proven event sequence.
- The report uses a named threat-actor object, but the visible evidence does not independently establish attribution.
- Potential data exfiltration is an inference unless object access and transfer volume are confirmed.
- Passive DNS and certificate colocation can reflect shared hosting and require corroboration.
- The Sigma description references unapproved ASNs, but its displayed detection logic does not filter on ASN.
- The STIX bundle should be schema- and semantics-validated before exchange or ingestion.
- The console's generated detections require environment-specific field mapping, tuning, and testing.

## Analyst sign-off checklist

- [ ] Seed provenance recorded
- [ ] Sensitive values removed or appropriately protected
- [ ] Primary telemetry preserved
- [ ] Every high-impact claim corroborated
- [ ] Alternative hypotheses evaluated
- [ ] Timeline timestamps normalized and interpreted correctly
- [ ] ATT&CK mappings reviewed
- [ ] Sigma logic tested and tuned
- [ ] KQL schema validated
- [ ] STIX bundle validated and marked
- [ ] Containment decisions approved under organizational policy
- [ ] Final disposition and residual uncertainty documented


