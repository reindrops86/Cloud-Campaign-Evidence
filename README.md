# 🛡️ Cloud Campaign Evidence Graph

> **Defensible, Agentic Cloud Threat Intelligence Pipeline & STIX 2.1 Graph Generator**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![STIX 2.1 Compliant](https://img.shields.io/badge/STIX-2.1%20Validated-brightgreen.svg)](https://oasis-open.github.io/cti-documentation/stix/intro.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Benchmark Evaluation](https://img.shields.io/badge/Benchmark-100%25%20Pass%20(20%2F20)-success.svg)](eval/evaluation_report.json)
[![Deception Resilience](https://img.shields.io/badge/Deception--Resilience-100%25%20Pass%20(8%2F8)-success.svg)](eval/deception_evaluation_report.json)
[![CI/CD Pipeline](https://img.shields.io/badge/CI%2FCD-Passing-brightgreen.svg)](.github/workflows/ci.yml)

## Pipeline Architecture

```
Seed Indicator (Domain, IP, Hash, IAM Access Key, Container Digest, GitHub Repo)
      │
      ▼
Collector Agent (queries CTI wrappers, normalizes, defangs, deduplicates)
      │
      ▼
Evidence Graph & Timeline Engine (deterministic nodes, edges, half-life decay)
      │
      ▼
Enrichment Analyst Agent (correlates domains, IPs, certs, hashes, vulns)
      │
      ▼
Cloud-TTP Analyst Agent (maps to AWS, Azure, K8s, IAM, OAuth, CI/CD abuse)
      │
      ▼
Hypothesis Analyst Agent (proposes campaign explanations & alternatives)
      │
      ▼
Skeptic / Reviewer Agent (audits claims, flags circular reporting, rejects weak links)
      │
      ▼
Report & Artifact Generator (STIX 2.1 bundle, Sigma/KQL rules, markdown report)
```

## Agent Roles & Responsibilities

- **Collector:** Ingests seed indicators, normalizes IOCs, deduplicates entities, and preserves raw evidence provenance.
- **Enrichment Analyst:** Discovers cross-indicator relationships (passive DNS, certificate transparency, IP colocation, hash rep).
- **Cloud-TTP Analyst:** Maps findings to MITRE ATT&CK Cloud Matrix (AWS, Azure, K8s, IAM, OAuth, CI/CD).
- **Hypothesis Analyst:** Proposes primary campaign hypothesis and explicit alternative hypotheses.
- **Skeptic / Reviewer:** Rejects unsupported claims, flags circular reporting, detects weak evidence, and assigns confidence scores.
- **Report Builder:** Compiles accepted findings into STIX 2.1 JSON, Sigma/KQL detection rules, and an executive CTI report.

## Quick Start

### Run a Single Campaign Investigation

```powershell
python app/main.py --seed "AKIAIOSFODNN7EXAMPLE" --seed-type "iam_access_key" --output data/investigation_output.json
```

### Generate Daily Reports

The GitHub Actions workflow at `.github/workflows/daily-reports.yml` runs every
day at 09:00 UTC and can also be started from the repository's **Actions** tab.
It uses the safe synthetic seed, generates investigation, response, threat-intel,
executive, STIX, and Markdown artifacts, uploads them to the workflow run, and
commits updated report files only when their content changes.

The daily job deliberately does not use live AWS credentials. To schedule
read-only live collection, create a separate hardened workflow using OIDC and a
least-privileged role; do not store long-lived cloud keys in repository secrets.

### Run the Evaluation Benchmark (20 Cloud Threat Cases)

```powershell
python eval/evaluate.py --cases eval/benchmark_cases.json --output eval/evaluation_report.json
```

## ☁️ AWS Telemetry & Effective-Permission Attack Paths

The pipeline analyzes **real AWS CloudTrail telemetry** and the **IAM configuration behind it**, so conclusions rest on logged events and evaluated permissions rather than assumption.

### Run against exported CloudTrail JSON (no AWS account needed)

```powershell
python app/main.py --seed "AKIACOMPROMISEDKEY01" --seed-type iam_access_key `
  --source file `
  --cloudtrail-file data/cloudtrail_samples/compromised_key.json `
  --iam-snapshot data/iam_snapshots/account_111122223333.json `
  --start-time 2026-08-01T00:00:00Z --end-time 2026-09-01T00:00:00Z
```

### Run against a live account (read-only)

```powershell
python app/main.py --seed "AKIA..." --seed-type iam_access_key `
  --source aws --profile investigation-readonly --region us-east-1 --simulate
```

Credentials resolve through the standard AWS credential chain (IAM Identity Center locally, an assumed read-only role in deployment). **The tool never accepts a secret access key** — the key you supply is the key under investigation.

### Evidence-status labels

Every attack path carries an explicit status so possibility is never mistaken for proof:

| Status | Meaning |
|---|---|
| `OBSERVED` | CloudTrail shows the action was actually invoked |
| `CONFIRMED_ALLOWED` | `SimulatePrincipalPolicy` evaluated the action as allowed |
| `POTENTIAL` | Policy configuration permits it, but it was never evaluated or seen |
| `UNRESOLVED` | A policy condition (e.g. `aws:MultiFactorAuthPresent`) could not be evaluated |
| `BLOCKED` | An explicit deny or permissions boundary defeats the path |

An explicit deny is never overridden by telemetry. When CloudTrail shows an action that policy evaluation denies, the path stays `BLOCKED` and the disagreement is surfaced as a **contradiction** for the analyst to resolve.

### Telemetry scope limits

`LookupEvents` returns management and Insights events only. S3/Lambda **data events are not logged by default**, so the pipeline reports management and data event counts separately and will not assert data exfiltration from a management event such as `PutBucketPolicy`. Prove object access with a CloudTrail S3 log export or CloudTrail Lake.

### Sample result: compromised vs. benign key

| Fixture | Events | Paths | OBSERVED | BLOCKED | Highest Risk |
|---|---|---|---|---|---|
| `compromised_key.json` | 6 | 9 | 3 | 2 | 100/100 |
| `benign_automation.json` | 3 | 1 | 0 | 0 | 55/100 |

## 🌐 Workload Identity Federation Attack Paths

Federated trust conditions are where cloud identity actually breaks. A Kubernetes ServiceAccount or a GitHub Actions workflow exchanges an OIDC token for real cloud credentials, and the only thing standing between "one workload" and "every workload" is a `sub` condition on the role's trust policy.

```
RBAC subject / CI trigger  →  workload identity  →  OIDC sub condition
                                                          ↓
                                              IAM role  →  action  →  resource
```

### Run cross-plane analysis

```powershell
python app/main.py --seed "AKIACOMPROMISEDKEY01" --seed-type iam_access_key `
  --source file --cloudtrail-file data/federation/cloudtrail_web_identity.json `
  --federated-roles data/federation/aws_federated_roles.json `
  --k8s-snapshot data/federation/k8s_cluster_prod_east.json `
  --k8s-audit-log data/federation/k8s_audit_prod_east.json `
  --github-snapshot data/federation/github_org_example.json
```

### The bug class, in both planes

| Plane | Over-broad condition | What it actually grants |
|---|---|---|
| **EKS / IRSA** | `StringLike` `...:sub` = `system:serviceaccount:*:*` | Any ServiceAccount in any namespace. Pod-create rights anywhere in the cluster become production cloud permissions. |
| **EKS / IRSA** | `system:serviceaccount:*:app-sa` | Any namespace containing a ServiceAccount with that name. |
| **GitHub Actions** | `StringLike` `...:sub` = `repo:org/*` | Every repository in the organization, including public ones accepting pull requests. |
| **GitHub Actions** | `repo:org/repo` with no `:ref:` | Any branch, tag, or PR workflow in that repo. |
| **Either** | No `:sub` condition at all | Every workload holding a token from the provider. |

### Worked example from the fixtures

`eks-payments-irsa` is meant for one ServiceAccount but its trust policy uses `system:serviceaccount:*:*`:

```
2 RBAC subject(s) can obtain this ServiceAccount token
  → system:serviceaccount:payments:payments-sa
  → https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE...
  → eks-payments-irsa
  → secretsmanager:GetSecretValue
  → arn:aws:secretsmanager:...:secret:prod/payments/*        [OBSERVED, risk 100/100]

  Base risk for secret_access: 65
  Path crosses an identity plane into cloud IAM (+15)
  CloudTrail confirms this role was assumed via OIDC (+25)
  Trust condition is broader than one workload (+20)
    - `StringLike` on `...:sub` uses catch-all `system:serviceaccount:*:*`:
      every workload behind this provider can assume the role.
  Same condition also admits 2 other workload(s): observability/fluentbit-sa, ci/build-runner-sa
  Reachable entry point into the workload (+15)
    - Group `platform-engineering` — create pods with serviceAccountName
    - Group `platform-engineering` — pods/exec
  Wildcard resource scope broadens blast radius (+10)
```

That path is `OBSERVED` end to end: a Kubernetes audit event proves the pod ran as the ServiceAccount, a CloudTrail `AssumeRoleWithWebIdentity` proves the role was assumed by that exact subject, and a further CloudTrail event proves the assumed-role session read the secret.

### Evidence rules that apply here too

- A trust edge is `OBSERVED` only when CloudTrail shows **that subject** assuming **that role** — not merely that the role was used.
- A path is `OBSERVED` only when every hop has evidence; a proven role assumption with an unproven action stays `POTENTIAL`.
- A subject that fails every `:sub` condition is recorded as a `BLOCKED` refuted path at risk 0, so the report shows what was ruled out.
- An audience condition that cannot be checked against the provider's registered audiences yields `UNRESOLVED`, never a pass.

### Kubernetes RBAC routes to a ServiceAccount token

The analyzer reports which verb enables each route, so a pod-create pivot is distinguishable from a direct secret read:

- `create pods` + `serviceAccountName` — mounts the token into an attacker-controlled pod
- `pods/exec`, `pods/attach`, `pods/portforward` — executes inside a pod already running as the SA
- `get`/`list secrets` — reads the token directly
- `create serviceaccounts/token` — mints one via the TokenRequest API
- `escalate`, `bind`, `impersonate` — grants itself the rights to do any of the above

## 🛡️ CTI Quality & Deception Benchmark Evaluator

Security teams require proof that agentic research systems resist manipulation, detect circular reporting, and reject over-attribution.

Run the Deception Benchmark Evaluator:

```powershell
python eval/deception_evaluator.py --cases eval/deception_cases.json --output eval/deception_evaluation_report.json
```

### Deception Vectors Tested & Evaluated

| Deception Vector | Defense Mechanism | Measured Result |
|---|---|---|
| **Prompt Injection in Retrieved Pages** | Pattern scanner blocks malicious instructions (`ignore previous...`) in indicator metadata | **100% Blocked (1/1)** |
| **Circular Reporting Loops** | Single-source dependency detector flags unverified vendor feedback loops | **100% Flagged (1/1)** |
| **Shared Hosting & CDN Over-Attribution** | CDN ISP identification (Cloudflare, Akamai, Fastly) penalizes false domain linkage | **100% Avoided (3/3)** |
| **Stale / Decayed Indicators** | Exponential half-life decay math reduces confidence for quiet indicators (>90d) | **Confidence Decayed** |
| **Domain Reuse & Free Cert Ambiguity** | Flags generic Let's Encrypt wildcard certs and domain ownership gaps | **Contradiction Flagged** |
| **Provenance Preservation** | Ensures every graph node maintains explicit source attribution tags | **100% Provenance Coverage** |
| **Observation vs Inference Separation** | Separates raw deterministic graph nodes from agentic analytical inferences | **100% Separation Rate** |

## 📦 STIX 2.1, TAXII 2.1, & OpenCTI Interoperability

The pipeline includes full **STIX 2.1 validation**, an **emulated TAXII 2.1 server**, an **OpenCTI GraphQL mutation converter**, and an **HTML/PDF Report Exporter**:

1. **STIX 2.1 Validation**: Programmatically validates bundle schema & SDO/SRO relationships (`app/stix/stix_validator.py`).
2. **TAXII 2.1 Server Emulation**: Emulates TAXII 2.1 Discovery, API-Root, Collections, and POST Object publishing (`app/stix/taxii_emulator.py`).
3. **OpenCTI GraphQL Converter**: Transforms graph nodes & STIX objects into OpenCTI GraphQL mutations (`app/stix/opencti_exporter.py`).
4. **HTML/PDF CTI Report Exporter**: Generates standalone, formatted executive CTI reports (`app/reports/report_exporter.py`).

Validate any generated bundle programmatically:

```python
from app.stix.stix_validator import STIX21Validator
from app.stix.taxii_emulator import TAXII21ServerEmulator

validator = STIX21Validator()
is_valid, errors = validator.validate_bundle(stix_bundle_json)

# Publish bundle to TAXII 2.1 collection
taxii_server = TAXII21ServerEmulator()
publish_status = taxii_server.publish_stix_bundle("91a7b520-2ceb-478b-aebd-47ee21074e2d", stix_bundle_json)
print(f"STIX Valid: {is_valid} | TAXII Delivered Objects: {publish_status['success_count']}")
```

## Key Metrics Evaluated

- IOC Extraction Precision & Recall
- Entity Relationship Correctness
- ATT&CK Mapping Accuracy
- Unsupported-Claim Rate
- Provenance Coverage
- Circular Reporting Detection
- Execution Cost & Runtime per Investigation
