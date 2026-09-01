# Cloud Campaign Evidence Graph

A defensible, agentic threat intelligence pipeline that ingests cloud-related seed indicators (IAM credentials, IPs, domains, container images, GitHub repos, phishing URLs) and outputs time-bounded campaign investigations, evidence graphs, ATT&CK mappings, skeptic-reviewed analytical judgments, STIX 2.1 bundles, and detection rules.

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

### Run the Evaluation Benchmark (20 Cloud Threat Cases)

```powershell
python eval/evaluate.py --cases eval/benchmark_cases.json --output eval/evaluation_report.json
```

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

## Key Metrics Evaluated

- IOC Extraction Precision & Recall
- Entity Relationship Correctness
- ATT&CK Mapping Accuracy
- Unsupported-Claim Rate
- Provenance Coverage
- Circular Reporting Detection
- Execution Cost & Runtime per Investigation
