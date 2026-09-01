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
