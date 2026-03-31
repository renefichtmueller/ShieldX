# Threat Model

## Overview

This document maps the threat landscape for LLM-integrated applications to the MITRE ATLAS (Adversarial Threat Landscape for Artificial Intelligence Systems) framework and shows where ShieldX provides coverage.

## MITRE ATLAS Technique Coverage

### Reconnaissance (ATLAS Tactic: TA0001)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Discover ML Model Ontology | AML.T0001 | Covered | L9: Leakage Detector, Canary Manager |
| Discover ML Model Family | AML.T0002 | Covered | L1: Rule Engine (model probing patterns) |
| Discover ML Capabilities | AML.T0014 | Covered | L6: Session Profiler (probing behavior detection) |
| Search for Victim's Publicly Available ML Artifacts | AML.T0003 | Out of scope | N/A (external to the application) |

### Resource Development (ATLAS Tactic: TA0002)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Acquire Public ML Artifacts | AML.T0004 | Out of scope | N/A (attacker preparation, external) |
| Develop Adversarial ML Attacks | AML.T0005 | Proactive defense | Red Team Engine generates variants |
| Publish Poisoned Datasets | AML.T0019 | Covered | L9: RAG Shield (document integrity scoring) |

### Initial Access (ATLAS Tactic: TA0003)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Prompt Injection (Direct) | AML.T0051 | Covered | L0: Preprocessing, L1: Rule Engine, L3: Embedding, L4: Entropy |
| Prompt Injection (Indirect) | AML.T0051.001 | Covered | Indirect Scanner, L7: Tool Poison Detector, L9: RAG Shield |
| Phishing / Social Engineering | AML.T0052 | Partial | L6: Intent Monitor (detects manipulation patterns) |
| Supply Chain Compromise of ML Model | AML.T0010 | Covered | Supply Chain Verifier, Model Provenance Checker |

### ML Model Access (ATLAS Tactic: TA0004)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Inference API Access | AML.T0040 | Out of scope | N/A (access control, external to ShieldX) |
| Full ML Model Access | AML.T0041 | Out of scope | N/A (access control, external to ShieldX) |
| ML Artifact Collection | AML.T0035 | Covered | L9: Leakage Detector (detects model weight/config extraction) |

### Execution (ATLAS Tactic: TA0005)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| LLM Prompt Injection | AML.T0051 | Covered | Full pipeline (L0-L9) |
| Arbitrary Code via ML Model | AML.T0053 | Covered | L7: MCP Guard (tool call validation) |
| User Execution of Malicious Content | AML.T0054 | Covered | L8: Output Sanitizer, L9: Output Validator |

### Persistence (ATLAS Tactic: TA0006)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Poisoning of Training Data | AML.T0020 | Out of scope | N/A (training pipeline, external) |
| Backdoor ML Model | AML.T0018 | Covered | Supply Chain Verifier, Model Provenance Checker |
| Modify ML Model Configuration | AML.T0024 | Covered | L6: Memory Integrity Guard, Context Integrity |
| Modify ML Pipeline Component | AML.T0023 | Partial | L7: Manifest Verifier (MCP server manifests) |

### Privilege Escalation (ATLAS Tactic: TA0007)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| LLM Jailbreak | AML.T0054 | Covered | L1: Rule Engine, L2: Sentinel, L6: Intent Monitor |
| System Prompt Override | AML.T0055 | Covered | L1: Rule patterns, L6: Context Integrity, L9: Role Integrity Checker |

### Defense Evasion (ATLAS Tactic: TA0008)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Adversarial Example in Inference | AML.T0043 | Covered | L3: Embedding Anomaly, L4: Entropy, L5: Attention |
| Evade ML Model | AML.T0015 | Covered | Red Team Engine (proactive gap discovery), L3: Embedding |
| Input Obfuscation | AML.T0016 | Covered | L0: Unicode Normalizer, Tokenizer Normalizer, Compressed Payload Detector |
| Encoding-Based Evasion | AML.T0058 | Covered | L0: Compressed Payload Detector, L4: Entropy Scanner |

### Credential Access (ATLAS Tactic: TA0009)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Extract Credentials via LLM | AML.T0056 | Covered | L8: Credential Redactor, L9: Leakage Detector |
| Extract API Keys via Tool Calls | AML.T0057 | Covered | L7: Tool Chain Guard, L8: Credential Redactor |

### Discovery (ATLAS Tactic: TA0010)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Discover ML Model Output | AML.T0044 | Covered | L6: Session Profiler (probing detection) |
| Extract System Prompt | AML.T0059 | Covered | L9: Canary Manager, Leakage Detector |
| Enumerate Available Tools | AML.T0060 | Covered | L7: Privilege Checker (denies unauthorized tool listing) |

### Lateral Movement (ATLAS Tactic: TA0011)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Cross-Agent Injection | AML.T0061 | Covered | L7: Tool Chain Guard, Tool Poison Detector |
| Exploit MCP Tool Chain | AML.T0062 | Covered | L7: Full MCP Guard suite |
| Data Store Poisoning | AML.T0063 | Covered | L9: RAG Shield (document integrity) |

### Collection (ATLAS Tactic: TA0012)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Exfiltrate Training Data | AML.T0025 | Out of scope | N/A (training pipeline) |
| Exfiltrate ML Model | AML.T0026 | Covered | L9: Leakage Detector |
| Harvest Credentials from Output | AML.T0064 | Covered | L8: Credential Redactor |

### Exfiltration (ATLAS Tactic: TA0013)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Data Exfiltration via LLM Output | AML.T0065 | Covered | L8: Output Sanitizer, Credential Redactor |
| Data Exfiltration via Tool Calls | AML.T0066 | Covered | L7: Tool Chain Guard, Resource Governor |
| Side-Channel Exfiltration | AML.T0067 | Partial | L4: Entropy (detects encoded data in output) |

### Impact (ATLAS Tactic: TA0014)

| ATLAS Technique | ID | ShieldX Coverage | Detecting Layer |
|-----------------|------|-----------------|-----------------|
| Denial of ML Service | AML.T0029 | Covered | L7: Resource Governor (budget enforcement) |
| ML Model Integrity Violation | AML.T0028 | Covered | L6: Context Integrity, Memory Integrity Guard |
| Harm to Downstream Task | AML.T0048 | Covered | L9: Scope Validator, Output Validator |

---

## OWASP LLM Top 10 (2025) Coverage

| # | Risk | OWASP ID | ShieldX Coverage | Primary Layers |
|---|------|----------|-----------------|----------------|
| 1 | Prompt Injection | LLM01 | Full coverage | L0-L5, L8 (input), L9 (output) |
| 2 | Insecure Output Handling | LLM02 | Full coverage | L8: Output Sanitizer, Credential Redactor |
| 3 | Training Data Poisoning | LLM03 | Partial (RAG documents only) | L9: RAG Shield |
| 4 | Model Denial of Service | LLM04 | Covered | L7: Resource Governor |
| 5 | Supply Chain Vulnerabilities | LLM05 | Covered | Supply Chain Verifier, MCP Manifest Verifier |
| 6 | Sensitive Information Disclosure | LLM06 | Full coverage | L8: Credential Redactor, L9: Leakage Detector, Canary Manager |
| 7 | Insecure Plugin Design | LLM07 | Full coverage | L7: Full MCP Guard suite |
| 8 | Excessive Agency | LLM08 | Full coverage | L7: Privilege Checker, Resource Governor, Tool Chain Guard |
| 9 | Overreliance | LLM09 | Partial | L9: Output Validator (factual scope checking) |
| 10 | Model Theft | LLM10 | Out of scope | N/A (infrastructure security) |

---

## Coverage Summary

### By ATLAS Tactic

| Tactic | Total Techniques | Covered | Partial | Out of Scope |
|--------|-----------------|---------|---------|-------------|
| Reconnaissance | 4 | 3 | 0 | 1 |
| Resource Development | 3 | 1 | 0 | 2 |
| Initial Access | 4 | 3 | 1 | 0 |
| ML Model Access | 3 | 1 | 0 | 2 |
| Execution | 3 | 3 | 0 | 0 |
| Persistence | 4 | 2 | 1 | 1 |
| Privilege Escalation | 2 | 2 | 0 | 0 |
| Defense Evasion | 4 | 4 | 0 | 0 |
| Credential Access | 2 | 2 | 0 | 0 |
| Discovery | 3 | 3 | 0 | 0 |
| Lateral Movement | 3 | 3 | 0 | 0 |
| Collection | 3 | 2 | 0 | 1 |
| Exfiltration | 3 | 2 | 1 | 0 |
| Impact | 3 | 3 | 0 | 0 |
| **Total** | **44** | **34** | **3** | **7** |

**Coverage rate: 77% full + 7% partial = 84% total**

### By OWASP LLM Top 10

| Coverage Level | Count | Risks |
|---------------|-------|-------|
| Full coverage | 6 | LLM01, LLM02, LLM06, LLM07, LLM08, LLM04 |
| Partial coverage | 3 | LLM03, LLM05, LLM09 |
| Out of scope | 1 | LLM10 |

**Coverage rate: 60% full + 30% partial = 90% total**

---

## Out of Scope

ShieldX is a runtime defense library. The following are explicitly out of scope:

| Area | Reason | Recommended Solution |
|------|--------|---------------------|
| Model training pipeline security | ShieldX operates at inference time | ML pipeline security tools (e.g., TensorFlow Model Analysis) |
| Infrastructure access control | ShieldX is an application-layer library | IAM, RBAC, network security |
| Model theft prevention | Requires infrastructure-level controls | API rate limiting, model encryption, access logging |
| Physical security | Out of software scope | Physical security measures |
| Social engineering (non-prompt) | Human factor, outside LLM context | Security awareness training |

---

## Threat Actor Profiles

### Casual Attacker

- **Sophistication**: Low
- **Typical techniques**: Copy-paste jailbreaks, known DAN prompts, simple role override
- **Kill chain progression**: Usually stops at initial access or privilege escalation
- **ShieldX detection rate**: >95% (L1 rule engine catches most known patterns)

### Skilled Researcher

- **Sophistication**: Medium
- **Typical techniques**: Novel prompt construction, encoding tricks, multi-turn escalation, attention manipulation
- **Kill chain progression**: May reach reconnaissance or persistence
- **ShieldX detection rate**: >85% (L3 embedding + L6 behavioral catches paraphrased variants)

### Advanced Persistent Threat

- **Sophistication**: High
- **Typical techniques**: Custom adversarial examples, supply chain poisoning, indirect injection via trusted documents, tool chain exploitation
- **Kill chain progression**: Full chain from initial access to actions on objective
- **ShieldX detection rate**: >70% (multi-layer defense with red team-evolved patterns)
- **Improvement path**: Red Team Engine continuously generates adversarial variants; federated sync shares patterns across deployments

### Automated Attack Tools

- **Sophistication**: Variable (tool-dependent)
- **Typical techniques**: Brute-force prompt mutation, automated jailbreak testing, fuzzing
- **Kill chain progression**: Typically initial access with high volume
- **ShieldX detection rate**: >90% (volume-based anomaly detection + rate limiting via Resource Governor)
