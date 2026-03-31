# EU AI Act Compliance

## Overview

ShieldX provides tooling to help organizations comply with the European Union Artificial Intelligence Act (Regulation 2024/1689), specifically the articles relevant to high-risk AI systems that incorporate large language models. ShieldX is not a legal compliance tool -- it is a technical implementation that addresses the measurable, auditable requirements of the regulation.

Enable EU AI Act compliance reporting:

```typescript
const shield = new ShieldX({
  compliance: { euAiAct: true },
})
```

This document covers Articles 9, 12, 14, and 15 -- the articles most relevant to LLM security and prompt injection defense.

---

## Article 9: Risk Management System

### What the Article Requires

High-risk AI systems must have a risk management system that:

1. Identifies and analyzes known and reasonably foreseeable risks
2. Estimates and evaluates risks that may emerge during intended use and reasonably foreseeable misuse
3. Adopts risk management measures to address identified risks
4. Tests the system to ensure residual risks are acceptable

### How ShieldX Addresses This

| Requirement | ShieldX Implementation | Evidence |
|-------------|----------------------|----------|
| Risk identification | MITRE ATLAS mapping identifies 44 attack techniques; OWASP LLM Top 10 maps 10 risk categories | `ComplianceReport.totalTechniques`, `ComplianceReport.coveredTechniques` |
| Risk estimation | Kill chain classification assigns severity levels (none, low, medium, high, critical) per detected threat | `ShieldXResult.threatLevel`, `ShieldXResult.killChainPhase` |
| Risk mitigation | 10-layer defense pipeline with phase-appropriate healing actions | `ShieldXResult.action`, `ShieldXResult.healingApplied` |
| Residual risk documentation | Gap analysis identifies uncovered ATLAS techniques | `ComplianceReport.gaps`, `ComplianceReport.recommendations` |
| Testing | Red Team Engine generates adversarial variants; benchmark suite measures ASR and false positive rate | `npm run self-test`, `npm run benchmark` |

### EU AI Act Report Fields

```typescript
interface EUAIActReport {
  article9RiskManagement: {
    riskIdentification: boolean     // ATLAS + OWASP mapping enabled
    riskMitigation: boolean         // Healing engine active
    residualRisks: string[]         // Uncovered ATLAS techniques
    testingPerformed: boolean       // Red team + benchmark results available
  }
}
```

### Generating a Risk Assessment

The `EUAIActReporter` module produces a structured report:

```typescript
const shield = new ShieldX({ compliance: { euAiAct: true } })
await shield.initialize()

// After running the system for a period:
const report = await shield.generateComplianceReport('eu_ai_act')

// report.article9RiskManagement contains:
// - riskIdentification: true (ATLAS mapping active)
// - riskMitigation: true (healing engine active)
// - residualRisks: ['AML.T0003', 'AML.T0004', ...] (techniques not covered)
// - testingPerformed: true/false (based on last red team run)
```

---

## Article 12: Record-Keeping (Logging)

### What the Article Requires

High-risk AI systems must enable automatic recording of events (logs) throughout the system's lifetime. Logging must:

1. Enable traceability of system functioning
2. Record events relevant to identifying risks
3. Maintain logs for an appropriate retention period
4. Be accessible for monitoring and audit

### How ShieldX Addresses This

| Requirement | ShieldX Implementation | Evidence |
|-------------|----------------------|----------|
| Automatic event recording | Every scan produces a structured `ShieldXResult` with timestamp, scan ID, scanner results, and actions | `ShieldXResult.id`, `ShieldXResult.timestamp` |
| Risk-relevant events | All detected threats are logged as `IncidentReport` with full context | `IncidentReport.id`, `IncidentReport.timestamp` |
| Traceability | Each scan result links to specific scanner IDs, matched patterns, and kill chain phase | `ScanResult.scannerId`, `ScanResult.matchedPatterns` |
| Audit trail | Incident reports include ATLAS technique IDs and OWASP risk mappings | `IncidentReport.atlasMapping`, `IncidentReport.owaspMapping` |
| Structured logging | Pino JSON logging with configurable levels | `logging.structured: true` |

### Incident Report Structure

Every incident generates a structured report:

```typescript
interface IncidentReport {
  id: string                          // Unique incident ID
  timestamp: string                   // ISO 8601 timestamp
  sessionId?: string                  // Session identifier (if available)
  userId?: string                     // User identifier (if available)
  threatLevel: ThreatLevel            // none | low | medium | high | critical
  killChainPhase: KillChainPhase      // 7-phase classification
  action: HealingAction               // Action taken
  attackVector: string                // Description of the attack vector
  matchedPatterns: string[]           // Pattern IDs that triggered detection
  inputHash: string                   // SHA-256 hash (never raw input)
  mitigationApplied: string           // Description of mitigation
  falsePositive?: boolean             // Post-hoc feedback
  atlasMapping?: string               // MITRE ATLAS technique ID
  owaspMapping?: string               // OWASP LLM risk ID
}
```

### EU AI Act Report Fields

```typescript
interface EUAIActReport {
  article12Logging: {
    incidentLogging: boolean    // Incident logging enabled
    auditTrail: boolean         // ATLAS/OWASP mappings in incident reports
    retentionPeriod: string     // Configured retention period
    totalIncidents: number      // Total incidents recorded
  }
}
```

### Privacy Consideration

ShieldX never stores raw user input in logs or incident reports. All input references are SHA-256 hashes. This is compatible with GDPR data minimization requirements while still providing the traceability required by Article 12.

---

## Article 14: Human Oversight

### What the Article Requires

High-risk AI systems must be designed to allow effective human oversight, including:

1. The ability for humans to understand the AI system's capabilities and limitations
2. The ability to monitor the system's operation
3. The ability to override or reverse the system's decisions
4. The ability to intervene or stop the system

### How ShieldX Addresses This

| Requirement | ShieldX Implementation | Evidence |
|-------------|----------------------|----------|
| Understanding capabilities | Full configuration transparency; every scanner and threshold is documented and configurable | `ShieldXConfig` (all fields documented) |
| Monitoring | Structured logging, incident reports, compliance reports, `getStats()` API | `LearningStats`, `ComplianceReport` |
| Override/reverse | `submitFeedback()` API for marking false positives; per-phase healing strategies are configurable | `shield.submitFeedback(scanId, { isFalsePositive: true })` |
| Intervention | All layers independently toggleable; master kill switch via `healing.enabled: false`; `destroy()` for clean shutdown | Config toggles, `shield.destroy()` |

### Human-in-the-Loop Integration

ShieldX supports human-in-the-loop workflows:

1. **Active Learning**: The learning engine identifies uncertain samples and surfaces them for human review via the `ActiveLearner` module. This ensures humans are involved in decisions at the classifier's uncertainty boundary.

2. **Feedback Loop**: The `submitFeedback()` API allows human operators to correct false positives and false negatives. This feedback is processed by the `FeedbackProcessor` to improve detection accuracy.

3. **Configurable Actions**: The `healing.phaseStrategies` configuration allows operators to set per-phase responses. Setting an action to `warn` instead of `block` enables human review before action is taken.

4. **Incident Review**: Incident reports are structured for human review, with ATLAS and OWASP mappings providing standardized context.

### EU AI Act Report Fields

```typescript
interface EUAIActReport {
  article14HumanOversight: {
    humanInTheLoop: boolean       // Active learning enabled
    overrideCapability: boolean   // Feedback API available
    feedbackMechanism: boolean    // Feedback processing enabled
  }
}
```

---

## Article 15: Accuracy, Robustness, and Cybersecurity

### What the Article Requires

High-risk AI systems must achieve appropriate levels of:

1. **Accuracy**: The system must perform at an appropriate level of accuracy
2. **Robustness**: The system must be resilient to errors and inconsistencies
3. **Cybersecurity**: The system must be protected against unauthorized access and adversarial attacks

### How ShieldX Addresses This

#### Accuracy

| Metric | Measurement Method | Target |
|--------|-------------------|--------|
| False positive rate | Tracked via feedback loop; `LearningStats.falsePositiveRate` | <5% |
| False negative rate | Measured via red team testing; `npm run self-test` | <15% against known patterns |
| Detection accuracy | PINT benchmark, AgentDojo benchmark | Published with each release |

ShieldX measures accuracy through:
- **Feedback Loop**: Every false positive report adjusts the classifier and threshold
- **Red Team Testing**: Automated adversarial testing measures the false negative rate
- **Benchmark Suite**: Standardized benchmarks (PINT, AgentDojo) provide comparable accuracy metrics

#### Robustness

| Property | Implementation |
|----------|---------------|
| Graceful degradation | Every scanner is wrapped in try/catch; `Promise.allSettled` ensures failing scanners do not block the pipeline |
| No single point of failure | 10 independent layers; any subset can operate alone |
| Adaptive thresholds | `ThresholdAdaptor` adjusts to changing attack patterns |
| Drift detection | `DriftDetector` alerts when attack patterns shift |

#### Cybersecurity

| Property | Implementation |
|----------|---------------|
| Defense in depth | 10 layers, each catching different attack types |
| Zero trust for data sources | `TrustTagger` assigns per-source trust scores; no data source is trusted by default |
| Cryptographic integrity | `SignedPromptVerifier` for system prompts; `ManifestVerifier` for MCP servers |
| No raw data storage | SHA-256 hashes only; raw input never persists |
| Self-testing | Red Team Engine continuously probes for weaknesses |
| Supply chain verification | `SupplyChainVerifier` and `ModelProvenanceChecker` |

### EU AI Act Report Fields

```typescript
interface EUAIActReport {
  article15Accuracy: {
    falsePositiveRate: number               // Current FP rate
    falseNegativeRate: number               // Current FN rate (from red team)
    benchmarkResults: Record<string, number> // PINT, AgentDojo, etc.
  }
  conformityAssessment: {
    selfAssessment: boolean      // Self-test has been run
    thirdPartyAudit: boolean     // External audit performed
    lastAssessmentDate?: string  // ISO date of last assessment
  }
}
```

---

## Generating Compliance Reports

### Full EU AI Act Report

```typescript
const shield = new ShieldX({ compliance: { euAiAct: true } })
await shield.initialize()

// After operating the system:
const report = await shield.generateComplianceReport('eu_ai_act')
```

The report covers all four articles with structured, auditable data.

### Combined Report (ATLAS + OWASP + EU AI Act)

```typescript
const report = await shield.generateComplianceReport('combined')
```

### Periodic Reporting

For continuous compliance, schedule regular report generation:

```typescript
// Generate weekly compliance reports
setInterval(async () => {
  const report = await shield.generateComplianceReport('eu_ai_act')
  await saveComplianceReport(report) // Your persistence layer
}, 7 * 24 * 60 * 60 * 1000)
```

---

## Risk Classification

The EU AI Act classifies AI systems by risk level. ShieldX helps determine and document the risk classification:

| Risk Category | Criteria | ShieldX Relevance |
|---------------|----------|-------------------|
| Unacceptable risk | Manipulative, exploitative, or social scoring systems | Out of scope (prohibited uses) |
| High risk | AI in critical infrastructure, education, employment, law enforcement, etc. | Full compliance tooling (Articles 9, 12, 14, 15) |
| Limited risk | Chatbots, emotion recognition, deep fakes | Transparency obligations; ShieldX provides audit trail |
| Minimal risk | Spam filters, AI-assisted games | No specific obligations; ShieldX still provides defense |

For high-risk AI systems, ShieldX provides the technical foundation for demonstrating compliance with the mandatory requirements. The compliance reports are designed to be presented to auditors and regulatory bodies as evidence of systematic risk management.

---

## Limitations

ShieldX provides technical tooling for compliance. It does not provide:

- Legal advice on whether your AI system is classified as high-risk
- Legal interpretation of EU AI Act articles
- Representation before regulatory authorities
- Certification or conformity marking

Organizations should consult legal counsel to determine their specific obligations under the EU AI Act and use ShieldX's compliance reports as technical evidence within their broader compliance strategy.
