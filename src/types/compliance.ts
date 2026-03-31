/**
 * Compliance mapping types (MITRE ATLAS, OWASP LLM Top 10, EU AI Act).
 */

import type { KillChainPhase } from './detection.js'

/** MITRE ATLAS technique mapping */
export interface ATLASMapping {
  readonly techniqueId: string
  readonly tacticId: string
  readonly techniqueName: string
  readonly tacticName: string
  readonly description: string
  readonly relatedKillChainPhase: KillChainPhase
  readonly mitigationIds: readonly string[]
  readonly caseStudyIds: readonly string[]
}

/** OWASP LLM Top 10 2025 mapping */
export interface OWASPMapping {
  readonly riskId: string
  readonly riskName: string
  readonly description: string
  readonly relatedKillChainPhases: readonly KillChainPhase[]
  readonly preventionMeasures: readonly string[]
  readonly shieldxCoverage: readonly string[]
}

/** Compliance report output */
export interface ComplianceReport {
  readonly generatedAt: string
  readonly framework: 'mitre_atlas' | 'owasp_llm' | 'eu_ai_act' | 'combined'
  readonly coverageScore: number
  readonly totalTechniques: number
  readonly coveredTechniques: number
  readonly gaps: readonly string[]
  readonly recommendations: readonly string[]
  readonly mappings: readonly (ATLASMapping | OWASPMapping)[]
}

/** EU AI Act Article 9/12 compliance report */
export interface EUAIActReport {
  readonly generatedAt: string
  readonly riskCategory: 'high' | 'limited' | 'minimal'
  readonly article9RiskManagement: {
    readonly riskIdentification: boolean
    readonly riskMitigation: boolean
    readonly residualRisks: readonly string[]
    readonly testingPerformed: boolean
  }
  readonly article12Logging: {
    readonly incidentLogging: boolean
    readonly auditTrail: boolean
    readonly retentionPeriod: string
    readonly totalIncidents: number
  }
  readonly article14HumanOversight: {
    readonly humanInTheLoop: boolean
    readonly overrideCapability: boolean
    readonly feedbackMechanism: boolean
  }
  readonly article15Accuracy: {
    readonly falsePositiveRate: number
    readonly falseNegativeRate: number
    readonly benchmarkResults: Readonly<Record<string, number>>
  }
  readonly conformityAssessment: {
    readonly selfAssessment: boolean
    readonly thirdPartyAudit: boolean
    readonly lastAssessmentDate?: string
  }
}
