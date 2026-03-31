/**
 * Unified compliance report generator.
 * Combines MITRE ATLAS, OWASP LLM Top 10, and EU AI Act
 * reports into a single compliance output.
 */

import type { ComplianceReport, ATLASMapping, OWASPMapping } from '../types/compliance.js'
import type { LearningStats } from '../types/learning.js'

import { ATLASMapper } from './ATLASMapper.js'
import { OWASPMapper } from './OWASPMapper.js'
import { EUAIActReporter } from './EUAIActReporter.js'

/**
 * ReportGenerator — unified compliance report generator.
 *
 * Orchestrates ATLAS, OWASP, and EU AI Act mappers/reporters
 * to produce individual or combined compliance reports.
 */
export class ReportGenerator {
  private readonly atlasMapper: ATLASMapper
  private readonly owaspMapper: OWASPMapper
  private readonly euAiActReporter: EUAIActReporter

  constructor() {
    this.atlasMapper = new ATLASMapper()
    this.owaspMapper = new OWASPMapper()
    this.euAiActReporter = new EUAIActReporter()
  }

  /**
   * Generate a compliance report for a specific framework or combined.
   * @param framework - Which compliance framework to report on
   * @param stats - Optional learning stats for EU AI Act reporting
   * @returns Structured compliance report
   */
  generateComplianceReport(
    framework: 'mitre_atlas' | 'owasp_llm' | 'eu_ai_act' | 'combined',
    stats?: LearningStats,
  ): ComplianceReport {
    switch (framework) {
      case 'mitre_atlas':
        return this.generateATLASReport()
      case 'owasp_llm':
        return this.generateOWASPReport()
      case 'eu_ai_act':
        return this.generateEUAIActComplianceReport(stats)
      case 'combined':
        return this.generateCombinedReport(stats)
    }
  }

  /**
   * Get the underlying ATLAS mapper for direct access.
   */
  getATLASMapper(): ATLASMapper {
    return this.atlasMapper
  }

  /**
   * Get the underlying OWASP mapper for direct access.
   */
  getOWASPMapper(): OWASPMapper {
    return this.owaspMapper
  }

  /**
   * Get the underlying EU AI Act reporter for direct access.
   */
  getEUAIActReporter(): EUAIActReporter {
    return this.euAiActReporter
  }

  // ---------------------------------------------------------------------------
  // Framework-specific reports
  // ---------------------------------------------------------------------------

  private generateATLASReport(): ComplianceReport {
    const coverage = this.atlasMapper.getCoverage()
    const mappings = this.atlasMapper.getAllMappings()

    return Object.freeze({
      generatedAt: new Date().toISOString(),
      framework: 'mitre_atlas' as const,
      coverageScore: coverage.total > 0 ? Math.round((coverage.covered / coverage.total) * 1000) / 1000 : 0,
      totalTechniques: coverage.total,
      coveredTechniques: coverage.covered,
      gaps: Object.freeze(coverage.gaps.map((g) => `ATLAS technique ${g} not covered`)),
      recommendations: Object.freeze(generateATLASRecommendations(coverage.gaps)),
      mappings: Object.freeze([...mappings]),
    })
  }

  private generateOWASPReport(): ComplianceReport {
    const coverage = this.owaspMapper.getCoverage()
    const mappings = this.owaspMapper.getAllMappings()

    return Object.freeze({
      generatedAt: new Date().toISOString(),
      framework: 'owasp_llm' as const,
      coverageScore: coverage.total > 0 ? Math.round((coverage.covered / coverage.total) * 1000) / 1000 : 0,
      totalTechniques: coverage.total,
      coveredTechniques: coverage.covered,
      gaps: Object.freeze(coverage.gaps.map((g) => `OWASP risk ${g} not covered`)),
      recommendations: Object.freeze(generateOWASPRecommendations(coverage.gaps)),
      mappings: Object.freeze([...mappings]),
    })
  }

  private generateEUAIActComplianceReport(stats?: LearningStats): ComplianceReport {
    const defaultStats = stats ?? createDefaultStats()
    const euReport = this.euAiActReporter.generateReport(defaultStats)

    // Score based on how many articles are compliant
    let compliantArticles = 0
    const totalArticles = 5 // 9, 12, 14, 15, conformity

    if (euReport.article9RiskManagement.riskIdentification && euReport.article9RiskManagement.riskMitigation) {
      compliantArticles += 1
    }
    if (euReport.article12Logging.incidentLogging && euReport.article12Logging.auditTrail) {
      compliantArticles += 1
    }
    if (euReport.article14HumanOversight.humanInTheLoop) {
      compliantArticles += 1
    }
    if (euReport.article15Accuracy.falsePositiveRate < 0.2) {
      compliantArticles += 1
    }
    if (euReport.conformityAssessment.selfAssessment) {
      compliantArticles += 1
    }

    const gaps: string[] = []
    if (!euReport.article9RiskManagement.testingPerformed) {
      gaps.push('Article 9: Red team testing not performed')
    }
    if (!euReport.conformityAssessment.thirdPartyAudit) {
      gaps.push('Conformity: Third-party audit not completed')
    }
    if (euReport.article15Accuracy.falsePositiveRate > 0.1) {
      gaps.push('Article 15: False positive rate exceeds 10%')
    }

    return Object.freeze({
      generatedAt: new Date().toISOString(),
      framework: 'eu_ai_act' as const,
      coverageScore: Math.round((compliantArticles / totalArticles) * 1000) / 1000,
      totalTechniques: totalArticles,
      coveredTechniques: compliantArticles,
      gaps: Object.freeze(gaps),
      recommendations: Object.freeze([
        'Perform regular red team self-testing (Article 9)',
        'Schedule third-party conformity assessment',
        'Monitor and reduce false positive rate below 10%',
        'Maintain incident logs for minimum 90 days',
      ]),
      mappings: Object.freeze([]),
    })
  }

  private generateCombinedReport(stats?: LearningStats): ComplianceReport {
    const atlasReport = this.generateATLASReport()
    const owaspReport = this.generateOWASPReport()
    const euReport = this.generateEUAIActComplianceReport(stats)

    const totalTechniques = atlasReport.totalTechniques + owaspReport.totalTechniques + euReport.totalTechniques
    const coveredTechniques = atlasReport.coveredTechniques + owaspReport.coveredTechniques + euReport.coveredTechniques
    const allGaps = [...atlasReport.gaps, ...owaspReport.gaps, ...euReport.gaps]
    const allRecommendations = [
      ...atlasReport.recommendations,
      ...owaspReport.recommendations,
      ...euReport.recommendations,
    ]
    const allMappings: readonly (ATLASMapping | OWASPMapping)[] = [
      ...atlasReport.mappings,
      ...owaspReport.mappings,
    ]

    return Object.freeze({
      generatedAt: new Date().toISOString(),
      framework: 'combined' as const,
      coverageScore: totalTechniques > 0 ? Math.round((coveredTechniques / totalTechniques) * 1000) / 1000 : 0,
      totalTechniques,
      coveredTechniques,
      gaps: Object.freeze([...allGaps]),
      recommendations: Object.freeze([...new Set(allRecommendations)]),
      mappings: Object.freeze([...allMappings]),
    })
  }
}

/** Generate ATLAS-specific recommendations based on gaps */
function generateATLASRecommendations(gaps: readonly string[]): string[] {
  const recs: string[] = []
  if (gaps.length > 0) {
    recs.push(`Add detection rules for ${gaps.length} uncovered ATLAS techniques`)
  }
  recs.push('Run quarterly ATLAS coverage assessments')
  recs.push('Update mappings when ATLAS releases new techniques')
  return recs
}

/** Generate OWASP-specific recommendations based on gaps */
function generateOWASPRecommendations(gaps: readonly string[]): string[] {
  const recs: string[] = []
  if (gaps.length > 0) {
    recs.push(`Implement controls for ${gaps.length} uncovered OWASP LLM risks`)
  }
  recs.push('Perform annual OWASP LLM Top 10 compliance review')
  recs.push('Monitor OWASP for updated risk categories')
  return recs
}

/** Create default learning stats when none provided */
function createDefaultStats(): LearningStats {
  return Object.freeze({
    totalPatterns: 0,
    builtinPatterns: 0,
    learnedPatterns: 0,
    communityPatterns: 0,
    redTeamPatterns: 0,
    totalIncidents: 0,
    falsePositiveRate: 0,
    topPatterns: Object.freeze([]),
    recentIncidents: 0,
    driftDetected: false,
  })
}
