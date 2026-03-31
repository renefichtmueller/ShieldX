/**
 * EU AI Act compliance reporting.
 * Generates reports covering Articles 9, 12, 14, and 15
 * of the EU AI Act for high-risk AI systems.
 */

import type { EUAIActReport } from '../types/compliance.js'
import type { LearningStats } from '../types/learning.js'

/**
 * EUAIActReporter — EU AI Act compliance report generator.
 *
 * Generates compliance reports covering:
 * - Article 9: Risk management system
 * - Article 12: Record-keeping / logging / audit trail
 * - Article 14: Human oversight
 * - Article 15: Accuracy, robustness, and cybersecurity
 */
export class EUAIActReporter {
  /**
   * Generate a comprehensive EU AI Act compliance report.
   * @param stats - Current learning statistics
   * @returns Structured EU AI Act compliance report
   */
  generateReport(stats: LearningStats): EUAIActReport {
    return Object.freeze({
      generatedAt: new Date().toISOString(),
      riskCategory: 'high' as const, // LLM security systems are high-risk

      // Article 9 — Risk Management System
      article9RiskManagement: Object.freeze({
        riskIdentification: true, // ShieldX identifies 7+ kill chain phases
        riskMitigation: true,     // Auto-healing, sanitization, blocking
        residualRisks: Object.freeze(computeResidualRisks(stats)),
        testingPerformed: stats.redTeamPatterns > 0, // Red team self-testing
      }),

      // Article 12 — Record-Keeping
      article12Logging: Object.freeze({
        incidentLogging: true,           // All incidents logged
        auditTrail: true,                // Full scan results persisted
        retentionPeriod: '90 days',      // Configurable
        totalIncidents: stats.totalIncidents,
      }),

      // Article 14 — Human Oversight
      article14HumanOversight: Object.freeze({
        humanInTheLoop: true,            // Active learning routes to human review
        overrideCapability: true,         // Operators can override decisions
        feedbackMechanism: true,          // False positive feedback loop
      }),

      // Article 15 — Accuracy, Robustness, and Cybersecurity
      article15Accuracy: Object.freeze({
        falsePositiveRate: stats.falsePositiveRate,
        falseNegativeRate: estimateFalseNegativeRate(stats),
        benchmarkResults: Object.freeze(computeBenchmarks(stats)),
      }),

      // Conformity Assessment
      conformityAssessment: Object.freeze({
        selfAssessment: true,
        thirdPartyAudit: false, // Requires external auditor
      }),
    })
  }
}

/**
 * Compute residual risks based on learning statistics.
 * Identifies areas where detection coverage is incomplete.
 */
function computeResidualRisks(stats: LearningStats): string[] {
  const risks: string[] = []

  // High false positive rate indicates overdetection
  if (stats.falsePositiveRate > 0.1) {
    risks.push('Elevated false positive rate may cause legitimate content blocking')
  }

  // Drift indicates evolving attack landscape
  if (stats.driftDetected) {
    risks.push('Concept drift detected — detection patterns may be stale')
  }

  // Low community patterns means limited shared intelligence
  if (stats.communityPatterns === 0) {
    risks.push('No community threat intelligence — blind spots possible')
  }

  // No red team testing
  if (stats.redTeamPatterns === 0) {
    risks.push('No red team self-testing performed — unknown evasion gaps')
  }

  // Few learned patterns indicates limited adaptation
  if (stats.learnedPatterns < 10) {
    risks.push('Limited learned patterns — evolution engine underutilized')
  }

  // Always include baseline risks
  risks.push('Zero-day prompt injection techniques not yet cataloged')
  risks.push('Multi-modal attacks (vision, audio) not currently covered')

  return risks
}

/**
 * Estimate false negative rate from available statistics.
 * This is inherently an estimate since false negatives are hard to observe.
 */
function estimateFalseNegativeRate(stats: LearningStats): number {
  // Use red team results as a proxy for false negative rate
  if (stats.redTeamPatterns > 0 && stats.totalPatterns > 0) {
    // Assume red team found some evasions; estimate based on ratio
    const detectionRatio = stats.totalPatterns / (stats.totalPatterns + stats.redTeamPatterns)
    return Math.round((1 - detectionRatio) * 1000) / 1000
  }

  // Without red team data, use a conservative estimate
  return 0.05 // 5% estimated FN rate
}

/**
 * Compute benchmark results from learning statistics.
 */
function computeBenchmarks(stats: LearningStats): Record<string, number> {
  const totalChecks = stats.topPatterns.reduce(
    (sum, p) => sum + p.hitCount + p.falsePositiveCount,
    0,
  )

  const truePositives = stats.topPatterns.reduce((sum, p) => sum + p.hitCount, 0)
  const falsePositives = stats.topPatterns.reduce((sum, p) => sum + p.falsePositiveCount, 0)

  const precision = totalChecks > 0 ? truePositives / (truePositives + falsePositives) : 0
  const patternCoverage = stats.totalPatterns > 0
    ? (stats.builtinPatterns + stats.learnedPatterns + stats.communityPatterns) / stats.totalPatterns
    : 0

  return {
    precision: Math.round(precision * 1000) / 1000,
    patternCoverage: Math.round(patternCoverage * 1000) / 1000,
    totalPatternsActive: stats.totalPatterns,
    incidentsLast24h: stats.recentIncidents,
    falsePositiveRate: stats.falsePositiveRate,
  }
}
