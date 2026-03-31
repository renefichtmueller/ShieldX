/**
 * RAG pipeline defense (P1).
 * Detects injection patterns in retrieved documents, scores document
 * integrity, and tracks provenance per document source.
 */

import type { ScanResult } from '../types/detection.js'

/** Document integrity score result */
interface DocumentScore {
  readonly integrityScore: number
  readonly suspicious: boolean
  readonly indicators: readonly string[]
}

/** Document input for batch scanning */
interface RetrievedDoc {
  readonly content: string
  readonly source: string
}

/**
 * Patterns that indicate injection attempts within retrieved documents.
 * Legitimate data-only documents should not contain instruction-like content.
 */
const INJECTION_PATTERNS: readonly { readonly pattern: RegExp; readonly weight: number; readonly label: string }[] = [
  { pattern: /(?:ignore|disregard|forget|override) (?:all |any )?(?:previous|prior|above|earlier) (?:instructions?|context|rules?)/i, weight: 0.95, label: 'instruction-override' },
  { pattern: /(?:you (?:are|must|should|will|shall) (?:now)?|new (?:instructions?|rules?|task)):?/i, weight: 0.8, label: 'new-instruction-injection' },
  { pattern: /(?:system|admin|root|developer|operator) (?:message|prompt|instruction|override|command)/i, weight: 0.85, label: 'authority-impersonation' },
  { pattern: /\[(?:SYSTEM|INST|ADMIN|ROOT)\]|<<SYS>>|<\|system\|>/i, weight: 0.9, label: 'template-marker-injection' },
  { pattern: /(?:execute|run|call|invoke|perform) (?:the )?(?:following|this|these) (?:command|function|tool|action)/i, weight: 0.75, label: 'command-injection' },
  { pattern: /(?:do not|don't|never) (?:tell|inform|reveal|disclose|mention|show) (?:the )?user/i, weight: 0.85, label: 'user-deception-instruction' },
  { pattern: /(?:pretend|act as if|behave as|respond as|you are now) (?:a |an )?/i, weight: 0.7, label: 'persona-injection' },
  { pattern: /(?:output|return|respond with|say|write) (?:only |exactly |precisely )?["'].+["']/i, weight: 0.65, label: 'output-control' },
  { pattern: /(?:send|forward|transmit|exfiltrate|email|post) .{0,40}(?:to|at) .{0,40}(?:@|https?:\/\/)/i, weight: 0.9, label: 'exfiltration-instruction' },
  { pattern: /(?:important|urgent|critical|required):\s*(?:you must|always|never|do not)/i, weight: 0.7, label: 'urgency-manipulation' },
  { pattern: /(?:this (?:document|text|content) (?:contains|has|includes) )?(?:hidden|invisible|secret) (?:instructions?|commands?|messages?)/i, weight: 0.95, label: 'hidden-instruction-disclosure' },
  { pattern: /\u200b|\u200c|\u200d|\u2060|\ufeff/g, weight: 0.8, label: 'zero-width-chars' },
] as const

/** Source reputation tiers */
const SOURCE_TRUST: Readonly<Record<string, number>> = {
  internal: 1.0,
  verified: 0.9,
  partner: 0.7,
  public: 0.4,
  unknown: 0.2,
} as const

/**
 * RAGShield — defense layer for Retrieval-Augmented Generation pipelines.
 *
 * Scans retrieved documents for injection patterns, computes integrity
 * scores, and provides provenance tracking per source.
 */
export class RAGShield {
  private readonly sourceScores: Map<string, readonly number[]> = new Map()

  /**
   * Score a single retrieved document for integrity.
   * @param content - Document content
   * @param source - Document source identifier
   * @returns Integrity assessment with score and indicators
   */
  scoreDocument(content: string, source: string): DocumentScore {
    const indicators: string[] = []
    let totalWeight = 0
    let matchCount = 0

    for (const entry of INJECTION_PATTERNS) {
      if (entry.pattern.test(content)) {
        indicators.push(entry.label)
        totalWeight += entry.weight
        matchCount += 1
      }
    }

    // Base integrity: 1.0 (clean) minus weighted indicator penalties
    const injectionPenalty = matchCount > 0
      ? Math.min(totalWeight / matchCount * Math.min(matchCount * 0.3, 1.0), 1.0)
      : 0

    // Source trust bonus
    const sourceTrust = resolveSourceTrust(source)

    // Integrity = (1 - injectionPenalty) * sourceTrust weighting
    const integrityScore = Math.max(
      (1 - injectionPenalty) * (0.7 + sourceTrust * 0.3),
      0,
    )

    const roundedScore = Math.round(integrityScore * 1000) / 1000

    // Track source scores for provenance
    this.trackSourceScore(source, roundedScore)

    return Object.freeze({
      integrityScore: roundedScore,
      suspicious: roundedScore < 0.6 || indicators.length >= 2,
      indicators: Object.freeze([...indicators]),
    })
  }

  /**
   * Scan a batch of retrieved documents.
   * @param docs - Array of retrieved documents with content and source
   * @returns Aggregated scan result
   */
  scanRetrievedDocs(docs: readonly RetrievedDoc[]): ScanResult {
    const startTime = performance.now()
    const allIndicators: string[] = []
    let worstScore = 1.0
    let detected = false

    for (const doc of docs) {
      const score = this.scoreDocument(doc.content, doc.source)
      if (score.suspicious) {
        detected = true
      }
      if (score.integrityScore < worstScore) {
        worstScore = score.integrityScore
      }
      allIndicators.push(
        ...score.indicators.map((ind) => `[${doc.source}] ${ind}`),
      )
    }

    const confidence = 1 - worstScore
    const latencyMs = Math.round((performance.now() - startTime) * 100) / 100

    return Object.freeze({
      scannerId: 'rag-shield',
      scannerType: 'rag_shield' as const,
      detected,
      confidence: Math.round(confidence * 1000) / 1000,
      threatLevel: confidenceToThreat(confidence),
      killChainPhase: detected ? 'initial_access' as const : 'none' as const,
      matchedPatterns: Object.freeze([...allIndicators]),
      latencyMs,
      metadata: Object.freeze({
        documentCount: docs.length,
        worstIntegrityScore: worstScore,
      }),
    })
  }

  /**
   * Get provenance summary for a source.
   * @param source - Source identifier
   * @returns Average integrity score for the source, or undefined
   */
  getSourceReputation(source: string): number | undefined {
    const scores = this.sourceScores.get(source)
    if (scores === undefined || scores.length === 0) return undefined
    const sum = scores.reduce((a, b) => a + b, 0)
    return Math.round((sum / scores.length) * 1000) / 1000
  }

  /** Track a score for provenance monitoring */
  private trackSourceScore(source: string, score: number): void {
    const existing = this.sourceScores.get(source) ?? []
    // Keep last 100 scores per source
    const updated = [...existing, score].slice(-100)
    this.sourceScores.set(source, Object.freeze(updated))
  }
}

/** Resolve source trust level from source identifier */
function resolveSourceTrust(source: string): number {
  const lower = source.toLowerCase()
  for (const [key, value] of Object.entries(SOURCE_TRUST)) {
    if (lower.includes(key)) return value
  }
  return SOURCE_TRUST['unknown'] ?? 0.2
}

/** Map confidence to threat level */
function confidenceToThreat(confidence: number): 'none' | 'low' | 'medium' | 'high' | 'critical' {
  if (confidence >= 0.9) return 'critical'
  if (confidence >= 0.7) return 'high'
  if (confidence >= 0.5) return 'medium'
  if (confidence >= 0.3) return 'low'
  return 'none'
}
