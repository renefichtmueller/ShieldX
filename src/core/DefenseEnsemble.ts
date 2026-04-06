/**
 * DefenseEnsemble — ShieldX Phase 3: Ensemble Voting Layer.
 *
 * Three independent voters (Rule-Based, Semantic, Behavioral) evaluate
 * disjoint subsets of ScanResult[], then a weighted-majority aggregation
 * produces the final EnsembleVerdict.
 *
 * Voter weights:
 *   Rule-Based   0.35
 *   Semantic     0.30
 *   Behavioral   0.35
 *
 * Decision logic:
 *   2+ voters 'threat'     → final 'threat'
 *   2+ voters 'suspicious' → final 'suspicious'
 *   otherwise              → final 'clean'
 *   unanimous 'threat'     → confidence boosted +0.1 (capped 1.0)
 *
 * All returned objects are deeply frozen (immutable).
 */

import type { ScanResult, ScannerType, ThreatLevel } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

/** Vote produced by a single voter */
export interface VoterVerdict {
  readonly voterId: string
  readonly vote: 'clean' | 'suspicious' | 'threat'
  readonly confidence: number
  readonly maxThreatLevel: ThreatLevel
  readonly resultCount: number
  readonly detectedCount: number
}

/** Aggregated verdict from the DefenseEnsemble */
export interface EnsembleVerdict {
  readonly finalVote: 'clean' | 'suspicious' | 'threat'
  readonly finalConfidence: number
  readonly maxThreatLevel: ThreatLevel
  readonly ruleVoter: VoterVerdict
  readonly semanticVoter: VoterVerdict
  readonly behavioralVoter: VoterVerdict
  readonly unanimous: boolean
  readonly evaluatedAt: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Voter weight distribution (must sum to 1.0) */
const WEIGHTS = Object.freeze({
  rule: 0.35,
  semantic: 0.30,
  behavioral: 0.35,
} as const)

/** Confidence boost when all three voters agree on 'threat' */
const UNANIMOUS_BOOST = 0.1

/** Detection ratio thresholds for voter verdicts */
const RATIO_THREAT = 0.5
const RATIO_SUSPICIOUS = 0.2

/** Threat level severity ordering (higher index = more severe) */
const THREAT_SEVERITY: readonly ThreatLevel[] = Object.freeze([
  'none', 'low', 'medium', 'high', 'critical',
])

// ---------------------------------------------------------------------------
// Scanner-to-voter classification
// ---------------------------------------------------------------------------

/** ScannerTypes routed to the RuleBasedVoter */
const RULE_SCANNER_TYPES: ReadonlySet<ScannerType> = new Set<ScannerType>([
  'rule', 'tokenizer', 'entropy', 'unicode',
])

/** ScannerTypes routed to the SemanticVoter */
const SEMANTIC_SCANNER_TYPES: ReadonlySet<ScannerType> = new Set<ScannerType>([
  'embedding', 'sentinel',
])

/** ScannerTypes routed to the BehavioralVoter */
const BEHAVIORAL_SCANNER_TYPES: ReadonlySet<ScannerType> = new Set<ScannerType>([
  'behavioral', 'conversation', 'context_integrity',
  'memory_integrity', 'intent_guard', 'tool_chain',
])

/** ScannerId substrings that override type-based classification */
const RULE_ID_PATTERNS: readonly string[] = Object.freeze([
  'cipher', 'emoji', 'upside', 'unicode', 'entropy',
  'rule', 'indirect', 'resource', 'output-payload',
])

const SEMANTIC_ID_PATTERNS: readonly string[] = Object.freeze([
  'semantic', 'embedding', 'sentinel',
])

const BEHAVIORAL_ID_PATTERNS: readonly string[] = Object.freeze([
  'conversation', 'intent', 'context', 'auth',
  'decomposition', 'tool-call', 'melon',
])

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

type VoterCategory = 'rule' | 'semantic' | 'behavioral'

function classifyResult(result: ScanResult): VoterCategory | null {
  const id = result.scannerId.toLowerCase()

  if (RULE_SCANNER_TYPES.has(result.scannerType)) return 'rule'
  if (SEMANTIC_SCANNER_TYPES.has(result.scannerType)) return 'semantic'
  if (BEHAVIORAL_SCANNER_TYPES.has(result.scannerType)) return 'behavioral'

  if (RULE_ID_PATTERNS.some((p) => id.includes(p))) return 'rule'
  if (SEMANTIC_ID_PATTERNS.some((p) => id.includes(p))) return 'semantic'
  if (BEHAVIORAL_ID_PATTERNS.some((p) => id.includes(p))) return 'behavioral'

  return null
}

function partitionResults(
  results: readonly ScanResult[],
): Readonly<Record<VoterCategory, readonly ScanResult[]>> {
  const rule: ScanResult[] = []
  const semantic: ScanResult[] = []
  const behavioral: ScanResult[] = []

  for (const result of results) {
    const category = classifyResult(result)
    if (category === 'rule') rule.push(result)
    else if (category === 'semantic') semantic.push(result)
    else if (category === 'behavioral') behavioral.push(result)
    // Unclassified results are intentionally dropped — each voter
    // only sees results from its domain.
  }

  return Object.freeze({
    rule: Object.freeze(rule),
    semantic: Object.freeze(semantic),
    behavioral: Object.freeze(behavioral),
  })
}

// ---------------------------------------------------------------------------
// Threat level helpers
// ---------------------------------------------------------------------------

function threatSeverityIndex(level: ThreatLevel): number {
  const idx = THREAT_SEVERITY.indexOf(level)
  return idx >= 0 ? idx : 0
}

function highestThreatLevel(results: readonly ScanResult[]): ThreatLevel {
  let maxIdx = 0
  for (const r of results) {
    const idx = threatSeverityIndex(r.threatLevel)
    if (idx > maxIdx) maxIdx = idx
  }
  return THREAT_SEVERITY[maxIdx] ?? 'none'
}

// ---------------------------------------------------------------------------
// Individual voter evaluation
// ---------------------------------------------------------------------------

function evaluateVoter(
  voterId: string,
  results: readonly ScanResult[],
): VoterVerdict {
  if (results.length === 0) {
    return Object.freeze({
      voterId,
      vote: 'clean' as const,
      confidence: 0,
      maxThreatLevel: 'none' as const,
      resultCount: 0,
      detectedCount: 0,
    })
  }

  const detectedResults = results.filter((r) => r.detected)
  const detectedCount = detectedResults.length
  const detectedRatio = detectedCount / results.length

  const avgConfidence = detectedCount > 0
    ? detectedResults.reduce((sum, r) => sum + r.confidence, 0) / detectedCount
    : 0

  const maxThreat = highestThreatLevel(results)
  const hasHighOrCritical = results.some(
    (r) => r.threatLevel === 'high' || r.threatLevel === 'critical',
  )

  let vote: VoterVerdict['vote']
  if (detectedRatio >= RATIO_THREAT) {
    vote = 'threat'
  } else if (detectedRatio >= RATIO_SUSPICIOUS || hasHighOrCritical) {
    vote = 'suspicious'
  } else {
    vote = 'clean'
  }

  return Object.freeze({
    voterId,
    vote,
    confidence: Math.round(avgConfidence * 1000) / 1000,
    maxThreatLevel: maxThreat,
    resultCount: results.length,
    detectedCount,
  })
}

// ---------------------------------------------------------------------------
// Ensemble aggregation
// ---------------------------------------------------------------------------

type VoteLevel = 'clean' | 'suspicious' | 'threat'

const VOTE_SEVERITY: Readonly<Record<VoteLevel, number>> = Object.freeze({
  clean: 0,
  suspicious: 1,
  threat: 2,
})

function aggregateVotes(
  ruleVoter: VoterVerdict,
  semanticVoter: VoterVerdict,
  behavioralVoter: VoterVerdict,
): { readonly finalVote: VoteLevel; readonly finalConfidence: number; readonly unanimous: boolean } {
  const votes: readonly VoterVerdict[] = [ruleVoter, semanticVoter, behavioralVoter]

  const threatCount = votes.filter((v) => v.vote === 'threat').length
  const suspiciousOrHigherCount = votes.filter(
    (v) => VOTE_SEVERITY[v.vote] >= VOTE_SEVERITY['suspicious'],
  ).length

  let finalVote: VoteLevel
  if (threatCount >= 2) {
    finalVote = 'threat'
  } else if (suspiciousOrHigherCount >= 2) {
    finalVote = 'suspicious'
  } else {
    finalVote = 'clean'
  }

  const weightedConfidence =
    ruleVoter.confidence * WEIGHTS.rule +
    semanticVoter.confidence * WEIGHTS.semantic +
    behavioralVoter.confidence * WEIGHTS.behavioral

  const unanimous = threatCount === 3
  const boostedConfidence = unanimous
    ? Math.min(weightedConfidence + UNANIMOUS_BOOST, 1.0)
    : weightedConfidence

  const finalConfidence = Math.round(boostedConfidence * 1000) / 1000

  return Object.freeze({ finalVote, finalConfidence, unanimous })
}

// ---------------------------------------------------------------------------
// DefenseEnsemble
// ---------------------------------------------------------------------------

/**
 * Defense Ensemble — weighted majority voting across three independent voters.
 *
 * Classifies each ScanResult by scanner type/id, feeds subsets to the
 * Rule-Based, Semantic, and Behavioral voters, then aggregates their
 * verdicts into a final EnsembleVerdict.
 *
 * Stateless: no mutable fields, every call to evaluate() is independent.
 *
 * @example
 * ```typescript
 * const ensemble = new DefenseEnsemble()
 * const verdict = ensemble.evaluate(scanResults)
 * if (verdict.finalVote === 'threat') blockRequest()
 * ```
 */
export class DefenseEnsemble {
  /**
   * Evaluate a set of ScanResults and produce an ensemble verdict.
   *
   * @param results - Array of ScanResult from the ShieldX pipeline scanners
   * @returns Frozen EnsembleVerdict with individual voter verdicts + final decision
   */
  evaluate(results: readonly ScanResult[]): EnsembleVerdict {
    const partitions = partitionResults(results)

    const ruleVoter = evaluateVoter('rule-based-voter', partitions.rule)
    const semanticVoter = evaluateVoter('semantic-voter', partitions.semantic)
    const behavioralVoter = evaluateVoter('behavioral-voter', partitions.behavioral)

    const { finalVote, finalConfidence, unanimous } = aggregateVotes(
      ruleVoter,
      semanticVoter,
      behavioralVoter,
    )

    const allResults = [
      ...partitions.rule,
      ...partitions.semantic,
      ...partitions.behavioral,
    ]
    const maxThreatLevel = allResults.length > 0
      ? highestThreatLevel(allResults)
      : 'none' as ThreatLevel

    return Object.freeze({
      finalVote,
      finalConfidence,
      maxThreatLevel,
      ruleVoter,
      semanticVoter,
      behavioralVoter,
      unanimous,
      evaluatedAt: new Date().toISOString(),
    })
  }
}
