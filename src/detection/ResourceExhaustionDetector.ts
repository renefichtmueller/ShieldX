/**
 * Resource Exhaustion Detector — ShieldX Early-Pipeline Defense
 *
 * Detects prompts designed to cause resource exhaustion (DoS-via-LLM):
 * 1. Token Bomb Detection — massive output generation triggers
 * 2. Context Window Stuffing — input designed to fill context
 * 3. Recursive/Loop Patterns — infinite continuation directives
 * 4. Batch Amplification — high-multiplier iteration requests
 *
 * Runs EARLY in the pipeline (before expensive scanners) to reject
 * token bombs and DoS attempts before they waste compute.
 *
 * Research references:
 * - OWASP LLM04:2025 Model Denial of Service
 * - Sponge Examples (Shumailov et al. 2021) — energy-latency attacks
 * - Schneier et al. 2026 Promptware Kill Chain (actions_on_objective)
 * - MITRE ATLAS AML.T0029 (Denial of ML Service)
 *
 * Performance target: <5ms for full scan. All regex pre-compiled at module load.
 */

import type { ScanResult, KillChainPhase, ThreatLevel } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a frozen ScanResult matching the orchestrator's expected shape */
function makeResult(
  ruleId: string,
  phase: KillChainPhase,
  confidence: number,
  threatLevel: ThreatLevel,
  description: string,
  matchedText: string,
  latencyMs: number,
): ScanResult {
  return Object.freeze({
    scannerId: ruleId,
    scannerType: 'resource' as const,
    detected: true,
    confidence,
    threatLevel,
    killChainPhase: phase,
    matchedPatterns: Object.freeze([matchedText.substring(0, 120)]),
    latencyMs,
    metadata: Object.freeze({ description, matchedText: matchedText.substring(0, 200) }),
  })
}

/** Map confidence to threat level */
function toThreatLevel(confidence: number): ThreatLevel {
  if (confidence >= 0.9) return 'critical'
  if (confidence >= 0.75) return 'high'
  if (confidence >= 0.5) return 'medium'
  if (confidence >= 0.25) return 'low'
  return 'none'
}

// ---------------------------------------------------------------------------
// Configurable Thresholds
// ---------------------------------------------------------------------------

export interface ResourceExhaustionThresholds {
  /** Word/line count threshold for token bomb (default: 5000) */
  readonly tokenBombWordThreshold: number
  /** Repeat count threshold (default: 100) */
  readonly repeatCountThreshold: number
  /** Max input length in chars before flagging stuffing (default: 50000) */
  readonly maxInputLength: number
  /** Max phrase repetitions before flagging (default: 20) */
  readonly maxPhraseRepetitions: number
  /** Minimum entropy for text of significant length (default: 2.0) */
  readonly minEntropyThreshold: number
  /** Batch item count threshold (default: 50) */
  readonly batchItemThreshold: number
}

const DEFAULT_THRESHOLDS: Readonly<ResourceExhaustionThresholds> = Object.freeze({
  tokenBombWordThreshold: 5000,
  repeatCountThreshold: 100,
  maxInputLength: 50000,
  maxPhraseRepetitions: 20,
  minEntropyThreshold: 2.0,
  batchItemThreshold: 50,
})

// ---------------------------------------------------------------------------
// 1. Token Bomb Detection
// ---------------------------------------------------------------------------

/**
 * Pre-compiled patterns for massive output generation requests.
 * Captures numeric values for threshold comparison.
 */
const TOKEN_BOMB_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly extractNumber: (match: RegExpExecArray) => number
}> = Object.freeze([
  {
    pattern: /\b(?:write|generate|create|produce|output|give\s+me)\b[^.]{0,40}\b(\d[\d,]*)\s*(?:thousand|million|billion|k\b)/i,
    id: 'resource-token-bomb-scale-word',
    description: 'Output request with scale multiplier (thousand/million/billion)',
    extractNumber: (m: RegExpExecArray): number => {
      const base = parseInt((m[1] ?? '0').replace(/,/g, ''), 10)
      const text = m[0].toLowerCase()
      if (text.includes('billion')) return base * 1_000_000_000
      if (text.includes('million')) return base * 1_000_000
      if (text.includes('thousand') || /\dk\b/.test(text)) return base * 1_000
      return base
    },
  },
  {
    pattern: /\b(?:write|generate|create|produce|output|give\s+me)\b[^.]{0,40}\b(\d[\d,]*)\s*(?:words?|lines?|paragraphs?|pages?|sentences?|characters?|tokens?)\b/i,
    id: 'resource-token-bomb-count',
    description: 'Output request with explicit large count',
    extractNumber: (m: RegExpExecArray): number => parseInt((m[1] ?? '0').replace(/,/g, ''), 10),
  },
  {
    pattern: /\brepeat\b[^.]{0,30}\b(\d[\d,]*)\s*times?\b/i,
    id: 'resource-token-bomb-repeat',
    description: 'Repeat N times directive',
    extractNumber: (m: RegExpExecArray): number => parseInt((m[1] ?? '0').replace(/,/g, ''), 10),
  },
  {
    pattern: /\b(?:enumerate|list)\b[^.]{0,20}\b(?:every|all)\s+(?:possible|potential)\s+(?:combination|permutation|variation)s?\b/i,
    id: 'resource-token-bomb-enumerate',
    description: 'Enumerate all possible combinations/permutations',
    extractNumber: (): number => Infinity,
  },
  {
    pattern: /\b(?:list|generate)\s+all\s+(?:possible\s+)?permutations?\b/i,
    id: 'resource-token-bomb-permutations',
    description: 'Generate all permutations request',
    extractNumber: (): number => Infinity,
  },
]) as ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly extractNumber: (match: RegExpExecArray) => number
}>

// ---------------------------------------------------------------------------
// 2. Context Window Stuffing (threshold-based, not regex)
// ---------------------------------------------------------------------------

// Handled in scanContextStuffing method — uses character counting + repetition analysis

// ---------------------------------------------------------------------------
// 3. Recursive/Loop Patterns
// ---------------------------------------------------------------------------

const RECURSIVE_LOOP_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}> = Object.freeze([
  {
    pattern: /\b(?:keep\s+going|continue)\s+(?:until|forever|indefinitely|endlessly|without\s+stopping)\b/i,
    id: 'resource-loop-keep-going',
    description: 'Instruction to continue indefinitely',
    confidence: 0.82,
  },
  {
    pattern: /\b(?:don'?t|do\s+not|never)\s+stop\b/i,
    id: 'resource-loop-dont-stop',
    description: 'Instruction to never stop generating',
    confidence: 0.78,
  },
  {
    pattern: /\brepeat\s+(?:yourself|this|that|the\s+(?:above|following))\s+(?:again\s+and\s+again|over\s+and\s+over|forever|indefinitely|endlessly)\b/i,
    id: 'resource-loop-repeat-forever',
    description: 'Instruction to repeat output indefinitely',
    confidence: 0.85,
  },
  {
    pattern: /\bsay\s+(?:that|this|it)\s+again\s+and\s+again\b/i,
    id: 'resource-loop-say-again',
    description: 'Instruction to repeat speech indefinitely',
    confidence: 0.8,
  },
  {
    pattern: /\b(?:apply|run|execute)\s+(?:these|this|the)\s+instructions?\s+(?:to|on|against)\s+(?:the\s+)?(?:output|result|response)\s+(?:of\s+)?(?:these|this|the)\s+instructions?\b/i,
    id: 'resource-loop-self-referencing',
    description: 'Self-referencing instructions (recursive loop)',
    confidence: 0.9,
  },
  {
    pattern: /\b(?:continue|go\s+on|keep\s+writing)\s+(?:until\s+(?:i|you)\s+(?:say|tell)\s+(?:you\s+to\s+)?stop|without\s+limit)\b/i,
    id: 'resource-loop-until-stop',
    description: 'Continue until told to stop (unbounded generation)',
    confidence: 0.75,
  },
  {
    pattern: /\b(?:infinite|unlimited|unbounded|endless)\s+(?:loop|output|generation|response|text)\b/i,
    id: 'resource-loop-infinite-keyword',
    description: 'Explicit request for infinite/unlimited output',
    confidence: 0.88,
  },
]) as ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}>

// ---------------------------------------------------------------------------
// 4. Batch Amplification
// ---------------------------------------------------------------------------

const BATCH_AMPLIFICATION_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly extractNumber: (match: RegExpExecArray) => number
}> = Object.freeze([
  {
    pattern: /\bfor\s+each\s+(?:of\s+)?(?:the\s+)?(?:following\s+)?(\d[\d,]*)\s+(?:items?|entries?|records?|elements?|rows?|things?)\b/i,
    id: 'resource-batch-for-each',
    description: 'For-each iteration over large item set',
    extractNumber: (m: RegExpExecArray): number => parseInt((m[1] ?? '0').replace(/,/g, ''), 10),
  },
  {
    pattern: /\b(?:call|run|execute|apply|invoke)\b[^.]{0,20}\bfor\s+(?:every|each|all)\b/i,
    id: 'resource-batch-call-every',
    description: 'Call/execute for every item pattern',
    extractNumber: (): number => Infinity,
  },
  {
    pattern: /\bprocess\s+(?:all\s+)?(\d[\d,]*)\s+(?:records?|items?|entries?|rows?|documents?|files?)\b/i,
    id: 'resource-batch-process-records',
    description: 'Process N records where N is very large',
    extractNumber: (m: RegExpExecArray): number => parseInt((m[1] ?? '0').replace(/,/g, ''), 10),
  },
]) as ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly extractNumber: (match: RegExpExecArray) => number
}>

// ---------------------------------------------------------------------------
// Shannon Entropy (lightweight inline version)
// ---------------------------------------------------------------------------

/** Compute Shannon entropy of a string in bits per character */
function shannonEntropy(s: string): number {
  if (s.length === 0) return 0
  const freq: Record<string, number> = {}
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!
    freq[ch] = (freq[ch] ?? 0) + 1
  }
  let entropy = 0
  const len = s.length
  for (const count of Object.values(freq)) {
    const p = count / len
    if (p > 0) {
      entropy -= p * Math.log2(p)
    }
  }
  return entropy
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * ResourceExhaustionDetector — Early-pipeline DoS defense.
 *
 * All patterns are pre-compiled at module load time for zero allocation
 * during scans. Designed to run before expensive scanners to reject
 * resource exhaustion attempts fast.
 *
 * Usage:
 * ```typescript
 * const detector = new ResourceExhaustionDetector()
 * const results = detector.scan('write 100000 words about...')
 * ```
 */
export class ResourceExhaustionDetector {
  private readonly thresholds: Readonly<ResourceExhaustionThresholds>

  constructor(thresholds?: Partial<ResourceExhaustionThresholds>) {
    this.thresholds = Object.freeze({
      ...DEFAULT_THRESHOLDS,
      ...(thresholds ?? {}),
    })
  }

  /**
   * Scan input text for resource exhaustion patterns.
   *
   * Checks all four categories and returns a ScanResult for every
   * detected pattern.
   *
   * @param input - The user input string
   * @returns Readonly array of ScanResult objects for detected threats
   */
  scan(input: string): readonly ScanResult[] {
    const start = performance.now()
    const results: ScanResult[] = []

    // Skip trivially short inputs
    if (input.length < 10) return Object.freeze([])

    // 1. Token bomb detection
    this.scanTokenBombs(input, start, results)

    // 2. Context window stuffing
    this.scanContextStuffing(input, start, results)

    // 3. Recursive/loop patterns
    this.scanRecursiveLoops(input, start, results)

    // 4. Batch amplification
    this.scanBatchAmplification(input, start, results)

    return Object.freeze(results)
  }

  // -------------------------------------------------------------------------
  // Private scan helpers
  // -------------------------------------------------------------------------

  /**
   * 1. Token Bomb Detection
   * Matches patterns requesting massive output, then checks extracted
   * numeric values against configurable thresholds.
   */
  private scanTokenBombs(
    input: string,
    start: number,
    results: ScanResult[],
  ): void {
    for (const rule of TOKEN_BOMB_PATTERNS) {
      const match = rule.pattern.exec(input)
      if (match) {
        const extractedNumber = rule.extractNumber(match)

        // For enumerate/permutation patterns, always flag
        if (extractedNumber === Infinity) {
          results.push(
            makeResult(
              rule.id,
              'actions_on_objective',
              0.88,
              'high',
              rule.description,
              match[0],
              performance.now() - start,
            ),
          )
          continue
        }

        // Check repeat-specific threshold
        const isRepeat = rule.id === 'resource-token-bomb-repeat'
        const threshold = isRepeat
          ? this.thresholds.repeatCountThreshold
          : this.thresholds.tokenBombWordThreshold

        if (extractedNumber > threshold) {
          // Scale confidence by how far over threshold
          const ratio = extractedNumber / threshold
          const confidence = Math.min(0.6 + ratio * 0.1, 0.98)

          results.push(
            makeResult(
              rule.id,
              'actions_on_objective',
              confidence,
              toThreatLevel(confidence),
              `${rule.description} (requested: ${extractedNumber.toLocaleString()}, threshold: ${threshold.toLocaleString()})`,
              match[0],
              performance.now() - start,
            ),
          )
        }
      }
    }
  }

  /**
   * 2. Context Window Stuffing Detection
   * Checks for: very long input, high repetition ratio, low information density.
   */
  private scanContextStuffing(
    input: string,
    start: number,
    results: ScanResult[],
  ): void {
    // Check raw input length
    if (input.length > this.thresholds.maxInputLength) {
      const ratio = input.length / this.thresholds.maxInputLength
      const confidence = Math.min(0.5 + ratio * 0.15, 0.95)

      results.push(
        makeResult(
          'resource-stuffing-length',
          'actions_on_objective',
          confidence,
          toThreatLevel(confidence),
          `Input length (${input.length.toLocaleString()} chars) exceeds threshold (${this.thresholds.maxInputLength.toLocaleString()})`,
          `[${input.length} chars]`,
          performance.now() - start,
        ),
      )
    }

    // Check phrase repetition: split into words, count most frequent N-gram (3-word)
    if (input.length > 100) {
      const repetitionResult = this.detectHighRepetition(input)
      if (repetitionResult !== null) {
        results.push(
          makeResult(
            'resource-stuffing-repetition',
            'actions_on_objective',
            repetitionResult.confidence,
            toThreatLevel(repetitionResult.confidence),
            `High phrase repetition detected: "${repetitionResult.phrase}" repeated ${repetitionResult.count} times`,
            repetitionResult.phrase,
            performance.now() - start,
          ),
        )
      }
    }

    // Check information density (entropy) for long inputs
    if (input.length > 500) {
      const entropy = shannonEntropy(input)
      if (entropy < this.thresholds.minEntropyThreshold) {
        const confidence = Math.min(0.5 + (this.thresholds.minEntropyThreshold - entropy) * 0.3, 0.9)

        results.push(
          makeResult(
            'resource-stuffing-low-entropy',
            'actions_on_objective',
            confidence,
            toThreatLevel(confidence),
            `Low information density (entropy: ${entropy.toFixed(2)}, threshold: ${this.thresholds.minEntropyThreshold})`,
            `[entropy=${entropy.toFixed(2)}, length=${input.length}]`,
            performance.now() - start,
          ),
        )
      }
    }
  }

  /**
   * 3. Recursive/Loop Pattern Detection
   * Matches patterns that request unbounded or infinite generation.
   */
  private scanRecursiveLoops(
    input: string,
    start: number,
    results: ScanResult[],
  ): void {
    for (const rule of RECURSIVE_LOOP_PATTERNS) {
      const match = rule.pattern.exec(input)
      if (match) {
        results.push(
          makeResult(
            rule.id,
            'actions_on_objective',
            rule.confidence,
            toThreatLevel(rule.confidence),
            rule.description,
            match[0],
            performance.now() - start,
          ),
        )
      }
    }
  }

  /**
   * 4. Batch Amplification Detection
   * Matches patterns with high iteration counts over item sets.
   */
  private scanBatchAmplification(
    input: string,
    start: number,
    results: ScanResult[],
  ): void {
    for (const rule of BATCH_AMPLIFICATION_PATTERNS) {
      const match = rule.pattern.exec(input)
      if (match) {
        const extractedNumber = rule.extractNumber(match)

        // For "call X for every" patterns, always flag
        if (extractedNumber === Infinity) {
          results.push(
            makeResult(
              rule.id,
              'actions_on_objective',
              0.75,
              'high',
              rule.description,
              match[0],
              performance.now() - start,
            ),
          )
          continue
        }

        if (extractedNumber > this.thresholds.batchItemThreshold) {
          const ratio = extractedNumber / this.thresholds.batchItemThreshold
          const confidence = Math.min(0.55 + ratio * 0.1, 0.95)

          results.push(
            makeResult(
              rule.id,
              'actions_on_objective',
              confidence,
              toThreatLevel(confidence),
              `${rule.description} (count: ${extractedNumber.toLocaleString()}, threshold: ${this.thresholds.batchItemThreshold})`,
              match[0],
              performance.now() - start,
            ),
          )
        }
      }
    }
  }

  /**
   * Detect high-repetition 3-word phrases in input.
   * Returns the most repeated phrase and its count, or null if below threshold.
   */
  private detectHighRepetition(
    input: string,
  ): { readonly phrase: string; readonly count: number; readonly confidence: number } | null {
    const words = input.toLowerCase().split(/\s+/).filter(w => w.length > 0)
    if (words.length < 6) return null

    const ngramCounts = new Map<string, number>()
    for (let i = 0; i <= words.length - 3; i++) {
      const ngram = `${words[i]} ${words[i + 1]} ${words[i + 2]}`
      ngramCounts.set(ngram, (ngramCounts.get(ngram) ?? 0) + 1)
    }

    let maxPhrase = ''
    let maxCount = 0
    for (const [phrase, count] of ngramCounts) {
      if (count > maxCount) {
        maxCount = count
        maxPhrase = phrase
      }
    }

    if (maxCount >= this.thresholds.maxPhraseRepetitions) {
      const confidence = Math.min(0.5 + (maxCount / this.thresholds.maxPhraseRepetitions) * 0.2, 0.95)
      return { phrase: maxPhrase, count: maxCount, confidence }
    }

    return null
  }
}
