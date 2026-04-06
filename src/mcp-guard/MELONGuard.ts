/**
 * MELONGuard — Masked Execution Logic for MCP (ICML 2025-inspired).
 *
 * Lightweight heuristic implementation of the MELON concept:
 * When a tool call is about to execute, determine whether it is
 * driven by the USER's intent or by INJECTED content.
 *
 * Detection approach:
 * 1. Argument Injection: Run RuleEngine on stringified tool arguments
 * 2. Tool Result Reference: Check if arguments contain substrings from
 *    previous tool results (indirect injection propagation)
 * 3. Context Mismatch: Heuristic check — does the tool call relate
 *    to what the user asked?
 * 4. Suspicious Pattern: Pre-compiled regex for common injection-in-args patterns
 *
 * All regex patterns are pre-compiled at module level for <5ms validation.
 *
 * Part of ShieldX Layer 7 (MCP Guard & Tool Security).
 *
 * References:
 * - MELON (ICML 2025) — >99% attack prevention for agentic systems
 * - Schneier et al. 2026 Promptware Kill Chain
 * - MITRE ATLAS AML.T0051 (LLM Prompt Injection)
 */

import type { RuleEngine } from '../detection/RuleEngine.js'
import type { IndirectInjectionDetector } from '../detection/IndirectInjectionDetector.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Configuration for the MELON guard */
export interface MELONConfig {
  readonly enabled: boolean
  readonly blockOnDetection: boolean
  readonly confidenceThreshold: number
}

/** Evidence of injection-driven tool call behavior */
export interface MELONEvidence {
  readonly type: 'argument_injection' | 'tool_result_reference' | 'context_mismatch' | 'suspicious_pattern'
  readonly detail: string
  readonly confidence: number
}

/** Result from MELON analysis */
export interface MELONResult {
  readonly injectionDriven: boolean
  readonly confidence: number
  readonly evidence: readonly MELONEvidence[]
  readonly recommendation: 'allow' | 'block' | 'review'
}

// ---------------------------------------------------------------------------
// Default configuration
// ---------------------------------------------------------------------------

export const DEFAULT_MELON_CONFIG: MELONConfig = Object.freeze({
  enabled: true,
  blockOnDetection: true,
  confidenceThreshold: 0.6,
})

// ---------------------------------------------------------------------------
// Pre-compiled patterns for argument-level injection detection
// ---------------------------------------------------------------------------

/** Instruction override patterns embedded in tool arguments */
const ARG_INSTRUCTION_OVERRIDE = /\b(?:ignore|disregard|forget|override|bypass)\b[^.]{0,30}\b(?:previous|prior|above|all|earlier)\b[^.]{0,30}\b(?:instructions?|prompts?|rules?|guidelines?)\b/i

/** Role reassignment in tool arguments */
const ARG_ROLE_REASSIGNMENT = /\byou\s+(?:are|must|should|will)\s+now\b[^.]{0,40}\b(?:act\s+as|behave\s+as|pretend|become|role)\b/i

/** System prompt prefix injected in arguments */
const ARG_SYSTEM_PREFIX = /^(?:system|assistant)\s*:/im

/** Special token delimiters in arguments */
const ARG_SPECIAL_TOKENS = /<\|(?:system|user|assistant|im_start|im_end|endoftext)\|>/i

/** Exfiltration via URL in arguments */
const ARG_EXFIL_URL = /https?:\/\/[^\s"']+[?&](?:data|token|key|secret|prompt|context|exfil|leak)=/i

/** Command injection patterns in non-shell tool arguments */
const ARG_COMMAND_INJECTION = /\$\(|`[^`]+`|\$\{.*\}|;\s*(?:curl|wget|nc|bash)\b/i

/** Hidden instruction after excessive whitespace */
const ARG_HIDDEN_WHITESPACE = /\n{5,}(?:ignore|disregard|system|you are|IMPORTANT)/i

/** Urgency prefix pattern */
const ARG_URGENCY_INJECTION = /\b(?:IMPORTANT|CRITICAL|URGENT|MANDATORY)\s*(?::|!)\s*(?:ignore|override|disregard|the following)\b/i

const SUSPICIOUS_ARG_PATTERNS: readonly {
  readonly pattern: RegExp
  readonly label: string
  readonly confidence: number
}[] = Object.freeze([
  { pattern: ARG_INSTRUCTION_OVERRIDE, label: 'instruction_override_in_args', confidence: 0.9 },
  { pattern: ARG_ROLE_REASSIGNMENT, label: 'role_reassignment_in_args', confidence: 0.88 },
  { pattern: ARG_SYSTEM_PREFIX, label: 'system_prefix_in_args', confidence: 0.85 },
  { pattern: ARG_SPECIAL_TOKENS, label: 'special_token_in_args', confidence: 0.92 },
  { pattern: ARG_EXFIL_URL, label: 'exfiltration_url_in_args', confidence: 0.85 },
  { pattern: ARG_COMMAND_INJECTION, label: 'command_injection_in_args', confidence: 0.82 },
  { pattern: ARG_HIDDEN_WHITESPACE, label: 'hidden_whitespace_injection', confidence: 0.8 },
  { pattern: ARG_URGENCY_INJECTION, label: 'urgency_injection_in_args', confidence: 0.78 },
])

/** Minimum substring length for tool result reference matching */
const MIN_REFERENCE_LENGTH = 20

/** Maximum tool result length to search (avoid perf issues on huge results) */
const MAX_RESULT_SEARCH_LENGTH = 50_000

// ---------------------------------------------------------------------------
// Weight constants for evidence aggregation
// ---------------------------------------------------------------------------

const EVIDENCE_WEIGHTS: Readonly<Record<MELONEvidence['type'], number>> = Object.freeze({
  argument_injection: 1.0,
  tool_result_reference: 0.85,
  context_mismatch: 0.6,
  suspicious_pattern: 0.9,
})

// ---------------------------------------------------------------------------
// Keyword extraction for context mismatch detection
// ---------------------------------------------------------------------------

/** Extract meaningful keywords from text (words with 4+ chars, lowercased) */
function extractKeywords(text: string): ReadonlySet<string> {
  const lower = text.toLowerCase()
  const words = lower.match(/\b[a-z]{4,}\b/g) ?? []
  // Deduplicate and exclude common stop words
  const stopWords = new Set([
    'that', 'this', 'with', 'from', 'have', 'been', 'will', 'would',
    'could', 'should', 'about', 'there', 'their', 'they', 'then',
    'than', 'what', 'when', 'where', 'which', 'while', 'were',
    'does', 'done', 'into', 'just', 'very', 'also', 'some', 'more',
    'other', 'each', 'only', 'over', 'such', 'after', 'before',
    'these', 'those', 'being', 'make', 'like', 'your', 'them',
  ])
  return new Set(words.filter(w => !stopWords.has(w)))
}

/**
 * Stringify tool arguments into a single searchable string.
 * Recursively walks objects and arrays.
 */
function stringifyArgs(args: Readonly<Record<string, unknown>>): string {
  const parts: string[] = []

  function walk(value: unknown): void {
    if (typeof value === 'string') {
      parts.push(value)
      return
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
      parts.push(String(value))
      return
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        walk(item)
      }
      return
    }
    if (value !== null && typeof value === 'object') {
      for (const v of Object.values(value as Record<string, unknown>)) {
        walk(v)
      }
    }
  }

  for (const v of Object.values(args)) {
    walk(v)
  }

  return parts.join(' ')
}

// ---------------------------------------------------------------------------
// MELONGuard Class
// ---------------------------------------------------------------------------

/**
 * MELONGuard — Masked Execution Logic for MCP tool calls.
 *
 * Analyzes whether a tool call is driven by user intent or injected content.
 * Combines rule engine scanning, tool result reference detection,
 * context mismatch analysis, and suspicious pattern matching.
 *
 * Usage:
 * ```typescript
 * const guard = new MELONGuard(config, ruleEngine, indirectDetector)
 * const result = guard.analyze('shell_exec', { command: 'rm -rf /' }, [], 'list files')
 * if (result.injectionDriven) {
 *   // Block the tool call
 * }
 * ```
 */
export class MELONGuard {
  private readonly config: MELONConfig
  private readonly ruleEngine: RuleEngine
  private readonly indirectDetector: IndirectInjectionDetector

  constructor(
    config: Partial<MELONConfig>,
    ruleEngine: RuleEngine,
    indirectDetector: IndirectInjectionDetector,
  ) {
    this.config = Object.freeze({ ...DEFAULT_MELON_CONFIG, ...config })
    this.ruleEngine = ruleEngine
    this.indirectDetector = indirectDetector
  }

  /**
   * Analyze a tool call for injection-driven behavior.
   *
   * @param toolName - Name of the tool being called
   * @param toolArgs - Arguments passed to the tool
   * @param toolResults - Previous tool results in context (for reference detection)
   * @param userPrompt - Original user prompt for context mismatch analysis
   * @returns MELONResult with injection assessment, confidence, and evidence
   */
  analyze(
    toolName: string,
    toolArgs: Readonly<Record<string, unknown>>,
    toolResults?: readonly string[],
    userPrompt?: string,
  ): MELONResult {
    if (!this.config.enabled) {
      return Object.freeze({
        injectionDriven: false,
        confidence: 0,
        evidence: Object.freeze([]),
        recommendation: 'allow' as const,
      })
    }

    const evidence: MELONEvidence[] = []
    const argsString = stringifyArgs(toolArgs)

    // 1. Argument Injection Check — run RuleEngine on stringified args
    this.checkArgumentInjection(argsString, evidence)

    // 2. Tool Result Reference — check if args contain substrings from tool results
    if (toolResults !== undefined && toolResults.length > 0) {
      this.checkToolResultReference(argsString, toolResults, evidence)
    }

    // 3. Context Mismatch — does the tool call relate to user intent?
    if (userPrompt !== undefined && userPrompt.length > 0) {
      this.checkContextMismatch(toolName, argsString, userPrompt, evidence)
    }

    // 4. Suspicious Pattern — pre-compiled regex for injection-in-args
    this.checkSuspiciousPatterns(argsString, evidence)

    // Aggregate evidence into final result
    return this.aggregateResult(evidence)
  }

  // -------------------------------------------------------------------------
  // Private detection methods
  // -------------------------------------------------------------------------

  /**
   * Check 1: Run the RuleEngine and IndirectInjectionDetector on tool arguments.
   * If the arguments alone trigger injection patterns, the tool call is likely
   * driven by injected content rather than user intent.
   */
  private checkArgumentInjection(argsString: string, evidence: MELONEvidence[]): void {
    if (argsString.length < 10) return

    // Rule engine scan on args
    const ruleResults = this.ruleEngine.scan(argsString)
    for (const result of ruleResults) {
      if (result.detected && result.confidence >= 0.5) {
        evidence.push(Object.freeze({
          type: 'argument_injection' as const,
          detail: `RuleEngine detected "${result.matchedPatterns[0] ?? result.scannerId}" in tool arguments (confidence: ${result.confidence.toFixed(2)})`,
          confidence: result.confidence,
        }))
      }
    }

    // Indirect injection scan on args
    const indirectResults = this.indirectDetector.scan(argsString)
    for (const result of indirectResults) {
      if (result.detected && result.confidence >= 0.5) {
        evidence.push(Object.freeze({
          type: 'argument_injection' as const,
          detail: `IndirectDetector detected "${result.matchedPatterns[0] ?? result.scannerId}" in tool arguments (confidence: ${result.confidence.toFixed(2)})`,
          confidence: result.confidence,
        }))
      }
    }
  }

  /**
   * Check 2: Detect if tool arguments reference content from previous tool results.
   * This indicates indirect injection propagation — the attacker injected payload
   * into a tool result, and it's now being echoed into subsequent tool calls.
   */
  private checkToolResultReference(
    argsString: string,
    toolResults: readonly string[],
    evidence: MELONEvidence[],
  ): void {
    if (argsString.length < MIN_REFERENCE_LENGTH) return

    for (let resultIndex = 0; resultIndex < toolResults.length; resultIndex++) {
      const toolResult = toolResults[resultIndex]
      if (toolResult === undefined || toolResult.length < MIN_REFERENCE_LENGTH) continue

      // Limit search length for performance
      const searchResult = toolResult.length > MAX_RESULT_SEARCH_LENGTH
        ? toolResult.slice(0, MAX_RESULT_SEARCH_LENGTH)
        : toolResult

      // Check for suspicious substrings shared between tool result and args.
      // Only flag if the shared substring is long enough to be non-trivial
      // and the tool result itself contains injection patterns.
      const resultScanResults = this.indirectDetector.scan(searchResult)
      const resultHasInjection = resultScanResults.some(r => r.detected)

      if (resultHasInjection) {
        // Check if any substantial substring from the tool result appears in args
        const overlap = this.findSubstringOverlap(argsString, searchResult)
        if (overlap !== null) {
          evidence.push(Object.freeze({
            type: 'tool_result_reference' as const,
            detail: `Tool arguments contain ${overlap.length}-char substring from tool result #${resultIndex + 1} which has injection patterns: "${overlap.slice(0, 80)}..."`,
            confidence: Math.min(0.95, 0.7 + (overlap.length / 200) * 0.25),
          }))
        }
      }
    }
  }

  /**
   * Check 3: Context mismatch between user prompt and tool call intent.
   * If the user asked about topic A but the tool call operates on topic B,
   * this may indicate the tool call was driven by injected content.
   */
  private checkContextMismatch(
    toolName: string,
    argsString: string,
    userPrompt: string,
    evidence: MELONEvidence[],
  ): void {
    const userKeywords = extractKeywords(userPrompt)
    const toolKeywords = extractKeywords(`${toolName} ${argsString}`)

    if (userKeywords.size === 0 || toolKeywords.size === 0) return

    // Compute Jaccard similarity between user intent and tool call intent
    let intersectionCount = 0
    for (const kw of toolKeywords) {
      if (userKeywords.has(kw)) {
        intersectionCount++
      }
    }

    const unionSize = new Set([...userKeywords, ...toolKeywords]).size
    const similarity = unionSize > 0 ? intersectionCount / unionSize : 0

    // Very low overlap suggests the tool call is not aligned with user intent
    if (similarity < 0.05 && toolKeywords.size >= 3) {
      evidence.push(Object.freeze({
        type: 'context_mismatch' as const,
        detail: `Tool call keywords have ${(similarity * 100).toFixed(1)}% overlap with user prompt (${intersectionCount}/${unionSize} shared keywords)`,
        confidence: Math.min(0.8, 0.5 + (1 - similarity) * 0.3),
      }))
    }
  }

  /**
   * Check 4: Pre-compiled regex patterns for common injection-in-arguments.
   */
  private checkSuspiciousPatterns(argsString: string, evidence: MELONEvidence[]): void {
    if (argsString.length < 10) return

    for (const { pattern, label, confidence } of SUSPICIOUS_ARG_PATTERNS) {
      if (pattern.test(argsString)) {
        evidence.push(Object.freeze({
          type: 'suspicious_pattern' as const,
          detail: `Suspicious pattern "${label}" detected in tool arguments`,
          confidence,
        }))
      }
      pattern.lastIndex = 0
    }
  }

  // -------------------------------------------------------------------------
  // Aggregation
  // -------------------------------------------------------------------------

  /**
   * Aggregate evidence into a final MELONResult.
   * Uses weighted maximum confidence with diminishing contributions
   * from additional evidence pieces.
   */
  private aggregateResult(evidence: readonly MELONEvidence[]): MELONResult {
    if (evidence.length === 0) {
      return Object.freeze({
        injectionDriven: false,
        confidence: 0,
        evidence: Object.freeze([]),
        recommendation: 'allow' as const,
      })
    }

    // Weighted confidence: max weighted evidence + diminishing contributions
    const weightedScores = evidence.map(e => e.confidence * EVIDENCE_WEIGHTS[e.type])
    const maxScore = Math.max(...weightedScores)
    const remainingSum = weightedScores
      .filter(s => s !== maxScore)
      .reduce((sum, s) => sum + s * 0.25, 0)

    const combinedConfidence = Math.min(1.0, maxScore + remainingSum)

    const injectionDriven = combinedConfidence >= this.config.confidenceThreshold
    const recommendation = this.determineRecommendation(combinedConfidence)

    return Object.freeze({
      injectionDriven,
      confidence: Math.round(combinedConfidence * 1000) / 1000,
      evidence: Object.freeze([...evidence]),
      recommendation,
    })
  }

  /**
   * Determine recommendation based on confidence and config.
   */
  private determineRecommendation(confidence: number): 'allow' | 'block' | 'review' {
    if (confidence >= this.config.confidenceThreshold) {
      return this.config.blockOnDetection ? 'block' : 'review'
    }
    if (confidence >= this.config.confidenceThreshold * 0.7) {
      return 'review'
    }
    return 'allow'
  }

  /**
   * Find a substantial overlapping substring between args and a tool result.
   * Uses a sliding window approach for efficiency.
   *
   * @returns The overlapping substring, or null if none found
   */
  private findSubstringOverlap(args: string, toolResult: string): string | null {
    // Use sliding windows of decreasing size from the args
    const maxWindowSize = Math.min(100, args.length)
    const minWindowSize = MIN_REFERENCE_LENGTH

    for (let windowSize = maxWindowSize; windowSize >= minWindowSize; windowSize -= 10) {
      for (let start = 0; start <= args.length - windowSize; start += 5) {
        const substring = args.slice(start, start + windowSize)
        // Skip trivially common substrings (mostly whitespace or punctuation)
        if (/^\s*$/.test(substring)) continue
        const alphaCount = (substring.match(/[a-zA-Z]/g) ?? []).length
        if (alphaCount < windowSize * 0.3) continue

        if (toolResult.includes(substring)) {
          return substring
        }
      }
    }

    return null
  }
}
