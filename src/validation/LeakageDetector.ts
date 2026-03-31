/**
 * System prompt leakage detection.
 * Identifies when an LLM output reveals information about
 * its system prompt, instructions, or internal configuration.
 */

import { createHash } from 'node:crypto'

/** Result of leakage detection */
interface LeakageResult {
  readonly leaked: boolean
  readonly confidence: number
  readonly indicators: readonly string[]
}

/**
 * Common patterns that indicate system prompt leakage.
 * Each pattern has an associated confidence weight.
 */
const LEAKAGE_PATTERNS: readonly { readonly pattern: RegExp; readonly weight: number; readonly label: string }[] = [
  { pattern: /my (?:system |initial )?instructions?\s+(?:say|tell|are|state|indicate)/i, weight: 0.9, label: 'explicit-instruction-reference' },
  { pattern: /i was (?:told|instructed|programmed|configured|set up) to/i, weight: 0.85, label: 'instruction-disclosure' },
  { pattern: /my (?:system )?prompt\s+(?:is|says|contains|includes)/i, weight: 0.95, label: 'prompt-disclosure' },
  { pattern: /(?:here(?:'s| is| are) my|these are the) (?:instructions|rules|guidelines|directives)/i, weight: 0.95, label: 'instruction-enumeration' },
  { pattern: /i(?:'m| am) (?:designed|built|created|made) to (?:never|always|only)/i, weight: 0.6, label: 'design-constraint-leak' },
  { pattern: /(?:the )?developer(?:s)? (?:told|instructed|configured|set) me/i, weight: 0.8, label: 'developer-reference' },
  { pattern: /(?:system|hidden|secret|internal) (?:message|prompt|instruction)/i, weight: 0.85, label: 'hidden-prompt-reference' },
  { pattern: /you(?:'re| are) not (?:supposed|allowed|meant) to (?:see|know|access) (?:this|that|these)/i, weight: 0.7, label: 'access-denial-leak' },
  { pattern: /(?:ignore|disregard|forget) (?:my |the )?(?:previous|above|prior) (?:instructions?|rules?)/i, weight: 0.75, label: 'instruction-override-attempt' },
  { pattern: /\[SYSTEM\]|\[INST\]|<<SYS>>|<\|system\|>/i, weight: 0.9, label: 'raw-template-markers' },
  { pattern: /(?:api[_-]?key|secret|token|password)\s*[:=]\s*\S+/i, weight: 0.95, label: 'credential-leak' },
  { pattern: /you (?:are|play|act as)\s+(?:a |an )?(?:helpful|friendly|expert|specialized)/i, weight: 0.4, label: 'role-description-leak' },
  { pattern: /(?:do not|don't|never) (?:reveal|share|disclose|tell|show) (?:your|the|my)/i, weight: 0.65, label: 'confidentiality-instruction-leak' },
  { pattern: /(?:behind the scenes|under the hood|internally),?\s+i/i, weight: 0.5, label: 'internal-reference' },
] as const

/**
 * LeakageDetector — identifies system prompt leakage in LLM output.
 *
 * Uses pattern matching against known leakage indicators and optional
 * system prompt hash comparison to detect when an LLM has revealed
 * information about its configuration.
 */
export class LeakageDetector {
  private readonly patterns: typeof LEAKAGE_PATTERNS

  constructor() {
    this.patterns = LEAKAGE_PATTERNS
  }

  /**
   * Detect potential system prompt leakage in an output string.
   * @param output - LLM output text to inspect
   * @param systemPromptHash - Optional SHA-256 hash of the system prompt to check for literal inclusion
   * @returns Detection result with confidence and matched indicators
   */
  detect(output: string, systemPromptHash?: string): LeakageResult {
    const indicators: string[] = []
    let maxConfidence = 0

    for (const entry of this.patterns) {
      if (entry.pattern.test(output)) {
        indicators.push(entry.label)
        maxConfidence = Math.max(maxConfidence, entry.weight)
      }
    }

    // If a system prompt hash is provided, check if the output
    // contains content that hashes to the same value (unlikely but possible)
    if (systemPromptHash !== undefined) {
      const hashMatch = checkHashPresence(output, systemPromptHash)
      if (hashMatch) {
        indicators.push('system-prompt-hash-match')
        maxConfidence = Math.max(maxConfidence, 0.99)
      }
    }

    // Multiple indicators compound confidence
    const compoundedConfidence = indicators.length > 1
      ? Math.min(maxConfidence + (indicators.length - 1) * 0.05, 1.0)
      : maxConfidence

    return Object.freeze({
      leaked: indicators.length > 0,
      confidence: Math.round(compoundedConfidence * 1000) / 1000,
      indicators: Object.freeze([...indicators]),
    })
  }
}

/**
 * Check if sliding windows of the output match the system prompt hash.
 * Tests window sizes from 50 to 500 chars in steps of 50.
 */
function checkHashPresence(output: string, targetHash: string): boolean {
  const windowSizes = [50, 100, 150, 200, 300, 500] as const
  for (const size of windowSizes) {
    if (output.length < size) continue
    for (let i = 0; i <= output.length - size; i += 25) {
      const window = output.slice(i, i + size)
      const windowHash = createHash('sha256').update(window).digest('hex')
      if (windowHash === targetHash) {
        return true
      }
    }
  }
  return false
}
