/**
 * InputSanitizer — Pre-LLM input cleaning.
 *
 * Strips detected injection patterns while preserving legitimate content.
 * Runs after detection scanners have identified matched patterns, removing
 * injection fragments and re-validating the stripped result.
 */

import type { ShieldXConfig } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Result of input sanitization */
export interface InputSanitizationResult {
  readonly sanitized: string
  readonly originalLength: number
  readonly sanitizedLength: number
  readonly patternsStripped: number
  readonly revalidated: boolean
  readonly preservedRatio: number
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Minimum viable input length after stripping */
const MIN_INPUT_LENGTH = 2

/** Maximum iterations to prevent infinite re-strip loops */
const MAX_STRIP_ITERATIONS = 5

/**
 * Residual injection fragments that may remain after pattern stripping.
 * These are checked during re-validation.
 */
const RESIDUAL_PATTERNS: readonly RegExp[] = Object.freeze([
  /\bignore\s+(all\s+)?previous\b/i,
  /\bsystem\s*:\s*/i,
  /\bdo\s+not\s+follow\b/i,
  /\byou\s+are\s+now\b/i,
  /\bnew\s+instructions?\s*:/i,
  /\boverride\b.*\binstructions?\b/i,
  /\bforget\b.*\brules?\b/i,
  /\bact\s+as\b/i,
  /\bpretend\s+you\b/i,
  /\bjailbreak\b/i,
  /```\s*(system|admin|root)\b/i,
  /<\/?(?:system|admin|instruction)[^>]*>/i,
])

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Pre-LLM input sanitizer.
 *
 * Strips matched injection patterns from user input, then re-validates
 * the cleaned result to catch residual fragments. Preserves user intent
 * by only removing confirmed injection patterns.
 */
export class InputSanitizer {
  private readonly _config: ShieldXConfig

  /** Access the active configuration */
  get config(): ShieldXConfig { return this._config }

  constructor(config: ShieldXConfig) {
    this._config = config
  }

  /**
   * Sanitize input by stripping matched patterns and re-validating.
   *
   * @param input - Raw user input
   * @param matchedPatterns - Patterns identified by RuleEngine or other scanners
   * @returns Sanitized input with metadata
   */
  async sanitize(
    input: string,
    matchedPatterns?: readonly string[],
  ): Promise<InputSanitizationResult> {
    if (!input || input.trim().length === 0) {
      return this.buildResult(input, '', 0, true)
    }

    const patterns = matchedPatterns ?? []

    // Phase 1: Strip matched patterns
    const stripped = this.stripPatterns(input, patterns)

    // Phase 2: Re-validate and strip residuals
    const { cleaned, additionalStrips } = this.revalidate(stripped)

    // Phase 3: Normalize whitespace
    const normalized = this.normalizeWhitespace(cleaned)

    // Phase 4: Ensure minimum viability
    const final = normalized.length >= MIN_INPUT_LENGTH ? normalized : ''

    return this.buildResult(
      input,
      final,
      patterns.length + additionalStrips,
      additionalStrips === 0,
    )
  }

  /**
   * Strip all matched patterns from input.
   * Uses case-insensitive matching with escaped regex special characters.
   */
  private stripPatterns(
    input: string,
    patterns: readonly string[],
  ): string {
    let result = input

    for (const pattern of patterns) {
      if (!pattern || pattern.length === 0) continue

      const escaped = this.escapeRegex(pattern)
      try {
        const regex = new RegExp(escaped, 'gi')
        result = result.replace(regex, ' ')
      } catch {
        // If regex construction fails, do literal replacement
        result = result.split(pattern).join(' ')
      }
    }

    return result
  }

  /**
   * Re-validate stripped input for residual injection fragments.
   * Iterates up to MAX_STRIP_ITERATIONS to catch nested patterns.
   */
  private revalidate(
    input: string,
  ): { readonly cleaned: string; readonly additionalStrips: number } {
    let current = input
    let totalStrips = 0

    for (let i = 0; i < MAX_STRIP_ITERATIONS; i++) {
      let stripped = false

      for (const pattern of RESIDUAL_PATTERNS) {
        if (pattern.test(current)) {
          current = current.replace(pattern, ' ')
          totalStrips++
          stripped = true
        }
      }

      if (!stripped) break
    }

    return { cleaned: current, additionalStrips: totalStrips }
  }

  /** Collapse multiple whitespace into single spaces, trim edges */
  private normalizeWhitespace(input: string): string {
    return input
      .replace(/\s+/g, ' ')
      .trim()
  }

  /** Escape special regex characters in a pattern string */
  private escapeRegex(pattern: string): string {
    return pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  }

  /** Build an immutable sanitization result */
  private buildResult(
    original: string,
    sanitized: string,
    patternsStripped: number,
    revalidated: boolean,
  ): InputSanitizationResult {
    const originalLength = original.length
    const sanitizedLength = sanitized.length
    const preservedRatio = originalLength > 0
      ? sanitizedLength / originalLength
      : 0

    return Object.freeze({
      sanitized,
      originalLength,
      sanitizedLength,
      patternsStripped,
      revalidated,
      preservedRatio: Math.round(preservedRatio * 1000) / 1000,
    })
  }
}
