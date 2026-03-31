/**
 * Prompt Reconstructor — Rebuilds clean prompts from injection-detected inputs.
 *
 * Strips all matched injection patterns, re-validates the stripped version,
 * and returns a clean prompt or null if nothing salvageable remains.
 */

import type { ScanResult } from '../types/detection.js'

/** Result of a prompt reconstruction attempt */
export interface ReconstructionResult {
  readonly cleanPrompt: string | null
  readonly patternsStripped: number
  readonly originalLength: number
  readonly cleanLength: number
  readonly salvageable: boolean
}

/** Minimum viable prompt length after stripping */
const MIN_PROMPT_LENGTH = 3

/**
 * Reconstructs clean prompts from injection-tainted inputs.
 *
 * Strips all patterns matched by scan results, normalizes whitespace,
 * and validates the result meets minimum viability requirements.
 */
export class PromptReconstructor {
  /**
   * Attempt to rebuild a clean prompt from a detected-injected input.
   *
   * @param input - The original tainted input
   * @param scanResults - Scan results with matched patterns to strip
   * @returns Reconstruction result with clean prompt or null
   */
  reconstruct(
    input: string,
    scanResults: readonly ScanResult[]
  ): ReconstructionResult {
    const patterns = this.collectPatterns(scanResults)
    const stripped = this.stripPatterns(input, patterns)
    const normalized = this.normalizeWhitespace(stripped)
    const isValid = this.validate(normalized)

    return {
      cleanPrompt: isValid ? normalized : null,
      patternsStripped: patterns.length,
      originalLength: input.length,
      cleanLength: normalized.length,
      salvageable: isValid,
    }
  }

  /**
   * Strip patterns and re-validate in a single pass, returning
   * the clean string or null.
   *
   * @param input - The original tainted input
   * @param scanResults - Scan results with matched patterns
   * @returns Clean prompt string or null
   */
  reconstructOrNull(
    input: string,
    scanResults: readonly ScanResult[]
  ): string | null {
    const result = this.reconstruct(input, scanResults)
    return result.cleanPrompt
  }

  /**
   * Collect all unique matched patterns from scan results.
   */
  private collectPatterns(scanResults: readonly ScanResult[]): readonly string[] {
    const patterns = scanResults
      .filter((r) => r.detected)
      .flatMap((r) => r.matchedPatterns)

    return [...new Set(patterns)].sort((a, b) => b.length - a.length)
  }

  /**
   * Strip all matched patterns from the input.
   * Patterns are sorted longest-first to prevent partial matches.
   */
  private stripPatterns(input: string, patterns: readonly string[]): string {
    let result = input

    for (const pattern of patterns) {
      const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      result = result.replace(new RegExp(escaped, 'gi'), '')
    }

    return result
  }

  /** Normalize whitespace: collapse runs, trim edges */
  private normalizeWhitespace(input: string): string {
    return input
      .replace(/\n{3,}/g, '\n\n')
      .replace(/[ \t]{2,}/g, ' ')
      .trim()
  }

  /**
   * Validate that the stripped prompt is still usable.
   * Must have minimum length and contain at least one word character.
   */
  private validate(input: string): boolean {
    if (input.length < MIN_PROMPT_LENGTH) return false
    if (!/\w/.test(input)) return false
    return true
  }
}
