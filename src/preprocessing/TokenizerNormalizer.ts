/**
 * TokenizerNormalizer — Layer 0 retokenization attack defense.
 *
 * Normalizes inputs to prevent retokenization attacks (TU Munich MetaBreak 2025)
 * where invisible Unicode causes LLM tokenizers to split tokens differently,
 * bypassing pattern-matching defenses.
 *
 * Covers: Unicode normalization forms, exotic whitespace, invisible separators,
 * curly quotes, dashes, and other typographic variants that alter tokenization.
 */

import type { ScanResult, ScannerType, ShieldXConfig } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SCANNER_ID = 'tokenizer-normalizer'
const SCANNER_TYPE: ScannerType = 'tokenizer'

/**
 * Exotic whitespace characters collapsed to regular space (U+0020).
 * Includes: em space, en space, thin space, hair space, figure space,
 * punctuation space, six-per-em space, four-per-em space, three-per-em space,
 * ideographic space, narrow no-break space, medium mathematical space,
 * no-break space, ogham space mark.
 */
const EXOTIC_WHITESPACE_REGEX = /[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/g

/**
 * Zero-width characters between tokens that cause retokenization.
 * ZWSP, ZWNJ, ZWJ, word joiner, ZWNBSP/BOM.
 */
const ZERO_WIDTH_TOKEN_REGEX = /[\u200B\u200C\u200D\u2060\uFEFF]/g

/**
 * Invisible line/paragraph separators.
 * U+2028 line separator, U+2029 paragraph separator.
 */
const INVISIBLE_SEPARATOR_REGEX = /[\u2028\u2029]/g

/**
 * Curly/smart quotes normalized to straight ASCII quotes.
 * Left/right single quotes, left/right double quotes.
 */
const CURLY_SINGLE_QUOTE_REGEX = /[\u2018\u2019\u201A\u201B]/g
const CURLY_DOUBLE_QUOTE_REGEX = /[\u201C\u201D\u201E\u201F]/g

/**
 * Dashes normalized to ASCII hyphen-minus (U+002D).
 * Em dash (2014), en dash (2013), figure dash (2012),
 * horizontal bar (2015), swung dash (2053), minus sign (2212).
 */
const DASH_REGEX = /[\u2012-\u2015\u2053\u2212]/g

/**
 * Multiple consecutive whitespace collapsed to single space.
 */
const MULTI_SPACE_REGEX = / {2,}/g

// ---------------------------------------------------------------------------
// TokenizerNormalizer class
// ---------------------------------------------------------------------------

export class TokenizerNormalizer {
  /**
   * Create a TokenizerNormalizer.
   * @param config - ShieldX configuration
   */
  constructor(private readonly config: ShieldXConfig) {}

  /**
   * Normalize input to canonical form that prevents retokenization attacks.
   * Synchronous for <0.5ms latency.
   *
   * @param input - Raw or pre-processed input string
   * @returns Normalized string in NFKC form with standardized whitespace/punctuation
   */
  normalize(input: string): string {
    // 1. NFKC normalization — canonical decomposition + compatibility composition.
    //    This collapses ligatures, fullwidth chars, superscripts, etc.
    let result = input.normalize('NFKC')

    // 2. Strip zero-width characters that cause token boundary changes
    result = result.replace(ZERO_WIDTH_TOKEN_REGEX, '')

    // 3. Replace invisible separators with newlines (preserve semantic breaks)
    result = result.replace(INVISIBLE_SEPARATOR_REGEX, '\n')

    // 4. Collapse exotic whitespace to regular space
    result = result.replace(EXOTIC_WHITESPACE_REGEX, ' ')

    // 5. Normalize curly quotes to straight
    result = result.replace(CURLY_SINGLE_QUOTE_REGEX, "'")
    result = result.replace(CURLY_DOUBLE_QUOTE_REGEX, '"')

    // 6. Normalize dashes to hyphen-minus
    result = result.replace(DASH_REGEX, '-')

    // 7. Collapse multiple spaces to single
    result = result.replace(MULTI_SPACE_REGEX, ' ')

    return result
  }

  /**
   * Scan input for retokenization attack indicators and return a ScanResult.
   * Synchronous for <0.5ms latency.
   *
   * @param input - Raw input string
   * @returns ScanResult with detection details
   */
  scan(input: string): ScanResult {
    const start = performance.now()

    const matchedPatterns: string[] = []
    let modifications = 0

    // Detect each category of problematic content
    const zeroWidthMatches = input.match(ZERO_WIDTH_TOKEN_REGEX)
    if (zeroWidthMatches) {
      modifications += zeroWidthMatches.length
      matchedPatterns.push('zero_width_token_splitters')
    }

    const exoticWhitespaceMatches = input.match(EXOTIC_WHITESPACE_REGEX)
    if (exoticWhitespaceMatches) {
      modifications += exoticWhitespaceMatches.length
      matchedPatterns.push('exotic_whitespace')
    }

    const separatorMatches = input.match(INVISIBLE_SEPARATOR_REGEX)
    if (separatorMatches) {
      modifications += separatorMatches.length
      matchedPatterns.push('invisible_separators')
    }

    const curlyQuoteMatches = [
      ...(input.match(CURLY_SINGLE_QUOTE_REGEX) ?? []),
      ...(input.match(CURLY_DOUBLE_QUOTE_REGEX) ?? []),
    ]
    if (curlyQuoteMatches.length > 0) {
      modifications += curlyQuoteMatches.length
      matchedPatterns.push('curly_quotes')
    }

    const dashMatches = input.match(DASH_REGEX)
    if (dashMatches) {
      modifications += dashMatches.length
      matchedPatterns.push('exotic_dashes')
    }

    // Check if NFKC normalization changes the string (indicates non-canonical form)
    const nfkcNormalized = input.normalize('NFKC')
    if (nfkcNormalized !== input) {
      const nfkcDiff = Math.abs(nfkcNormalized.length - input.length)
      modifications += nfkcDiff
      matchedPatterns.push('non_nfkc_form')
    }

    const latencyMs = performance.now() - start

    // Zero-width chars in a token context are more suspicious than curly quotes
    const zeroWidthCount = zeroWidthMatches?.length ?? 0
    const isSuspicious = zeroWidthCount > 3 || modifications > 10

    const rawScore = Math.min(
      1.0,
      (zeroWidthCount / 10) + (modifications / 50),
    )
    const confidence = isSuspicious ? Math.max(0.3, rawScore) : rawScore
    const threatLevel = this.computeThreatLevel(confidence)

    return {
      scannerId: SCANNER_ID,
      scannerType: SCANNER_TYPE,
      detected: isSuspicious,
      confidence,
      threatLevel,
      killChainPhase: isSuspicious ? 'initial_access' : 'none',
      matchedPatterns,
      rawScore,
      latencyMs,
      metadata: {
        totalModifications: modifications,
        zeroWidthCount,
      },
    }
  }

  /**
   * Map confidence score to threat level using config thresholds.
   */
  private computeThreatLevel(confidence: number): ScanResult['threatLevel'] {
    if (confidence >= this.config.thresholds.critical) return 'critical'
    if (confidence >= this.config.thresholds.high) return 'high'
    if (confidence >= this.config.thresholds.medium) return 'medium'
    if (confidence >= this.config.thresholds.low) return 'low'
    return 'none'
  }
}
