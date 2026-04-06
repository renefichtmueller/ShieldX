/**
 * UpsideDownTextDetector — Layer 0 flipped/rotated text detection.
 *
 * Detects and normalizes Unicode characters that visually resemble
 * upside-down or rotated Latin letters. Attackers use these to spell
 * words that LLMs read correctly but text-based guardrails miss entirely.
 *
 * This achieves near-100% ASR against unprotected systems because:
 * - The Unicode chars are valid, non-control characters
 * - LLMs internally normalize them during tokenization
 * - Pattern-matching rules only check standard Latin
 *
 * Synchronous execution, targeting <0.3ms latency.
 */

import type { ScanResult, ScannerType, ShieldXConfig } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SCANNER_ID = 'upside-down-text-detector'
const SCANNER_TYPE: ScannerType = 'unicode'

/**
 * Reverse mapping: upside-down Unicode characters to their normal Latin
 * equivalents. Covers the standard upside-down alphabet used in attacks.
 *
 * Source characters are IPA, Latin Extended, and other Unicode blocks
 * that visually resemble inverted Latin letters.
 */
const UPSIDE_DOWN_TO_LATIN: Readonly<Record<string, string>> = Object.freeze({
  // Lowercase upside-down → normal lowercase
  '\u0250': 'a',  // ɐ → a (turned a)
  '\u0254': 'c',  // ɔ → c (open o / turned c)
  '\u01DD': 'e',  // ǝ → e (turned e)
  '\u025F': 'f',  // ɟ → f (dotless j with stroke / turned f)
  '\u0183': 'g',  // ƃ → g (b with topbar / turned g)
  '\u0265': 'h',  // ɥ → h (turned h)
  '\u1D09': 'i',  // ᴉ → i (turned i)
  '\u027E': 'j',  // ɾ → j (r with fishhook / turned j)
  '\u029E': 'k',  // ʞ → k (turned k)
  '\u026F': 'm',  // ɯ → m (turned m)
  '\u0279': 'r',  // ɹ → r (turned r)
  '\u0287': 't',  // ʇ → t (turned t)
  '\u028C': 'v',  // ʌ → v (turned v)
  '\u028D': 'w',  // ʍ → w (turned w)
  '\u028E': 'y',  // ʎ → y (turned y)

  // Additional turned/rotated forms commonly used
  '\u0252': 'a',  // ɒ → a (turned alpha, also used for inverted a)
  '\u018D': 'g',  // ƍ → g (turned delta, sometimes used)
  '\u2C63': 'p',  // Ᵽ → P (P with stroke, sometimes confused)

  // Letters that map to themselves when "flipped" (b↔q, d↔p, n↔u)
  // These are regular Latin chars but used in flipped-text context:
  // b→q mapping: if 'q' appears where 'b' should be (contextual)
  // d→p mapping: if 'p' appears where 'd' should be (contextual)
  // n→u mapping: already normal Latin

  // Uppercase upside-down forms
  '\u2200': 'A',  // ∀ → A (for all / turned A)
  '\u2229': 'U',  // ∩ → U (intersection / turned U)
  '\u2C6F': 'A',  // Ɐ → A (turned A, Latin)
  '\u2132': 'F',  // Ⅎ → F (turned F)
  '\u2141': 'G',  // ⅁ → G (turned G)
  '\u0248': 'J',  // Ɉ → J (J with stroke / turned J)
  '\u2142': 'L',  // ⅂ → L (turned L)
  '\u0500': 'P',  // Ԁ → P (Cyrillic komi de / turned P visual)
  '\u1D1A': 'R',  // ᴚ → R (turned R, small caps)
  '\u22A5': 'T',  // ⊥ → T (perpendicular / turned T)
  '\u2144': 'Y',  // ⅄ → Y (turned Y)
})

/** Set of all upside-down characters for fast lookup */
const UPSIDE_DOWN_CHARS: ReadonlySet<string> = Object.freeze(
  new Set(Object.keys(UPSIDE_DOWN_TO_LATIN)),
)

/** Pre-built regex matching any upside-down character for single-pass replacement */
const UPSIDE_DOWN_CHARS_ARRAY = Object.keys(UPSIDE_DOWN_TO_LATIN)
const UPSIDE_DOWN_REGEX = UPSIDE_DOWN_CHARS_ARRAY.length > 0
  ? new RegExp(`[${UPSIDE_DOWN_CHARS_ARRAY.join('')}]`, 'gu')
  : null

/**
 * Threshold: fraction of alphabetic characters that are upside-down
 * before we flag the input as suspicious.
 */
const UPSIDE_DOWN_DENSITY_THRESHOLD = 0.2

/** Minimum alphabetic character count for density check to apply */
const MIN_ALPHA_CHARS_FOR_DENSITY = 5

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/** Result of upside-down text analysis */
export interface UpsideDownTextResult {
  readonly detected: boolean
  readonly normalized: string
  readonly upsideDownCharCount: number
  readonly totalAlphaChars: number
  readonly upsideDownDensity: number
  readonly suspiciousPatterns: readonly string[]
}

// ---------------------------------------------------------------------------
// UpsideDownTextDetector class
// ---------------------------------------------------------------------------

export class UpsideDownTextDetector {
  constructor(private readonly config: ShieldXConfig) {}

  /**
   * Analyze input for upside-down/flipped text and normalize it.
   *
   * @param input - Raw user input string
   * @returns Analysis result with normalized text and detection metadata
   */
  analyze(input: string): UpsideDownTextResult {
    const suspiciousPatterns: string[] = []

    // Count upside-down characters
    let upsideDownCharCount = 0
    const codePoints = [...input]

    for (const cp of codePoints) {
      if (UPSIDE_DOWN_CHARS.has(cp)) {
        upsideDownCharCount++
      }
    }

    // Count total alphabetic characters (Latin + upside-down)
    const latinAlphaCount = codePoints.filter(
      (cp) => /[a-zA-Z]/.test(cp),
    ).length
    const totalAlphaChars = latinAlphaCount + upsideDownCharCount

    // Compute density
    const upsideDownDensity =
      totalAlphaChars >= MIN_ALPHA_CHARS_FOR_DENSITY
        ? upsideDownCharCount / totalAlphaChars
        : 0

    // Normalize: replace upside-down chars with Latin equivalents
    const normalized = UPSIDE_DOWN_REGEX
      ? input.replace(UPSIDE_DOWN_REGEX, (ch) => UPSIDE_DOWN_TO_LATIN[ch] ?? ch)
      : input

    // Flag if density exceeds threshold
    if (
      upsideDownDensity > UPSIDE_DOWN_DENSITY_THRESHOLD &&
      totalAlphaChars >= MIN_ALPHA_CHARS_FOR_DENSITY
    ) {
      suspiciousPatterns.push('upside_down_text')
    }

    // Also flag if absolute count is high (even in long text)
    if (upsideDownCharCount >= 10) {
      suspiciousPatterns.push('high_upside_down_char_count')
    }

    const detected = suspiciousPatterns.length > 0

    return {
      detected,
      normalized,
      upsideDownCharCount,
      totalAlphaChars,
      upsideDownDensity,
      suspiciousPatterns,
    }
  }

  /**
   * Produce a ScanResult for the ShieldX pipeline.
   *
   * @param input - Raw user input string
   * @returns ScanResult with upside-down text detection details
   */
  scan(input: string): ScanResult {
    const start = performance.now()
    const result = this.analyze(input)
    const latencyMs = performance.now() - start

    const rawScore = Math.min(
      1.0,
      (result.upsideDownDensity * 2) + (result.upsideDownCharCount / 30),
    )

    const confidence = result.detected ? Math.max(0.5, rawScore) : rawScore
    const threatLevel = this.computeThreatLevel(confidence)

    return {
      scannerId: SCANNER_ID,
      scannerType: SCANNER_TYPE,
      detected: result.detected,
      confidence,
      threatLevel,
      killChainPhase: result.detected ? 'initial_access' : 'none',
      matchedPatterns: result.suspiciousPatterns,
      rawScore,
      latencyMs,
      metadata: {
        upsideDownCharCount: result.upsideDownCharCount,
        totalAlphaChars: result.totalAlphaChars,
        upsideDownDensity: result.upsideDownDensity,
        normalizedPreview: result.normalized.slice(0, 200),
      },
    }
  }

  /**
   * Normalize upside-down text back to standard Latin.
   * Convenience method that returns only the normalized string.
   *
   * @param input - Raw user input string
   * @returns String with upside-down characters replaced by Latin equivalents
   */
  normalize(input: string): string {
    return this.analyze(input).normalized
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
