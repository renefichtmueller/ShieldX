/**
 * UnicodeNormalizer — Layer 0 critical preprocessing.
 *
 * Strips invisible characters, homoglyphs, and steganographic Unicode
 * that evade all commercial guardrails. This is the single most impactful
 * zero-cost defense: invisible payloads are neutralized before any
 * downstream scanner ever sees the input.
 *
 * Covers: Unicode Tags, Zero-Width, BiDi overrides, Variation Selectors,
 * Cyrillic/Greek/Armenian homoglyphs, invisible formatting, control chars.
 */

import type { ScanResult, ScannerType, ShieldXConfig } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Scanner identifier for ScanResult */
const SCANNER_ID = 'unicode-normalizer'
const SCANNER_TYPE: ScannerType = 'unicode'

/**
 * Homoglyph map: visually identical non-Latin characters mapped to ASCII.
 * Covers Cyrillic, Greek, Armenian, and other confusable scripts.
 * At least 50 entries as required.
 */
const HOMOGLYPH_MAP: Readonly<Record<string, string>> = Object.freeze({
  // Cyrillic → Latin
  '\u0430': 'a',  // а → a
  '\u0435': 'e',  // е → e
  '\u043E': 'o',  // о → o
  '\u0440': 'p',  // р → p
  '\u0441': 'c',  // с → c
  '\u0443': 'y',  // у → y
  '\u0445': 'x',  // х → x
  '\u0456': 'i',  // і → i (Ukrainian)
  '\u0458': 'j',  // ј → j (Serbian)
  '\u04BB': 'h',  // һ → h
  '\u0455': 's',  // ѕ → s
  '\u0454': 'e',  // є → e (Ukrainian)
  '\u0457': 'i',  // ї → i (Ukrainian)
  '\u043A': 'k',  // к → k
  '\u043C': 'm',  // м → m (visually similar in some fonts)
  '\u0422': 'T',  // Т → T
  '\u0410': 'A',  // А → A
  '\u0412': 'B',  // В → B
  '\u0415': 'E',  // Е → E
  '\u041A': 'K',  // К → K
  '\u041C': 'M',  // М → M
  '\u041D': 'H',  // Н → H
  '\u041E': 'O',  // О → O
  '\u0420': 'P',  // Р → P
  '\u0421': 'C',  // С → C
  '\u0423': 'Y',  // У → Y (uppercase)
  '\u0425': 'X',  // Х → X
  '\u0417': '3',  // З → 3
  '\u0432': 'b',  // в → b (in some fonts)

  // Greek → Latin
  '\u03B1': 'a',  // α → a
  '\u03B5': 'e',  // ε → e (visually close)
  '\u03BF': 'o',  // ο → o
  '\u03C1': 'p',  // ρ → p
  '\u03C4': 't',  // τ → t (visually close in some fonts)
  '\u03BD': 'v',  // ν → v
  '\u0391': 'A',  // Α → A
  '\u0392': 'B',  // Β → B
  '\u0395': 'E',  // Ε → E
  '\u0396': 'Z',  // Ζ → Z
  '\u0397': 'H',  // Η → H
  '\u0399': 'I',  // Ι → I
  '\u039A': 'K',  // Κ → K
  '\u039C': 'M',  // Μ → M
  '\u039D': 'N',  // Ν → N
  '\u039F': 'O',  // Ο → O
  '\u03A1': 'P',  // Ρ → P
  '\u03A4': 'T',  // Τ → T
  '\u03A5': 'Y',  // Υ → Y
  '\u03A7': 'X',  // Χ → X
  '\u03B9': 'i',  // ι → i

  // Armenian → Latin
  '\u0570': 'h',  // հ → h
  '\u0578': 'n',  // ո → n
  '\u057D': 's',  // ս → s
  '\u0585': 'o',  // օ → o
  '\u0575': 'j',  // յ → j

  // Fullwidth Latin
  '\uFF41': 'a',  // ａ → a
  '\uFF42': 'b',  // ｂ → b
  '\uFF43': 'c',  // ｃ → c
  '\uFF44': 'd',  // ｄ → d
  '\uFF45': 'e',  // ｅ → e
})

/**
 * Regex for Unicode Tag Characters (U+E0000 - U+E007F).
 * These are invisible "language tag" characters abused for steganographic payloads.
 */
const UNICODE_TAGS_REGEX = /[\u{E0000}-\u{E007F}]/gu

/**
 * Zero-width characters used for invisible payloads.
 * ZWSP, ZWNJ, ZWJ, BOM/ZWNBSP
 */
const ZERO_WIDTH_REGEX = /[\u200B\u200C\u200D\uFEFF]/g

/**
 * Bidirectional override and embedding characters.
 * LRE (202A), RLE (202B), PDF (202C), LRO (202D), RLO (202E),
 * LRI (2066), RLI (2067), FSI (2068), PDI (2069)
 */
const BIDI_REGEX = /[\u202A-\u202E\u2066-\u2069]/g

/**
 * Variation Selectors: VS1-VS16 (FE00-FE0F) and VS17-VS256 (E0100-E01EF).
 */
const VARIATION_SELECTORS_REGEX = /[\uFE00-\uFE0F]|[\u{E0100}-\u{E01EF}]/gu

/**
 * Invisible formatting characters:
 * - U+00AD soft hyphen
 * - U+034F combining grapheme joiner
 * - U+061C Arabic letter mark
 * - U+115F, U+1160 Hangul filler characters
 * - U+17B4, U+17B5 Khmer invisible vowels
 * - U+180E Mongolian vowel separator
 * - U+2060 word joiner
 * - U+2061-U+2064 invisible math operators
 */
const INVISIBLE_FORMATTING_REGEX = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u2060-\u2064]/g

/**
 * Control characters: C0 (0000-001F except tab/newline/cr), DEL (007F), C1 (0080-009F).
 */
const CONTROL_CHARS_REGEX = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u0080-\u009F]/g

// Pre-build homoglyph regex for single-pass replacement
const HOMOGLYPH_CHARS = Object.keys(HOMOGLYPH_MAP)
const HOMOGLYPH_REGEX = HOMOGLYPH_CHARS.length > 0
  ? new RegExp(`[${HOMOGLYPH_CHARS.join('')}]`, 'g')
  : null

// ---------------------------------------------------------------------------
// Result type for normalize()
// ---------------------------------------------------------------------------

/** Result of Unicode normalization with metadata for logging */
export interface UnicodeNormalizationResult {
  readonly normalized: string
  readonly strippedChars: number
  readonly homoglyphsReplaced: number
  readonly suspiciousPatterns: readonly string[]
}

// ---------------------------------------------------------------------------
// UnicodeNormalizer class
// ---------------------------------------------------------------------------

export class UnicodeNormalizer {
  private readonly strippedCharsThreshold: number
  private readonly homoglyphThreshold: number

  /**
   * Create a UnicodeNormalizer.
   * @param config - ShieldX configuration. Thresholds drive suspicion flagging.
   */
  constructor(private readonly config: ShieldXConfig) {
    // Default thresholds — flag if more than 5 stripped chars or 3 homoglyphs
    this.strippedCharsThreshold = 5
    this.homoglyphThreshold = 3
  }

  /**
   * Normalize input by stripping all invisible/steganographic Unicode.
   * Synchronous for <0.1ms latency.
   *
   * @param input - Raw user input string
   * @returns Normalization result with metadata
   */
  normalize(input: string): UnicodeNormalizationResult {
    let strippedChars = 0
    const suspiciousPatterns: string[] = []

    // Count and strip each category
    const afterTags = input.replace(UNICODE_TAGS_REGEX, () => {
      strippedChars++
      return ''
    })

    const afterZeroWidth = afterTags.replace(ZERO_WIDTH_REGEX, () => {
      strippedChars++
      return ''
    })

    const afterBidi = afterZeroWidth.replace(BIDI_REGEX, () => {
      strippedChars++
      return ''
    })

    const afterVarSel = afterBidi.replace(VARIATION_SELECTORS_REGEX, () => {
      strippedChars++
      return ''
    })

    const afterInvisible = afterVarSel.replace(INVISIBLE_FORMATTING_REGEX, () => {
      strippedChars++
      return ''
    })

    const afterControl = afterInvisible.replace(CONTROL_CHARS_REGEX, () => {
      strippedChars++
      return ''
    })

    // Homoglyph replacement
    let homoglyphsReplaced = 0
    const afterHomoglyphs = HOMOGLYPH_REGEX
      ? afterControl.replace(HOMOGLYPH_REGEX, (ch) => {
        homoglyphsReplaced++
        return HOMOGLYPH_MAP[ch] ?? ch
      })
      : afterControl

    // Build suspicious pattern list for logging
    if (input.match(UNICODE_TAGS_REGEX)) {
      suspiciousPatterns.push('unicode_tag_characters')
    }
    if (input.match(ZERO_WIDTH_REGEX)) {
      suspiciousPatterns.push('zero_width_characters')
    }
    if (input.match(BIDI_REGEX)) {
      suspiciousPatterns.push('bidi_override_characters')
    }
    if (input.match(VARIATION_SELECTORS_REGEX)) {
      suspiciousPatterns.push('variation_selectors')
    }
    if (input.match(INVISIBLE_FORMATTING_REGEX)) {
      suspiciousPatterns.push('invisible_formatting')
    }
    if (input.match(CONTROL_CHARS_REGEX)) {
      suspiciousPatterns.push('control_characters')
    }
    if (homoglyphsReplaced > 0) {
      suspiciousPatterns.push('homoglyph_substitution')
    }

    return {
      normalized: afterHomoglyphs,
      strippedChars,
      homoglyphsReplaced,
      suspiciousPatterns,
    }
  }

  /**
   * Scan input for suspicious Unicode patterns and return a ScanResult.
   * Synchronous for <0.1ms latency.
   *
   * @param input - Raw user input string
   * @returns ScanResult with detection details
   */
  scan(input: string): ScanResult {
    const start = performance.now()
    const result = this.normalize(input)
    const latencyMs = performance.now() - start

    const isSuspicious =
      result.strippedChars > this.strippedCharsThreshold ||
      result.homoglyphsReplaced > this.homoglyphThreshold

    // Confidence: scale based on number of suspicious indicators
    const rawScore = Math.min(
      1.0,
      (result.strippedChars / 20) + (result.homoglyphsReplaced / 10),
    )

    const confidence = isSuspicious ? Math.max(0.4, rawScore) : rawScore

    const threatLevel = this.computeThreatLevel(confidence)

    return {
      scannerId: SCANNER_ID,
      scannerType: SCANNER_TYPE,
      detected: isSuspicious,
      confidence,
      threatLevel,
      killChainPhase: isSuspicious ? 'initial_access' : 'none',
      matchedPatterns: result.suspiciousPatterns,
      rawScore,
      latencyMs,
      metadata: {
        strippedChars: result.strippedChars,
        homoglyphsReplaced: result.homoglyphsReplaced,
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
