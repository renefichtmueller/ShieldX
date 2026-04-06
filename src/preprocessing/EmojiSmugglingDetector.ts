/**
 * EmojiSmugglingDetector — Layer 0 emoji-based smuggling detection.
 *
 * Detects attackers encoding instructions as emoji sequences to bypass
 * guardrails. Techniques include:
 * - Regional indicator symbols (U+1F1E6-U+1F1FF) spelling words as flag pairs
 * - Emoji skin tone modifiers used as data carriers
 * - Excessive emoji density as obfuscation cover
 * - Keycap sequences (digit + VS16 + U+20E3) encoding numeric payloads
 *
 * These techniques achieve near-100% ASR against unprotected LLM guardrails.
 * Synchronous execution, targeting <0.5ms latency.
 */

import type { ScanResult, ScannerType, ShieldXConfig } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SCANNER_ID = 'emoji-smuggling-detector'
const SCANNER_TYPE: ScannerType = 'unicode'

/** Regional indicator symbols U+1F1E6 (A) through U+1F1FF (Z) */
const REGIONAL_INDICATOR_REGEX = /[\u{1F1E6}-\u{1F1FF}]/gu

/**
 * Mapping from regional indicator symbols to Latin letters.
 * U+1F1E6 = A, U+1F1E7 = B, ..., U+1F1FF = Z
 */
const REGIONAL_INDICATOR_BASE = 0x1F1E6

/** Emoji skin tone modifiers (Fitzpatrick scale) */
const SKIN_TONE_MODIFIERS_REGEX = /[\u{1F3FB}-\u{1F3FF}]/gu

/** Keycap sequences: digit/# /* + VS16 (FE0F) + combining enclosing keycap (20E3) */
const KEYCAP_SEQUENCE_REGEX = /[\d#*]\uFE0F?\u20E3/g

/**
 * Broad emoji detection regex covering common emoji ranges.
 * Includes: emoticons, symbols, transport, misc, dingbats, supplemental,
 * flags, skin tones, ZWJ sequences, variation selectors within emoji context.
 */
const EMOJI_BROAD_REGEX = /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F900}-\u{1F9FF}\u{1FA00}-\u{1FA6F}\u{1FA70}-\u{1FAFF}\u{231A}-\u{231B}\u{23E9}-\u{23F3}\u{23F8}-\u{23FA}\u{25AA}-\u{25AB}\u{25B6}\u{25C0}\u{25FB}-\u{25FE}\u{2614}-\u{2615}\u{2648}-\u{2653}\u{267F}\u{2693}\u{26A1}\u{26AA}-\u{26AB}\u{26BD}-\u{26BE}\u{26C4}-\u{26C5}\u{26CE}\u{26D4}\u{26EA}\u{26F2}-\u{26F3}\u{26F5}\u{26FA}\u{26FD}\u{2702}\u{2705}\u{2708}-\u{270D}\u{270F}]/gu

/** Threshold: emoji density above this fraction flags suspicious */
const EMOJI_DENSITY_THRESHOLD = 0.3

/** Threshold: number of regional indicators that triggers detection */
const REGIONAL_INDICATOR_THRESHOLD = 4

/** Threshold: number of keycap sequences that triggers detection */
const KEYCAP_THRESHOLD = 3

/** Threshold: skin tone modifier count that triggers data-carrier suspicion */
const SKIN_TONE_THRESHOLD = 5

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/** Result of emoji smuggling analysis */
export interface EmojiSmugglingResult {
  readonly detected: boolean
  readonly regionalIndicatorCount: number
  readonly decodedRegionalText: string
  readonly skinToneModifierCount: number
  readonly keycapSequenceCount: number
  readonly decodedKeycapNumbers: string
  readonly emojiDensity: number
  readonly suspiciousPatterns: readonly string[]
}

// ---------------------------------------------------------------------------
// EmojiSmugglingDetector class
// ---------------------------------------------------------------------------

export class EmojiSmugglingDetector {
  constructor(private readonly config: ShieldXConfig) {}

  /**
   * Analyze input for emoji-based smuggling techniques.
   *
   * @param input - Raw user input string
   * @returns Analysis result with decoded payloads and detection flags
   */
  analyze(input: string): EmojiSmugglingResult {
    const suspiciousPatterns: string[] = []

    // 1. Regional indicator detection and decoding
    const regionalMatches = [...input.matchAll(REGIONAL_INDICATOR_REGEX)]
    const regionalIndicatorCount = regionalMatches.length
    const decodedRegionalText = this.decodeRegionalIndicators(regionalMatches)

    if (regionalIndicatorCount >= REGIONAL_INDICATOR_THRESHOLD) {
      suspiciousPatterns.push('regional_indicator_smuggling')
    }

    // 2. Skin tone modifier analysis
    const skinToneMatches = input.match(SKIN_TONE_MODIFIERS_REGEX)
    const skinToneModifierCount = skinToneMatches?.length ?? 0

    if (skinToneModifierCount >= SKIN_TONE_THRESHOLD) {
      suspiciousPatterns.push('skin_tone_data_carrier')
    }

    // 3. Keycap sequence detection and decoding
    const keycapMatches = [...input.matchAll(KEYCAP_SEQUENCE_REGEX)]
    const keycapSequenceCount = keycapMatches.length
    const decodedKeycapNumbers = keycapMatches
      .map((m) => m[0].charAt(0))
      .join('')

    if (keycapSequenceCount >= KEYCAP_THRESHOLD) {
      suspiciousPatterns.push('keycap_number_encoding')
    }

    // 4. Emoji density check
    const emojiDensity = this.computeEmojiDensity(input)

    if (emojiDensity > EMOJI_DENSITY_THRESHOLD) {
      suspiciousPatterns.push('excessive_emoji_density')
    }

    const detected = suspiciousPatterns.length > 0

    return {
      detected,
      regionalIndicatorCount,
      decodedRegionalText,
      skinToneModifierCount,
      keycapSequenceCount,
      decodedKeycapNumbers,
      emojiDensity,
      suspiciousPatterns,
    }
  }

  /**
   * Produce a ScanResult for the ShieldX pipeline.
   *
   * @param input - Raw user input string
   * @returns ScanResult with emoji smuggling detection details
   */
  scan(input: string): ScanResult {
    const start = performance.now()
    const result = this.analyze(input)
    const latencyMs = performance.now() - start

    const rawScore = Math.min(
      1.0,
      (result.regionalIndicatorCount / 20) +
      (result.keycapSequenceCount / 10) +
      (result.skinToneModifierCount / 15) +
      (result.emojiDensity > EMOJI_DENSITY_THRESHOLD ? 0.3 : 0),
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
        regionalIndicatorCount: result.regionalIndicatorCount,
        decodedRegionalText: result.decodedRegionalText,
        skinToneModifierCount: result.skinToneModifierCount,
        keycapSequenceCount: result.keycapSequenceCount,
        decodedKeycapNumbers: result.decodedKeycapNumbers,
        emojiDensity: result.emojiDensity,
      },
    }
  }

  /**
   * Strip/neutralize emoji smuggling sequences from input.
   * Replaces regional indicators with their decoded Latin letters,
   * strips skin tone modifiers used as data carriers,
   * and replaces keycap sequences with plain digits.
   *
   * @param input - Raw user input string
   * @returns Neutralized string with emoji smuggling removed
   */
  neutralize(input: string): string {
    // Replace regional indicator pairs/sequences with decoded letters
    let result = input.replace(REGIONAL_INDICATOR_REGEX, (char) => {
      const codePoint = char.codePointAt(0)
      if (codePoint === undefined) return ''
      const letterIndex = codePoint - REGIONAL_INDICATOR_BASE
      if (letterIndex >= 0 && letterIndex < 26) {
        return String.fromCharCode(65 + letterIndex) // A-Z uppercase
      }
      return ''
    })

    // Strip standalone skin tone modifiers (when not attached to a base emoji)
    result = result.replace(SKIN_TONE_MODIFIERS_REGEX, '')

    // Replace keycap sequences with plain digits
    result = result.replace(KEYCAP_SEQUENCE_REGEX, (match) => match.charAt(0))

    return result
  }

  /**
   * Decode regional indicator symbols into Latin letters.
   * Each regional indicator maps to A-Z: U+1F1E6 = A, U+1F1E7 = B, etc.
   */
  private decodeRegionalIndicators(
    matches: readonly RegExpMatchArray[],
  ): string {
    return matches
      .map((m) => {
        const codePoint = m[0].codePointAt(0)
        if (codePoint === undefined) return ''
        const letterIndex = codePoint - REGIONAL_INDICATOR_BASE
        if (letterIndex >= 0 && letterIndex < 26) {
          return String.fromCharCode(65 + letterIndex)
        }
        return ''
      })
      .join('')
  }

  /**
   * Compute emoji density as fraction of input characters that are emoji.
   * Uses grapheme-aware counting where possible.
   */
  private computeEmojiDensity(input: string): number {
    if (input.length === 0) return 0

    // Count codepoints, not bytes
    const codePoints = [...input]
    const totalCodePoints = codePoints.length
    if (totalCodePoints === 0) return 0

    const emojiMatches = input.match(EMOJI_BROAD_REGEX)
    const emojiCount = emojiMatches?.length ?? 0

    return emojiCount / totalCodePoints
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
