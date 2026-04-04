/**
 * CipherDecoder — Layer 0 character-level cipher attack detection.
 *
 * Detects and decodes cipher-based obfuscation techniques used to hide
 * prompt injection payloads from text-based rule engines:
 *
 * - FlipAttack: reversed text (char or word level) expecting model to reverse
 * - ArtPrompt: ASCII art representation of harmful words
 * - CipherChat: ROT13, Caesar cipher (shifts 1-25), Morse code, Pig Latin
 * - Leet speak: 1337 substitutions (e/3, a/4, i/1, o/0, s/5, ...)
 *
 * Runs synchronously, targeting <3ms execution.
 */

import type { ShieldXConfig } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Supported cipher obfuscation types */
export type CipherType =
  | 'flip_attack_char'
  | 'flip_attack_word'
  | 'rot13'
  | `caesar_${number}`
  | 'morse_code'
  | 'leet_speak'
  | 'pig_latin'
  | 'ascii_art_suspected'

/** Result returned by CipherDecoder.decode() */
export interface CipherDecoderResult {
  /** Original unmodified input */
  readonly original: string
  /** Decoded/normalized version most likely to reveal true intent */
  readonly normalized: string
  /** All cipher types detected in the input */
  readonly detectedCiphers: CipherType[]
  /** Aggregate suspicion score 0.0–1.0 */
  readonly suspicionScore: number
  /** All decoded versions keyed by cipher type */
  readonly decodedVersions: ReadonlyArray<{ cipher: CipherType; decoded: string }>
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * 30 jailbreak keywords checked against decoded/reversed text.
 * Kept lowercase for case-insensitive matching.
 */
const JAILBREAK_KEYWORDS: readonly string[] = [
  'ignore previous',
  'ignore above',
  'ignore all',
  'disregard',
  'forget your instructions',
  'new instructions',
  'system prompt',
  'you are now',
  'act as',
  'pretend you',
  'override',
  'jailbreak',
  'developer mode',
  'sudo',
  'admin access',
  'execute command',
  'run command',
  'reveal secret',
  'show password',
  'bypass',
  'disable safety',
  'no restrictions',
  'dan mode',
  'do anything now',
  'without restrictions',
  'no filters',
  'unrestricted',
  'harmful content',
  'malicious',
  'evil instructions',
]

/**
 * Top English bigrams by frequency for Caesar/ROT13 quality scoring.
 */
const COMMON_BIGRAMS: readonly string[] = [
  'th', 'he', 'in', 'er', 'an', 're', 'nd', 'at', 'on', 'en',
  'nt', 'io', 'es', 'is', 'or', 'ti', 'it', 'ar', 'te', 'se',
]

/**
 * Morse code lookup table (character → morse).
 */
const MORSE_DECODE: Readonly<Record<string, string>> = {
  '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e',
  '..-.': 'f', '--.': 'g', '....': 'h', '..': 'i', '.---': 'j',
  '-.-': 'k', '.-..': 'l', '--': 'm', '-.': 'n', '---': 'o',
  '.--.': 'p', '--.-': 'q', '.-.': 'r', '...': 's', '-': 't',
  '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x', '-.--': 'y',
  '--..': 'z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
  '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
  '----.': '9',
}

/**
 * Leet speak substitution map (leet char → plain char).
 */
const LEET_MAP: Readonly<Record<string, string>> = {
  '3': 'e', '4': 'a', '1': 'i', '0': 'o', '5': 's', '7': 't',
  '@': 'a', '$': 's', '!': 'i', '+': 't', '|': 'i', '(': 'c',
  '&': 'and', '#': 'h', '%': 'x',
}

// ---------------------------------------------------------------------------
// CipherDecoder class
// ---------------------------------------------------------------------------

/**
 * Detects and decodes character-level cipher attacks in LLM prompt inputs.
 * Synchronous, <3ms target execution time.
 */
export class CipherDecoder {
  /**
   * Create a CipherDecoder.
   * @param config - ShieldX configuration (reserved for future threshold config)
   */
  constructor(private readonly config?: ShieldXConfig) {}

  /**
   * Decode and analyze input for all supported cipher attack types.
   *
   * @param input - Raw input string to analyze
   * @returns CipherDecoderResult with detections, decoded versions, and suspicion score
   */
  decode(input: string): CipherDecoderResult {
    const decodedVersions: Array<{ cipher: CipherType; decoded: string }> = []
    const detectedCiphers: CipherType[] = []

    // Run all detection passes
    this.detectFlipAttack(input, decodedVersions, detectedCiphers)
    this.detectRot13(input, decodedVersions, detectedCiphers)
    this.detectCaesar(input, decodedVersions, detectedCiphers)
    this.detectMorse(input, decodedVersions, detectedCiphers)
    this.detectLeetSpeak(input, decodedVersions, detectedCiphers)
    this.detectPigLatin(input, detectedCiphers)
    this.detectAsciiArt(input, detectedCiphers)

    const suspicionScore = this.computeSuspicionScore(detectedCiphers, decodedVersions)

    // Best normalized: first decoded version that contains jailbreak keyword; else first decoded; else original
    const normalized = this.selectNormalized(input, decodedVersions)

    return {
      original: input,
      normalized,
      detectedCiphers,
      suspicionScore,
      decodedVersions,
    }
  }

  // ---------------------------------------------------------------------------
  // Detection: FlipAttack
  // ---------------------------------------------------------------------------

  /**
   * Detect character-level and word-level reversal attacks.
   * Checks if reversing the string or word order yields jailbreak keywords.
   */
  private detectFlipAttack(
    input: string,
    decodedVersions: Array<{ cipher: CipherType; decoded: string }>,
    detected: CipherType[],
  ): void {
    const charReversed = input.split('').reverse().join('')
    if (this.containsJailbreakKeyword(charReversed)) {
      detected.push('flip_attack_char')
      decodedVersions.push({ cipher: 'flip_attack_char', decoded: charReversed })
    }

    const wordReversed = input.split(/\s+/).reverse().join(' ')
    if (wordReversed !== charReversed && this.containsJailbreakKeyword(wordReversed)) {
      detected.push('flip_attack_word')
      decodedVersions.push({ cipher: 'flip_attack_word', decoded: wordReversed })
    }
  }

  // ---------------------------------------------------------------------------
  // Detection: ROT13
  // ---------------------------------------------------------------------------

  /**
   * Detect ROT13 encoding by checking bigram frequency improvement and jailbreak keywords.
   * ROT13 is its own inverse; apply once to decode.
   */
  private detectRot13(
    input: string,
    decodedVersions: Array<{ cipher: CipherType; decoded: string }>,
    detected: CipherType[],
  ): void {
    const rot13 = this.applyRot13(input)
    const originalScore = this.bigramScore(input)
    const decodedScore = this.bigramScore(rot13)

    const hasKeyword = this.containsJailbreakKeyword(rot13)
    const biggramImprovement = originalScore > 0 ? (decodedScore - originalScore) / originalScore : decodedScore

    if (hasKeyword || biggramImprovement > 0.2) {
      detected.push('rot13')
      decodedVersions.push({ cipher: 'rot13', decoded: rot13 })
    }
  }

  // ---------------------------------------------------------------------------
  // Detection: Caesar cipher
  // ---------------------------------------------------------------------------

  /**
   * Try all 25 Caesar shifts, detect if any shows >20% bigram improvement
   * or contains jailbreak keywords. Returns best candidate shift.
   */
  private detectCaesar(
    input: string,
    decodedVersions: Array<{ cipher: CipherType; decoded: string }>,
    detected: CipherType[],
  ): void {
    const originalScore = this.bigramScore(input)
    let bestShift = -1
    let bestScore = originalScore
    let bestDecoded = ''

    for (let shift = 1; shift <= 25; shift++) {
      const decoded = this.applyCaesarShift(input, shift)
      const score = this.bigramScore(decoded)
      const hasKeyword = this.containsJailbreakKeyword(decoded)

      if (hasKeyword || score > bestScore) {
        bestScore = score
        bestShift = shift
        bestDecoded = decoded
        if (hasKeyword) break
      }
    }

    const threshold = originalScore > 0 ? originalScore * 1.2 : 0.1
    if (bestShift !== -1 && (bestScore >= threshold || this.containsJailbreakKeyword(bestDecoded))) {
      const cipherType = `caesar_${bestShift}` as CipherType
      detected.push(cipherType)
      decodedVersions.push({ cipher: cipherType, decoded: bestDecoded })
    }
  }

  // ---------------------------------------------------------------------------
  // Detection: Morse code
  // ---------------------------------------------------------------------------

  /**
   * Detect Morse code patterns (dots, dashes, spaces) and attempt decoding.
   * Checks decoded result for jailbreak keywords or recognizable English words.
   */
  private detectMorse(
    input: string,
    decodedVersions: Array<{ cipher: CipherType; decoded: string }>,
    detected: CipherType[],
  ): void {
    // Morse pattern: only dots, dashes, spaces, slashes and newlines
    const morsePattern = /^[\s./\-|]+$/
    const tokenRatio = (input.match(/[.\-]/g)?.length ?? 0) / Math.max(input.length, 1)

    if (!morsePattern.test(input) || tokenRatio < 0.2) return

    const decoded = this.decodeMorse(input)
    if (decoded.length < 2) return

    if (this.containsJailbreakKeyword(decoded) || /[a-z]{3,}/i.test(decoded)) {
      detected.push('morse_code')
      decodedVersions.push({ cipher: 'morse_code', decoded })
    }
  }

  // ---------------------------------------------------------------------------
  // Detection: Leet speak
  // ---------------------------------------------------------------------------

  /**
   * Normalize leet speak substitutions and check for jailbreak keywords.
   * Only flags if normalized form contains known jailbreak patterns.
   */
  private detectLeetSpeak(
    input: string,
    decodedVersions: Array<{ cipher: CipherType; decoded: string }>,
    detected: CipherType[],
  ): void {
    const normalized = this.normalizeLeet(input)
    if (normalized === input) return

    if (this.containsJailbreakKeyword(normalized)) {
      detected.push('leet_speak')
      decodedVersions.push({ cipher: 'leet_speak', decoded: normalized })
    }
  }

  // ---------------------------------------------------------------------------
  // Detection: Pig Latin
  // ---------------------------------------------------------------------------

  /**
   * Detect Pig Latin by checking what fraction of words match [word]ay or [word]way pattern.
   * Flags if >40% of words match.
   */
  private detectPigLatin(input: string, detected: CipherType[]): void {
    const words = input.split(/\s+/).filter((w) => w.length > 2)
    if (words.length < 3) return

    const pigWords = words.filter((w) => /[a-z]+(ay|way)$/i.test(w))
    if (pigWords.length / words.length > 0.4) {
      detected.push('pig_latin')
    }
  }

  // ---------------------------------------------------------------------------
  // Detection: ASCII art
  // ---------------------------------------------------------------------------

  /**
   * Detect ASCII art by checking whitespace ratio and line structure.
   * High whitespace density with multiple consistent lines suggests character art.
   */
  private detectAsciiArt(input: string, detected: CipherType[]): void {
    const lines = input.split('\n')
    if (lines.length < 3) return

    const totalChars = input.length
    const whitespaceChars = (input.match(/[ \t]/g) ?? []).length
    const whitespaceRatio = whitespaceChars / Math.max(totalChars, 1)

    if (whitespaceRatio < 0.4) return

    const lineLengths = lines.map((l) => l.length)
    const maxLen = Math.max(...lineLengths)
    const consistentLines = lineLengths.filter((l) => l > maxLen * 0.5).length

    if (consistentLines >= 3) {
      detected.push('ascii_art_suspected')
    }
  }

  // ---------------------------------------------------------------------------
  // Scoring
  // ---------------------------------------------------------------------------

  /**
   * Compute suspicion score 0.0–1.0 based on detected ciphers and decoded content.
   */
  private computeSuspicionScore(
    detectedCiphers: CipherType[],
    decodedVersions: ReadonlyArray<{ cipher: CipherType; decoded: string }>,
  ): number {
    if (detectedCiphers.length === 0) return 0

    const hasHarmfulKeyword = decodedVersions.some(({ decoded }) =>
      this.containsJailbreakKeyword(decoded),
    )

    let score = hasHarmfulKeyword ? 0.7 : 0.3

    // ASCII art can't be fully decoded, lower base score
    const onlyAsciiArt =
      detectedCiphers.length === 1 && detectedCiphers[0] === 'ascii_art_suspected'
    if (onlyAsciiArt) return 0.3

    // Additional +0.1 per extra cipher beyond the first
    const extraCiphers = detectedCiphers.filter((c) => c !== 'ascii_art_suspected').length - 1
    score += Math.max(0, extraCiphers) * 0.1

    return Math.min(1.0, score)
  }

  // ---------------------------------------------------------------------------
  // Normalization selection
  // ---------------------------------------------------------------------------

  /**
   * Select the best normalized output: prefers decoded version containing
   * a jailbreak keyword; falls back to first decoded version or original.
   */
  private selectNormalized(
    original: string,
    decodedVersions: ReadonlyArray<{ cipher: CipherType; decoded: string }>,
  ): string {
    const harmful = decodedVersions.find(({ decoded }) => this.containsJailbreakKeyword(decoded))
    if (harmful) return harmful.decoded
    if (decodedVersions.length > 0) return decodedVersions[0].decoded
    return original
  }

  // ---------------------------------------------------------------------------
  // Cipher helpers
  // ---------------------------------------------------------------------------

  /**
   * Apply ROT13 transformation to alphabetic characters only.
   */
  private applyRot13(input: string): string {
    return input.replace(/[a-zA-Z]/g, (ch) => {
      const base = ch <= 'Z' ? 65 : 97
      return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base)
    })
  }

  /**
   * Apply Caesar cipher shift (positive = decode forward, decode by shifting back).
   * Shift N means input was encoded by shifting forward N — we shift back N.
   */
  private applyCaesarShift(input: string, shift: number): string {
    return input.replace(/[a-zA-Z]/g, (ch) => {
      const base = ch <= 'Z' ? 65 : 97
      return String.fromCharCode(((ch.charCodeAt(0) - base - shift + 26) % 26) + base)
    })
  }

  /**
   * Decode Morse code string. Words separated by ' / ' or double-space,
   * letters separated by single space.
   */
  private decodeMorse(input: string): string {
    const wordSeparator = /\s*[/|]\s*|\s{2,}/
    const words = input.trim().split(wordSeparator)
    return words
      .map((word) => {
        const letters = word.trim().split(/\s+/)
        return letters.map((code) => MORSE_DECODE[code.trim()] ?? '').join('')
      })
      .join(' ')
      .trim()
  }

  /**
   * Normalize leet speak substitutions to plain ASCII equivalents.
   */
  private normalizeLeet(input: string): string {
    let result = ''
    for (const ch of input) {
      result += LEET_MAP[ch] ?? ch
    }
    return result
  }

  // ---------------------------------------------------------------------------
  // Scoring helpers
  // ---------------------------------------------------------------------------

  /**
   * Compute bigram frequency score for an input string.
   * Higher score = more common English bigrams present.
   */
  private bigramScore(input: string): number {
    const lower = input.toLowerCase().replace(/[^a-z]/g, '')
    if (lower.length < 2) return 0

    let count = 0
    for (let i = 0; i < lower.length - 1; i++) {
      if (COMMON_BIGRAMS.includes(lower.slice(i, i + 2))) {
        count++
      }
    }
    return count / (lower.length - 1)
  }

  /**
   * Check if text contains any known jailbreak keyword (case-insensitive).
   */
  private containsJailbreakKeyword(text: string): boolean {
    const lower = text.toLowerCase()
    return JAILBREAK_KEYWORDS.some((kw) => lower.includes(kw))
  }
}
