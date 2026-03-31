/**
 * CompressedPayloadDetector — Layer 0 encoded payload detection.
 *
 * Detects and decodes Base64, hex, URL-encoded, Unicode escape, HTML entity,
 * and ROT13-encoded payloads that hide prompt injections inside encoded strings.
 * Supports recursive decoding (up to 3 levels) for nested encodings like
 * Base64(URL(text)).
 *
 * This runs in the preprocessing layer so downstream scanners see the
 * decoded plaintext, not the obfuscated payload.
 */

import type { ScanResult, ScannerType, ShieldXConfig } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SCANNER_ID = 'compressed-payload-detector'
const SCANNER_TYPE: ScannerType = 'compressed_payload'
const DEFAULT_MAX_DEPTH = 3

/**
 * Base64 pattern: blocks of 20+ valid base64 characters with optional padding.
 * Must start/end on word boundaries to avoid false positives on short tokens.
 */
const BASE64_REGEX = /(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g

/**
 * Hex-encoded sequences: 0x-prefixed or backslash-x escaped.
 * Matches sequences of at least 4 hex pairs.
 */
const HEX_0X_REGEX = /0x(?:[0-9a-fA-F]{2}){4,}/g
const HEX_ESCAPED_REGEX = /(?:\\x[0-9a-fA-F]{2}){4,}/g

/**
 * URL-encoded sequences: %XX patterns, at least 4 in a row.
 */
const URL_ENCODED_REGEX = /(?:%[0-9a-fA-F]{2}){4,}/g

/**
 * Unicode escape sequences: \uXXXX patterns.
 */
const UNICODE_ESCAPE_REGEX = /(?:\\u[0-9a-fA-F]{4}){3,}/g

/**
 * HTML numeric entities: &#XXXX; or &#xXXXX; patterns.
 */
const HTML_NUMERIC_ENTITY_REGEX = /(?:&#x?[0-9a-fA-F]+;){3,}/g

/**
 * HTML named entities (common attack vectors).
 */
const HTML_NAMED_ENTITY_REGEX = /&(?:amp|lt|gt|quot|apos|nbsp|tab|newline|lpar|rpar|lsqb|rsqb|lcub|rcub|sol|bsol|colon|semi|comma|period|excl|quest|num|dollar|percnt|ast|plus|equals|hyphen);/gi

/**
 * Known attack patterns to check in decoded/ROT13'd content.
 * Kept lowercase for case-insensitive matching.
 */
const ATTACK_KEYWORDS: readonly string[] = [
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
]

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** Detection result with decoded payloads */
export interface EncodedPayloadResult {
  readonly hasEncodedPayload: boolean
  readonly decodedPayloads: readonly string[]
  readonly encodingTypes: readonly string[]
}

// ---------------------------------------------------------------------------
// CompressedPayloadDetector class
// ---------------------------------------------------------------------------

export class CompressedPayloadDetector {
  private readonly maxDecodeDepth: number

  /**
   * Create a CompressedPayloadDetector.
   * @param config - ShieldX configuration
   */
  constructor(private readonly config: ShieldXConfig) {
    this.maxDecodeDepth = DEFAULT_MAX_DEPTH
  }

  /**
   * Detect encoded payloads in input.
   * Async (up to 2ms target).
   *
   * @param input - Input string to scan for encoded payloads
   * @returns Detection result with decoded payloads and encoding types found
   */
  async detect(input: string): Promise<EncodedPayloadResult> {
    const decodedPayloads: string[] = []
    const encodingTypes: string[] = []

    // Base64
    const base64Matches = input.match(BASE64_REGEX)
    if (base64Matches) {
      for (const match of base64Matches) {
        const decoded = this.tryBase64Decode(match)
        if (decoded !== null) {
          decodedPayloads.push(decoded)
          if (!encodingTypes.includes('base64')) {
            encodingTypes.push('base64')
          }
        }
      }
    }

    // Hex (0x prefix)
    const hex0xMatches = input.match(HEX_0X_REGEX)
    if (hex0xMatches) {
      for (const match of hex0xMatches) {
        const decoded = this.decodeHex0x(match)
        if (decoded !== null) {
          decodedPayloads.push(decoded)
          if (!encodingTypes.includes('hex')) {
            encodingTypes.push('hex')
          }
        }
      }
    }

    // Hex (backslash-x escaped)
    const hexEscMatches = input.match(HEX_ESCAPED_REGEX)
    if (hexEscMatches) {
      for (const match of hexEscMatches) {
        const decoded = this.decodeHexEscaped(match)
        if (decoded !== null) {
          decodedPayloads.push(decoded)
          if (!encodingTypes.includes('hex_escaped')) {
            encodingTypes.push('hex_escaped')
          }
        }
      }
    }

    // URL encoding
    const urlMatches = input.match(URL_ENCODED_REGEX)
    if (urlMatches) {
      for (const match of urlMatches) {
        const decoded = this.tryUrlDecode(match)
        if (decoded !== null) {
          decodedPayloads.push(decoded)
          if (!encodingTypes.includes('url_encoding')) {
            encodingTypes.push('url_encoding')
          }
        }
      }
    }

    // Unicode escapes
    const unicodeMatches = input.match(UNICODE_ESCAPE_REGEX)
    if (unicodeMatches) {
      for (const match of unicodeMatches) {
        const decoded = this.decodeUnicodeEscapes(match)
        if (decoded !== null) {
          decodedPayloads.push(decoded)
          if (!encodingTypes.includes('unicode_escape')) {
            encodingTypes.push('unicode_escape')
          }
        }
      }
    }

    // HTML numeric entities
    const htmlNumericMatches = input.match(HTML_NUMERIC_ENTITY_REGEX)
    if (htmlNumericMatches) {
      for (const match of htmlNumericMatches) {
        const decoded = this.decodeHtmlNumericEntities(match)
        if (decoded !== null) {
          decodedPayloads.push(decoded)
          if (!encodingTypes.includes('html_entity')) {
            encodingTypes.push('html_entity')
          }
        }
      }
    }

    // HTML named entities
    const htmlNamedMatches = input.match(HTML_NAMED_ENTITY_REGEX)
    if (htmlNamedMatches && htmlNamedMatches.length >= 3) {
      if (!encodingTypes.includes('html_named_entity')) {
        encodingTypes.push('html_named_entity')
      }
    }

    // ROT13 heuristic: apply ROT13 to the whole input and check for attack patterns
    const rot13Result = this.applyRot13(input)
    if (this.containsAttackPatterns(rot13Result)) {
      decodedPayloads.push(rot13Result)
      if (!encodingTypes.includes('rot13')) {
        encodingTypes.push('rot13')
      }
    }

    return {
      hasEncodedPayload: encodingTypes.length > 0,
      decodedPayloads,
      encodingTypes,
    }
  }

  /**
   * Scan input for encoded payloads and return a ScanResult.
   * Async (up to 2ms target).
   *
   * @param input - Raw input string
   * @returns ScanResult with detection details
   */
  async scan(input: string): Promise<ScanResult> {
    const start = performance.now()
    const result = await this.detect(input)
    const latencyMs = performance.now() - start

    // Check decoded payloads for attack patterns
    const attackPatternsFound: string[] = []
    for (const decoded of result.decodedPayloads) {
      const patterns = this.findAttackPatterns(decoded)
      for (const p of patterns) {
        if (!attackPatternsFound.includes(p)) {
          attackPatternsFound.push(p)
        }
      }
    }

    const hasAttackPatterns = attackPatternsFound.length > 0
    const isSuspicious = result.hasEncodedPayload

    const rawScore = Math.min(
      1.0,
      (result.encodingTypes.length / 5) +
        (hasAttackPatterns ? 0.5 : 0) +
        (result.decodedPayloads.length / 10),
    )

    const confidence = hasAttackPatterns
      ? Math.max(0.7, rawScore)
      : isSuspicious
        ? Math.max(0.3, rawScore)
        : 0

    const threatLevel = this.computeThreatLevel(confidence)

    const matchedPatterns = [
      ...result.encodingTypes.map((t) => `encoding:${t}`),
      ...attackPatternsFound.map((p) => `attack:${p}`),
    ]

    return {
      scannerId: SCANNER_ID,
      scannerType: SCANNER_TYPE,
      detected: isSuspicious,
      confidence,
      threatLevel,
      killChainPhase: hasAttackPatterns ? 'initial_access' : isSuspicious ? 'reconnaissance' : 'none',
      matchedPatterns,
      rawScore,
      latencyMs,
      metadata: {
        encodingTypes: result.encodingTypes,
        decodedPayloadCount: result.decodedPayloads.length,
        attackPatternsFound: attackPatternsFound.length,
      },
    }
  }

  /**
   * Recursively decode all known encodings and return plaintext.
   * Decodes up to maxDepth levels to handle nested encodings like Base64(URL(text)).
   *
   * @param input - Encoded input string
   * @param maxDepth - Maximum recursion depth (default 3)
   * @returns Fully decoded plaintext
   */
  async decodeRecursive(input: string, maxDepth: number = this.maxDecodeDepth): Promise<string> {
    let current = input
    let depth = 0

    while (depth < maxDepth) {
      const decoded = this.decodeOneLevel(current)
      if (decoded === current) {
        // No more encodings found
        break
      }
      current = decoded
      depth++
    }

    return current
  }

  // ---------------------------------------------------------------------------
  // Private decode helpers
  // ---------------------------------------------------------------------------

  /**
   * Attempt one level of decoding across all supported encodings.
   */
  private decodeOneLevel(input: string): string {
    let result = input

    // URL decode
    result = this.replaceAllEncoded(result, URL_ENCODED_REGEX, (m) => this.tryUrlDecode(m) ?? m)

    // Base64 decode
    result = this.replaceAllEncoded(result, BASE64_REGEX, (m) => this.tryBase64Decode(m) ?? m)

    // Hex 0x decode
    result = this.replaceAllEncoded(result, HEX_0X_REGEX, (m) => this.decodeHex0x(m) ?? m)

    // Hex escaped decode
    result = this.replaceAllEncoded(result, HEX_ESCAPED_REGEX, (m) => this.decodeHexEscaped(m) ?? m)

    // Unicode escapes
    result = this.replaceAllEncoded(result, UNICODE_ESCAPE_REGEX, (m) => this.decodeUnicodeEscapes(m) ?? m)

    // HTML numeric entities
    result = this.replaceAllEncoded(result, HTML_NUMERIC_ENTITY_REGEX, (m) => this.decodeHtmlNumericEntities(m) ?? m)

    return result
  }

  /**
   * Replace all matches of a regex using a replacer function.
   * Returns original string if no matches found.
   */
  private replaceAllEncoded(
    input: string,
    regex: RegExp,
    replacer: (match: string) => string,
  ): string {
    // Reset regex state for global regexes
    const freshRegex = new RegExp(regex.source, regex.flags)
    return input.replace(freshRegex, replacer)
  }

  /**
   * Try to decode a Base64 string. Returns null if not valid Base64
   * or if the decoded result is not valid UTF-8 text.
   */
  private tryBase64Decode(encoded: string): string | null {
    try {
      const decoded = Buffer.from(encoded, 'base64').toString('utf-8')
      // Verify it produced readable text (not binary garbage)
      // Check that most characters are printable ASCII or common Unicode
      const printableRatio = this.computePrintableRatio(decoded)
      if (printableRatio < 0.7) return null
      // Also verify round-trip: re-encoding should match
      const reEncoded = Buffer.from(decoded, 'utf-8').toString('base64')
      // Remove padding differences for comparison
      const stripPad = (s: string): string => s.replace(/=+$/, '')
      if (stripPad(reEncoded) !== stripPad(encoded)) return null
      return decoded
    } catch {
      return null
    }
  }

  /**
   * Decode 0x-prefixed hex string.
   */
  private decodeHex0x(encoded: string): string | null {
    try {
      const hex = encoded.startsWith('0x') ? encoded.slice(2) : encoded
      const buf = Buffer.from(hex, 'hex')
      const decoded = buf.toString('utf-8')
      if (this.computePrintableRatio(decoded) < 0.7) return null
      return decoded
    } catch {
      return null
    }
  }

  /**
   * Decode backslash-x escaped hex sequences.
   */
  private decodeHexEscaped(encoded: string): string | null {
    try {
      const hex = encoded.replace(/\\x/g, '')
      const buf = Buffer.from(hex, 'hex')
      const decoded = buf.toString('utf-8')
      if (this.computePrintableRatio(decoded) < 0.7) return null
      return decoded
    } catch {
      return null
    }
  }

  /**
   * Try to URL-decode a string. Returns null on failure.
   */
  private tryUrlDecode(encoded: string): string | null {
    try {
      return decodeURIComponent(encoded)
    } catch {
      return null
    }
  }

  /**
   * Decode Unicode escape sequences (\uXXXX).
   */
  private decodeUnicodeEscapes(encoded: string): string | null {
    try {
      const decoded = encoded.replace(
        /\\u([0-9a-fA-F]{4})/g,
        (_, hex: string) => String.fromCharCode(parseInt(hex, 16)),
      )
      return decoded
    } catch {
      return null
    }
  }

  /**
   * Decode HTML numeric entities (&#XXXX; and &#xXXXX;).
   */
  private decodeHtmlNumericEntities(encoded: string): string | null {
    try {
      const decoded = encoded.replace(
        /&#(x?)([0-9a-fA-F]+);/g,
        (_, isHex: string, num: string) => {
          const codePoint = isHex ? parseInt(num, 16) : parseInt(num, 10)
          return String.fromCodePoint(codePoint)
        },
      )
      return decoded
    } catch {
      return null
    }
  }

  /**
   * Apply ROT13 cipher to a string (letters only).
   */
  private applyRot13(input: string): string {
    return input.replace(/[a-zA-Z]/g, (ch) => {
      const base = ch <= 'Z' ? 65 : 97
      return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base)
    })
  }

  /**
   * Check if a string contains known attack patterns.
   */
  private containsAttackPatterns(text: string): boolean {
    const lower = text.toLowerCase()
    return ATTACK_KEYWORDS.some((keyword) => lower.includes(keyword))
  }

  /**
   * Find all attack patterns present in text.
   */
  private findAttackPatterns(text: string): string[] {
    const lower = text.toLowerCase()
    return ATTACK_KEYWORDS.filter((keyword) => lower.includes(keyword))
  }

  /**
   * Compute the ratio of printable characters in a string.
   * Used to distinguish decoded text from binary garbage.
   */
  private computePrintableRatio(text: string): number {
    if (text.length === 0) return 0
    let printable = 0
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i)
      // Printable ASCII, common Latin extended, or common Unicode
      if (
        (code >= 0x20 && code <= 0x7E) || // ASCII printable
        code === 0x09 || code === 0x0A || code === 0x0D || // tab, LF, CR
        (code >= 0xA0 && code <= 0xFFFF) // Latin extended + common Unicode
      ) {
        printable++
      }
    }
    return printable / text.length
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
