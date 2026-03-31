/**
 * Preprocessing — Layer 0 defense.
 *
 * Zero-cost, high-impact filters that run before all other scanners.
 * Strips steganographic/invisible attacks and decodes obfuscated payloads
 * so downstream layers see clean plaintext.
 *
 * Modules:
 * - UnicodeNormalizer: Strips invisible Unicode, homoglyphs, BiDi overrides
 * - TokenizerNormalizer: Prevents retokenization attacks (MetaBreak 2025)
 * - CompressedPayloadDetector: Decodes Base64, hex, URL, HTML entity payloads
 */

export { UnicodeNormalizer } from './UnicodeNormalizer.js'
export type { UnicodeNormalizationResult } from './UnicodeNormalizer.js'

export { TokenizerNormalizer } from './TokenizerNormalizer.js'

export { CompressedPayloadDetector } from './CompressedPayloadDetector.js'
export type { EncodedPayloadResult } from './CompressedPayloadDetector.js'
