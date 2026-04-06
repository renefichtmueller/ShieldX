/**
 * Preprocessing — Layer 0 defense.
 *
 * Zero-cost, high-impact filters that run before all other scanners.
 * Strips steganographic/invisible attacks and decodes obfuscated payloads
 * so downstream layers see clean plaintext.
 *
 * Modules:
 * - UnicodeNormalizer: Strips invisible Unicode, homoglyphs, BiDi overrides,
 *   emoji smuggling, and upside-down text
 * - EmojiSmugglingDetector: Detects regional indicators, keycap encoding,
 *   skin tone data carriers, excessive emoji density
 * - UpsideDownTextDetector: Detects and normalizes flipped Unicode characters
 * - TokenizerNormalizer: Prevents retokenization attacks (MetaBreak 2025)
 * - CompressedPayloadDetector: Decodes Base64, hex, URL, HTML entity payloads
 * - CipherDecoder: Detects FlipAttack, ROT13, Caesar, Morse, leet speak, Pig Latin, ASCII art
 */

export { UnicodeNormalizer } from './UnicodeNormalizer.js'
export type { UnicodeNormalizationResult } from './UnicodeNormalizer.js'

export { EmojiSmugglingDetector } from './EmojiSmugglingDetector.js'
export type { EmojiSmugglingResult } from './EmojiSmugglingDetector.js'

export { UpsideDownTextDetector } from './UpsideDownTextDetector.js'
export type { UpsideDownTextResult } from './UpsideDownTextDetector.js'

export { TokenizerNormalizer } from './TokenizerNormalizer.js'

export { CompressedPayloadDetector } from './CompressedPayloadDetector.js'
export type { EncodedPayloadResult } from './CompressedPayloadDetector.js'

export { CipherDecoder } from './CipherDecoder.js'
export type { CipherDecoderResult, CipherType } from './CipherDecoder.js'
