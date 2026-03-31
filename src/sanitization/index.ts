/**
 * Sanitization — Layer 8 defense.
 *
 * Pre/post-LLM sanitization, polymorphic prompt assembly, channel separation,
 * spotlighting, delimiter hardening, credential redaction, and prompt signing.
 *
 * Modules:
 * - InputSanitizer: Pre-LLM input cleaning (strips injection patterns)
 * - OutputSanitizer: Post-LLM output validation and cleaning
 * - PolymorphicAssembler: PPA — randomized prompt structure per session
 * - StructuredQueryEncoder: StruQ channel separation (USENIX Security 2025)
 * - SpotlightingEncoder: Microsoft Spotlighting (3 modes)
 * - DelimiterHardener: Cryptographic delimiter generation and verification
 * - CredentialRedactor: API key, secret, token redaction (Presidio-inspired)
 * - SignedPromptVerifier: HMAC-SHA256 prompt signing (ACL 2025)
 */

export { InputSanitizer } from './InputSanitizer.js'
export type { InputSanitizationResult } from './InputSanitizer.js'

export { OutputSanitizer } from './OutputSanitizer.js'
export type { OutputSanitizationResult } from './OutputSanitizer.js'

export { PolymorphicAssembler } from './PolymorphicAssembler.js'
export type { AssemblyResult } from './PolymorphicAssembler.js'

export { StructuredQueryEncoder } from './StructuredQueryEncoder.js'
export type { StructuredQueryResult } from './StructuredQueryEncoder.js'

export { SpotlightingEncoder } from './SpotlightingEncoder.js'
export type { SpotlightingResult } from './SpotlightingEncoder.js'

export { DelimiterHardener } from './DelimiterHardener.js'
export type { DelimiterVerificationResult } from './DelimiterHardener.js'

export { CredentialRedactor } from './CredentialRedactor.js'
export type { RedactionResult } from './CredentialRedactor.js'

export { SignedPromptVerifier } from './SignedPromptVerifier.js'
export type { SignedPrompt, TamperingResult } from './SignedPromptVerifier.js'
