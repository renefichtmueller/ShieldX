/**
 * SignedPromptVerifier — Cryptographic prompt signing and verification.
 *
 * Implements HMAC-SHA256 prompt signing per ACL 2025 research on
 * protecting system prompts from modification during conversation.
 * Signs prompts at initialization and verifies integrity at each turn,
 * detecting tampering or injection that alters the system prompt.
 */

import { createHmac, timingSafeEqual } from 'node:crypto'
import type { ShieldXConfig } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A signed prompt with its HMAC signature */
export interface SignedPrompt {
  readonly signed: string
  readonly signature: string
}

/** Result of tampering detection between two prompt versions */
export interface TamperingResult {
  readonly tampered: boolean
  readonly diffs: readonly string[]
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Signature header embedded in the signed prompt */
const SIGNATURE_HEADER = '[ShieldX-Sig:'
const SIGNATURE_FOOTER = ']'

/** Maximum diff entries to return (prevent unbounded output) */
const MAX_DIFFS = 50

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Signed Prompt Verifier.
 *
 * Signs system prompts with HMAC-SHA256 so any modification during
 * the conversation can be detected. Supports signing, verification,
 * and detailed tampering analysis.
 */
export class SignedPromptVerifier {
  private readonly _config: ShieldXConfig

  /** Access the active configuration */
  get config(): ShieldXConfig { return this._config }

  constructor(config: ShieldXConfig) {
    this._config = config
  }

  /**
   * Sign a prompt with HMAC-SHA256.
   *
   * @param prompt - The prompt text to sign
   * @param secret - Signing secret (per-deployment or per-session)
   * @returns Signed prompt string and detached signature
   */
  signPrompt(prompt: string, secret: string): SignedPrompt {
    const signature = this.computeSignature(prompt, secret)

    const signed = [
      `${SIGNATURE_HEADER}${signature}${SIGNATURE_FOOTER}`,
      prompt,
    ].join('\n')

    return Object.freeze({ signed, signature })
  }

  /**
   * Verify a signed prompt against its signature.
   *
   * @param signed - The signed prompt string (with embedded signature)
   * @param signature - The expected signature
   * @param secret - The signing secret
   * @returns True if the prompt has not been modified
   */
  verifyPrompt(
    signed: string,
    signature: string,
    secret: string,
  ): boolean {
    const extracted = this.extractPromptFromSigned(signed)
    if (extracted === null) return false

    const { prompt: extractedPrompt, embeddedSignature } = extracted

    // Verify embedded signature matches provided signature
    if (!this.safeCompare(embeddedSignature, signature)) {
      return false
    }

    // Recompute and verify
    const expectedSignature = this.computeSignature(extractedPrompt, secret)
    return this.safeCompare(signature, expectedSignature)
  }

  /**
   * Detect tampering between the original prompt and the current version.
   *
   * @param original - The original prompt text
   * @param current - The current prompt text to check
   * @returns Tampering detection result with diff details
   */
  detectTampering(original: string, current: string): TamperingResult {
    if (original === current) {
      return Object.freeze({ tampered: false, diffs: Object.freeze([]) })
    }

    const diffs = this.computeDiffs(original, current)

    return Object.freeze({
      tampered: true,
      diffs: Object.freeze(diffs),
    })
  }

  /**
   * Sign a prompt and return only the signature (no embedding).
   * Useful for storing signatures separately.
   *
   * @param prompt - The prompt text
   * @param secret - The signing secret
   * @returns HMAC-SHA256 signature hex string
   */
  computeSignature(prompt: string, secret: string): string {
    const hmac = createHmac('sha256', secret)
    hmac.update(prompt)
    return hmac.digest('hex')
  }

  /** Extract prompt content and embedded signature from a signed string */
  private extractPromptFromSigned(
    signed: string,
  ): { readonly prompt: string; readonly embeddedSignature: string } | null {
    const firstNewline = signed.indexOf('\n')
    if (firstNewline === -1) return null

    const firstLine = signed.slice(0, firstNewline)

    if (
      !firstLine.startsWith(SIGNATURE_HEADER) ||
      !firstLine.endsWith(SIGNATURE_FOOTER)
    ) {
      return null
    }

    const embeddedSignature = firstLine.slice(
      SIGNATURE_HEADER.length,
      -SIGNATURE_FOOTER.length,
    )
    const prompt = signed.slice(firstNewline + 1)

    return { prompt, embeddedSignature }
  }

  /**
   * Compute line-level diffs between original and current.
   * Returns human-readable diff descriptions capped at MAX_DIFFS.
   */
  private computeDiffs(original: string, current: string): readonly string[] {
    const originalLines = original.split('\n')
    const currentLines = current.split('\n')
    const diffs: string[] = []

    const maxLines = Math.max(originalLines.length, currentLines.length)

    for (let i = 0; i < maxLines && diffs.length < MAX_DIFFS; i++) {
      const origLine = i < originalLines.length ? originalLines[i] : undefined
      const currLine = i < currentLines.length ? currentLines[i] : undefined

      if (origLine === undefined && currLine !== undefined) {
        diffs.push(`+L${i + 1}: Line added`)
      } else if (origLine !== undefined && currLine === undefined) {
        diffs.push(`-L${i + 1}: Line removed`)
      } else if (origLine !== currLine) {
        diffs.push(`~L${i + 1}: Line modified`)
      }
    }

    // Check for length changes
    if (originalLines.length !== currentLines.length) {
      diffs.push(
        `Length changed: ${originalLines.length} -> ${currentLines.length} lines`,
      )
    }

    // Check for character-level changes
    if (original.length !== current.length) {
      diffs.push(
        `Size changed: ${original.length} -> ${current.length} chars`,
      )
    }

    return diffs.slice(0, MAX_DIFFS)
  }

  /** Timing-safe string comparison */
  private safeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false
    try {
      return timingSafeEqual(Buffer.from(a), Buffer.from(b))
    } catch {
      return false
    }
  }
}
