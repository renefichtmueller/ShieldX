/**
 * StructuredQueryEncoder — StruQ channel separation.
 *
 * Implements the StruQ defense from USENIX Security 2025 (Berkeley BAIR).
 * Separates instructions and data into distinct channels using reserved
 * delimiter tokens, clearly marking untrusted data boundaries so the
 * LLM can distinguish between trusted instructions and untrusted user data.
 */

import { createHmac, randomBytes } from 'node:crypto'
import type { ShieldXConfig } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Result of structured query encoding */
export interface StructuredQueryResult {
  readonly encodedPrompt: string
  readonly metadata: Readonly<Record<string, string>>
}

/** Supported delimiter styles */
export type DelimiterStyle = 'xml' | 'bracket' | 'fence' | 'token'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Reserved StruQ delimiter tokens per style */
const DELIMITER_TEMPLATES: Readonly<Record<DelimiterStyle, {
  readonly instructionStart: string
  readonly instructionEnd: string
  readonly dataStart: string
  readonly dataEnd: string
}>> = Object.freeze({
  xml: {
    instructionStart: '<STRUQ_INSTRUCTION channel="trusted">',
    instructionEnd: '</STRUQ_INSTRUCTION>',
    dataStart: '<STRUQ_DATA channel="untrusted">',
    dataEnd: '</STRUQ_DATA>',
  },
  bracket: {
    instructionStart: '[[STRUQ_INSTRUCTION::TRUSTED]]',
    instructionEnd: '[[/STRUQ_INSTRUCTION]]',
    dataStart: '[[STRUQ_DATA::UNTRUSTED]]',
    dataEnd: '[[/STRUQ_DATA]]',
  },
  fence: {
    instructionStart: '```struq-instruction:trusted',
    instructionEnd: '```',
    dataStart: '```struq-data:untrusted',
    dataEnd: '```',
  },
  token: {
    instructionStart: '<|INSTRUCTION_START|>',
    instructionEnd: '<|INSTRUCTION_END|>',
    dataStart: '<|DATA_START|>',
    dataEnd: '<|DATA_END|>',
  },
})

/** Metadata keys */
const META_STYLE = 'struq_delimiter_style'
const META_SESSION = 'struq_session_hash'
const META_CHANNELS = 'struq_channel_count'
const META_DATA_HASH = 'struq_data_integrity'

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Structured Query Encoder.
 *
 * Separates system instructions (trusted channel) from user data
 * (untrusted channel) using reserved delimiter tokens. This makes
 * injection attacks structurally impossible to execute because the
 * LLM sees a clear channel boundary.
 */
export class StructuredQueryEncoder {
  private readonly _config: ShieldXConfig
  private readonly defaultStyle: DelimiterStyle

  /** Access the active configuration */
  get config(): ShieldXConfig { return this._config }

  constructor(config: ShieldXConfig, defaultStyle?: DelimiterStyle) {
    this._config = config
    this.defaultStyle = defaultStyle ?? 'xml'
  }

  /**
   * Encode system prompt and user input into separate channels.
   *
   * @param systemPrompt - Trusted system instructions
   * @param userInput - Untrusted user data
   * @param style - Delimiter style to use (default: constructor default)
   * @returns Encoded prompt with channel separation and metadata
   */
  encode(
    systemPrompt: string,
    userInput: string,
    style?: DelimiterStyle,
  ): StructuredQueryResult {
    const effectiveStyle = style ?? this.defaultStyle
    const delimiters = DELIMITER_TEMPLATES[effectiveStyle]
    const sessionHash = this.generateSessionHash()

    // Sanitize inputs to prevent delimiter injection
    const cleanSystem = this.escapeDelimiters(systemPrompt, effectiveStyle)
    const cleanUser = this.escapeDelimiters(userInput, effectiveStyle)

    // Compute data integrity hash
    const dataHash = this.computeDataHash(cleanUser, sessionHash)

    // Build channel-separated prompt
    const encodedPrompt = this.buildEncodedPrompt(
      cleanSystem,
      cleanUser,
      delimiters,
      sessionHash,
      dataHash,
    )

    const metadata: Record<string, string> = {
      [META_STYLE]: effectiveStyle,
      [META_SESSION]: sessionHash,
      [META_CHANNELS]: '2',
      [META_DATA_HASH]: dataHash,
    }

    return Object.freeze({
      encodedPrompt,
      metadata: Object.freeze(metadata),
    })
  }

  /**
   * Escape any occurrences of delimiter tokens within content
   * to prevent delimiter injection attacks.
   */
  private escapeDelimiters(content: string, style: DelimiterStyle): string {
    const delimiters = DELIMITER_TEMPLATES[style]
    let escaped = content

    const tokensToEscape = [
      delimiters.instructionStart,
      delimiters.instructionEnd,
      delimiters.dataStart,
      delimiters.dataEnd,
    ]

    for (const token of tokensToEscape) {
      const escapedToken = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const regex = new RegExp(escapedToken, 'g')
      escaped = escaped.replace(regex, `[ESCAPED:${token.slice(0, 8)}]`)
    }

    return escaped
  }

  /** Generate a session hash for channel binding */
  private generateSessionHash(): string {
    return randomBytes(8).toString('hex')
  }

  /** Compute HMAC integrity hash of user data */
  private computeDataHash(data: string, sessionHash: string): string {
    const hmac = createHmac('sha256', sessionHash)
    hmac.update(data)
    return hmac.digest('hex').slice(0, 16)
  }

  /** Build the final channel-separated prompt */
  private buildEncodedPrompt(
    systemPrompt: string,
    userInput: string,
    delimiters: typeof DELIMITER_TEMPLATES[DelimiterStyle],
    sessionHash: string,
    dataHash: string,
  ): string {
    const parts: string[] = [
      `[StruQ Session: ${sessionHash}]`,
      '',
      delimiters.instructionStart,
      systemPrompt,
      delimiters.instructionEnd,
      '',
      `[Data Integrity: ${dataHash}]`,
      delimiters.dataStart,
      userInput,
      delimiters.dataEnd,
      '',
      `[StruQ End: ${sessionHash}]`,
    ]

    return parts.join('\n')
  }
}
