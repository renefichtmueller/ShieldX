/**
 * Canary token generation and verification.
 * Generates cryptographically random tokens injected into prompts
 * to detect system prompt leakage in LLM outputs.
 */

import { randomBytes } from 'node:crypto'

/** Result of checking output for canary token leakage */
interface CanaryCheckResult {
  readonly leaked: boolean
  readonly leakedTokens: readonly string[]
}

/**
 * CanaryManager — generates, stores, and checks canary tokens.
 * Tokens are session-scoped and rotated at a configurable interval.
 */
export class CanaryManager {
  private readonly tokens: string[] = []
  private readonly tokenLength: number
  private readonly prefix: string
  private lastRotation: number

  /**
   * @param tokenCount - Number of tokens to generate initially
   * @param rotationIntervalMs - Rotation interval in milliseconds
   * @param tokenLength - Byte length for random tokens (hex-encoded = 2x chars)
   * @param prefix - Prefix for all tokens to speed up detection
   */
  constructor(
    tokenCount: number = 3,
    private readonly rotationIntervalMs: number = 3_600_000,
    tokenLength: number = 16,
    prefix: string = 'SX_CANARY_',
  ) {
    this.tokenLength = tokenLength
    this.prefix = prefix
    this.lastRotation = Date.now()

    const generated = generateTokensBatch(tokenCount, tokenLength, prefix)
    this.tokens.push(...generated)
  }

  /**
   * Generate a single cryptographically random canary token.
   * @returns A new canary token string
   */
  generateToken(): string {
    const token = createRandomToken(this.tokenLength, this.prefix)
    this.tokens.push(token)
    return token
  }

  /**
   * Generate multiple canary tokens at once.
   * @param count - Number of tokens to generate
   * @returns Array of new canary tokens
   */
  generateTokens(count: number): readonly string[] {
    const newTokens = generateTokensBatch(count, this.tokenLength, this.prefix)
    this.tokens.push(...newTokens)
    return newTokens
  }

  /**
   * Check an LLM output for the presence of any active canary tokens.
   * @param output - LLM output text to inspect
   * @param tokens - Optional specific token list; defaults to all active tokens
   * @returns Check result indicating if any tokens leaked
   */
  checkOutput(output: string, tokens?: readonly string[]): CanaryCheckResult {
    const checkSet = tokens ?? this.tokens
    const leakedTokens = checkSet.filter((token) => output.includes(token))

    return Object.freeze({
      leaked: leakedTokens.length > 0,
      leakedTokens: Object.freeze(leakedTokens),
    })
  }

  /**
   * Rotate all active tokens. Old tokens are discarded.
   * @returns The new set of tokens
   */
  rotateTokens(): readonly string[] {
    const count = this.tokens.length || 3
    this.tokens.length = 0
    const newTokens = generateTokensBatch(count, this.tokenLength, this.prefix)
    this.tokens.push(...newTokens)
    this.lastRotation = Date.now()
    return Object.freeze([...this.tokens])
  }

  /**
   * Check if rotation is due based on configured interval.
   * @returns True if tokens should be rotated
   */
  isRotationDue(): boolean {
    return Date.now() - this.lastRotation >= this.rotationIntervalMs
  }

  /**
   * Get all currently active canary tokens (read-only copy).
   */
  getActiveTokens(): readonly string[] {
    return Object.freeze([...this.tokens])
  }
}

/** Create a single random canary token */
function createRandomToken(byteLength: number, prefix: string): string {
  return `${prefix}${randomBytes(byteLength).toString('hex')}`
}

/** Generate a batch of random canary tokens */
function generateTokensBatch(
  count: number,
  byteLength: number,
  prefix: string,
): string[] {
  return Array.from({ length: count }, () => createRandomToken(byteLength, prefix))
}
