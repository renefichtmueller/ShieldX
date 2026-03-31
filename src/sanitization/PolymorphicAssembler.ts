/**
 * PolymorphicAssembler — Polymorphic Prompt Assembly (PPA).
 *
 * Randomizes HOW system prompt and user input are structured to prevent
 * attackers from predicting prompt layout. Uses HMAC-SHA256 for deterministic
 * but unpredictable separators, session-unique XML-like tags for data isolation,
 * and canary token weaving throughout the assembled prompt.
 *
 * Deterministic within a session (same sessionId = same structure),
 * but changes every new session.
 */

import { createHmac, randomBytes } from 'node:crypto'
import type { ShieldXConfig } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Result of polymorphic prompt assembly */
export interface AssemblyResult {
  readonly assembled: string
  readonly sessionTag: string
  readonly separatorHash: string
  readonly canaryTokens: readonly string[]
  readonly randomizationLevel: 'low' | 'medium' | 'high'
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Secret used for HMAC if none provided — should be overridden per deployment */
const DEFAULT_HMAC_SECRET = 'shieldx-ppa-default-secret-change-me'

/** Number of noise separators to insert at each randomization level */
const NOISE_COUNTS: Readonly<Record<'low' | 'medium' | 'high', number>> = Object.freeze({
  low: 1,
  medium: 3,
  high: 6,
})

/** Instruction placement strategies */
const PLACEMENT_STRATEGIES = [
  'before_input',
  'after_input',
  'split_around',
  'interleaved',
] as const

type PlacementStrategy = typeof PLACEMENT_STRATEGIES[number]

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Polymorphic Prompt Assembler.
 *
 * Assembles system prompts and user input with session-unique separators,
 * randomized instruction placement, dynamic XML tags, and canary tokens.
 */
export class PolymorphicAssembler {
  private readonly config: ShieldXConfig
  private readonly secret: string

  constructor(config: ShieldXConfig, secret?: string) {
    this.config = config
    this.secret = secret ?? DEFAULT_HMAC_SECRET
  }

  /**
   * Assemble a prompt with polymorphic structure.
   *
   * @param userInput - The user's input text
   * @param systemPrompt - Optional system prompt to include
   * @param sessionId - Session identifier for deterministic randomization
   * @returns Assembled prompt with metadata
   */
  assemble(
    userInput: string,
    systemPrompt?: string,
    sessionId?: string,
  ): AssemblyResult {
    const effectiveSessionId = sessionId ?? randomBytes(16).toString('hex')
    const level = this.config.ppa.randomizationLevel

    // Generate session-deterministic separator
    const separatorHash = this.generateSeparatorHash(effectiveSessionId)
    const separator = this.buildSeparator(separatorHash)

    // Generate session-unique XML tag
    const sessionTag = this.generateSessionTag(effectiveSessionId)

    // Generate canary tokens
    const canaryTokens = this.generateCanaryTokens(effectiveSessionId)

    // Select placement strategy deterministically
    const strategy = this.selectPlacement(effectiveSessionId)

    // Build noise separators
    const noiseSeparators = this.generateNoiseSeparators(
      effectiveSessionId,
      NOISE_COUNTS[level] ?? 3,
    )

    // Assemble the prompt
    const assembled = this.buildPrompt({
      userInput,
      systemPrompt: systemPrompt ?? '',
      separator,
      sessionTag,
      canaryTokens,
      strategy,
      noiseSeparators,
      level,
    })

    return Object.freeze({
      assembled,
      sessionTag,
      separatorHash,
      canaryTokens: Object.freeze([...canaryTokens]),
      randomizationLevel: level,
    })
  }

  /**
   * Generate HMAC-SHA256 separator hash from session context.
   * Deterministic for the same session, unpredictable across sessions.
   */
  private generateSeparatorHash(sessionId: string): string {
    const timestamp = Math.floor(Date.now() / 3600000).toString()
    const hmac = createHmac('sha256', this.secret)
    hmac.update(`${sessionId}:${timestamp}:separator`)
    return hmac.digest('hex').slice(0, 16)
  }

  /** Build a visual separator from the hash */
  private buildSeparator(hash: string): string {
    return `====[ ${hash} ]====`
  }

  /** Generate a session-unique XML-like tag identifier */
  private generateSessionTag(sessionId: string): string {
    const hmac = createHmac('sha256', this.secret)
    hmac.update(`${sessionId}:tag`)
    return `user_input_${hmac.digest('hex').slice(0, 6)}`
  }

  /** Generate canary tokens for this session */
  private generateCanaryTokens(sessionId: string): readonly string[] {
    const count = this.config.canary.tokenCount
    const tokens: string[] = []

    for (let i = 0; i < count; i++) {
      const hmac = createHmac('sha256', this.secret)
      hmac.update(`${sessionId}:canary:${i}`)
      tokens.push(`[CANARY:${hmac.digest('hex').slice(0, 12)}]`)
    }

    return tokens
  }

  /** Select placement strategy deterministically based on session */
  private selectPlacement(sessionId: string): PlacementStrategy {
    const hmac = createHmac('sha256', this.secret)
    hmac.update(`${sessionId}:placement`)
    const hash = hmac.digest('hex')
    const index = parseInt(hash.slice(0, 2), 16) % PLACEMENT_STRATEGIES.length
    return PLACEMENT_STRATEGIES[index] as PlacementStrategy
  }

  /** Generate noise separator strings */
  private generateNoiseSeparators(
    sessionId: string,
    count: number,
  ): readonly string[] {
    const separators: string[] = []

    for (let i = 0; i < count; i++) {
      const hmac = createHmac('sha256', this.secret)
      hmac.update(`${sessionId}:noise:${i}`)
      const hash = hmac.digest('hex').slice(0, 8)
      separators.push(`---[${hash}]---`)
    }

    return separators
  }

  /** Build the final prompt based on strategy and configuration */
  private buildPrompt(params: {
    readonly userInput: string
    readonly systemPrompt: string
    readonly separator: string
    readonly sessionTag: string
    readonly canaryTokens: readonly string[]
    readonly strategy: PlacementStrategy
    readonly noiseSeparators: readonly string[]
    readonly level: 'low' | 'medium' | 'high'
  }): string {
    const {
      userInput,
      systemPrompt,
      separator,
      sessionTag,
      canaryTokens,
      strategy,
      noiseSeparators,
      level,
    } = params

    const wrappedInput = `<${sessionTag}>\n${userInput}\n</${sessionTag}>`
    const parts: string[] = []

    // Weave first canary at the top
    const firstCanary = canaryTokens[0]
    if (canaryTokens.length > 0 && firstCanary !== undefined) {
      parts.push(firstCanary)
    }

    switch (strategy) {
      case 'before_input': {
        if (systemPrompt) parts.push(systemPrompt)
        parts.push(separator)
        this.insertNoise(parts, noiseSeparators, 0)
        parts.push(wrappedInput)
        break
      }
      case 'after_input': {
        parts.push(wrappedInput)
        parts.push(separator)
        this.insertNoise(parts, noiseSeparators, 0)
        if (systemPrompt) parts.push(systemPrompt)
        break
      }
      case 'split_around': {
        if (systemPrompt) {
          const mid = Math.floor(systemPrompt.length / 2)
          const splitPoint = systemPrompt.indexOf('\n', mid)
          const effectiveSplit = splitPoint > 0 ? splitPoint : mid

          parts.push(systemPrompt.slice(0, effectiveSplit))
          parts.push(separator)
          this.insertNoise(parts, noiseSeparators, 0)
          parts.push(wrappedInput)
          parts.push(separator)
          parts.push(systemPrompt.slice(effectiveSplit))
        } else {
          parts.push(separator)
          parts.push(wrappedInput)
        }
        break
      }
      case 'interleaved': {
        if (systemPrompt) {
          const lines = systemPrompt.split('\n')
          const chunkSize = Math.max(1, Math.floor(lines.length / 3))

          parts.push(lines.slice(0, chunkSize).join('\n'))
          this.insertNoise(parts, noiseSeparators, 0)
          parts.push(separator)
          parts.push(wrappedInput)
          parts.push(separator)
          this.insertNoise(parts, noiseSeparators, 1)
          parts.push(lines.slice(chunkSize).join('\n'))
        } else {
          parts.push(separator)
          parts.push(wrappedInput)
        }
        break
      }
    }

    // Weave remaining canary tokens
    for (let i = 1; i < canaryTokens.length; i++) {
      const token = canaryTokens[i]
      if (token === undefined) continue
      const insertPos = Math.min(
        Math.floor((parts.length / canaryTokens.length) * i),
        parts.length,
      )
      parts.splice(insertPos, 0, token)
    }

    // High randomization: add extra noise at random positions
    if (level === 'high') {
      for (const noise of noiseSeparators.slice(2)) {
        const pos = Math.floor(parts.length / 2)
        parts.splice(pos, 0, noise)
      }
    }

    return parts.join('\n')
  }

  /** Insert noise separators into the parts array */
  private insertNoise(
    parts: string[],
    noiseSeparators: readonly string[],
    startIndex: number,
  ): void {
    const endIndex = Math.min(startIndex + 2, noiseSeparators.length)
    for (let i = startIndex; i < endIndex; i++) {
      const sep = noiseSeparators[i]
      if (sep !== undefined) parts.push(sep)
    }
  }
}
