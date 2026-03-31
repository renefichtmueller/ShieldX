/**
 * Resource Governor — prevents DoS and Denial-of-Wallet attacks.
 * Tracks token usage, cost, and rate limiting per session.
 * Detects ThinkTrap patterns where output tokens vastly exceed expectations.
 * Part of ShieldX Layer 7 (MCP Guard & Tool Security).
 */

/** Budget check result */
interface BudgetCheckResult {
  readonly allowed: boolean
  readonly remaining: number
  readonly reason?: string
}

/** Session usage statistics */
interface SessionUsage {
  readonly totalInputTokens: number
  readonly totalOutputTokens: number
  readonly totalCost: number
  readonly requestCount: number
}

/** Session limits configuration */
interface SessionLimits {
  readonly maxTokensPerRequest?: number
  readonly maxTokensPerSession?: number
  readonly maxRequestsPerMinute?: number
  readonly maxCostPerSession?: number
}

/** Internal mutable usage record */
interface UsageRecord {
  inputTokens: number
  outputTokens: number
  cost: number
  requestCount: number
  requestTimestamps: number[]
  limits: SessionLimits
}

/** Default per-token pricing (USD) */
const DEFAULT_INPUT_TOKEN_PRICE = 0.000003
const DEFAULT_OUTPUT_TOKEN_PRICE = 0.000015

/** Default limits when none are configured */
const DEFAULT_LIMITS: SessionLimits = {
  maxTokensPerRequest: 100_000,
  maxTokensPerSession: 2_000_000,
  maxRequestsPerMinute: 60,
  maxCostPerSession: 10.0,
}

/** ThinkTrap detection: output/input ratio threshold */
const THINK_TRAP_RATIO_THRESHOLD = 20

/** ThinkTrap detection: minimum output tokens to trigger */
const THINK_TRAP_MIN_OUTPUT = 5_000

/** Per-session usage store */
const sessionUsage = new Map<string, UsageRecord>()

/** Configurable pricing */
let inputTokenPrice = DEFAULT_INPUT_TOKEN_PRICE
let outputTokenPrice = DEFAULT_OUTPUT_TOKEN_PRICE

/**
 * Gets or creates a usage record for a session.
 */
function getOrCreateRecord(sessionId: string): UsageRecord {
  const existing = sessionUsage.get(sessionId)
  if (existing !== undefined) return existing

  const record: UsageRecord = {
    inputTokens: 0,
    outputTokens: 0,
    cost: 0,
    requestCount: 0,
    requestTimestamps: [],
    limits: { ...DEFAULT_LIMITS },
  }
  sessionUsage.set(sessionId, record)
  return record
}

/**
 * Counts requests within the last minute from the timestamp array.
 */
function countRecentRequests(timestamps: readonly number[]): number {
  const oneMinuteAgo = Date.now() - 60_000
  return timestamps.filter(t => t > oneMinuteAgo).length
}

/**
 * Prunes timestamps older than one minute.
 */
function pruneTimestamps(timestamps: number[]): number[] {
  const oneMinuteAgo = Date.now() - 60_000
  return timestamps.filter(t => t > oneMinuteAgo)
}

/**
 * Checks if a request is within the session's budget and rate limits.
 *
 * @param sessionId - Session identifier
 * @param estimatedTokens - Estimated total tokens for the request
 * @returns Whether the request is allowed, with remaining budget
 */
export function checkBudget(
  sessionId: string,
  estimatedTokens: number,
): BudgetCheckResult {
  const record = getOrCreateRecord(sessionId)
  const limits = record.limits

  // Check per-request token limit
  if (limits.maxTokensPerRequest !== undefined && estimatedTokens > limits.maxTokensPerRequest) {
    return {
      allowed: false,
      remaining: limits.maxTokensPerRequest - estimatedTokens,
      reason: `Request exceeds per-request token limit: ${estimatedTokens} > ${limits.maxTokensPerRequest}`,
    }
  }

  // Check session token limit
  if (limits.maxTokensPerSession !== undefined) {
    const totalUsed = record.inputTokens + record.outputTokens
    const remaining = limits.maxTokensPerSession - totalUsed
    if (totalUsed + estimatedTokens > limits.maxTokensPerSession) {
      return {
        allowed: false,
        remaining,
        reason: `Session token budget exhausted: ${totalUsed + estimatedTokens} > ${limits.maxTokensPerSession}`,
      }
    }
  }

  // Check rate limit
  if (limits.maxRequestsPerMinute !== undefined) {
    const recentCount = countRecentRequests(record.requestTimestamps)
    if (recentCount >= limits.maxRequestsPerMinute) {
      return {
        allowed: false,
        remaining: 0,
        reason: `Rate limit exceeded: ${recentCount} requests in the last minute (max: ${limits.maxRequestsPerMinute})`,
      }
    }
  }

  // Check cost limit
  if (limits.maxCostPerSession !== undefined) {
    const estimatedCost = estimatedTokens * outputTokenPrice
    if (record.cost + estimatedCost > limits.maxCostPerSession) {
      return {
        allowed: false,
        remaining: 0,
        reason: `Cost budget exceeded: $${(record.cost + estimatedCost).toFixed(4)} > $${limits.maxCostPerSession.toFixed(2)}`,
      }
    }
  }

  const sessionRemaining = limits.maxTokensPerSession !== undefined
    ? limits.maxTokensPerSession - (record.inputTokens + record.outputTokens)
    : Infinity

  return {
    allowed: true,
    remaining: sessionRemaining,
  }
}

/**
 * Records token usage for a completed request.
 * Also detects ThinkTrap patterns (output >> input for simple queries).
 *
 * @param sessionId - Session identifier
 * @param inputTokens - Tokens consumed by the input
 * @param outputTokens - Tokens produced in the output
 * @param _latencyMs - Request latency in milliseconds (reserved for future use)
 * @returns Array of warnings (e.g., ThinkTrap detection)
 */
export function recordUsage(
  sessionId: string,
  inputTokens: number,
  outputTokens: number,
  _latencyMs: number,
): readonly string[] {
  const record = getOrCreateRecord(sessionId)
  const warnings: string[] = []

  // Update usage counters (create new record for immutable external view)
  record.inputTokens += inputTokens
  record.outputTokens += outputTokens
  record.cost += (inputTokens * inputTokenPrice) + (outputTokens * outputTokenPrice)
  record.requestCount += 1
  record.requestTimestamps = [...pruneTimestamps(record.requestTimestamps), Date.now()]

  // Detect ThinkTrap: output tokens vastly exceed input tokens
  if (
    inputTokens > 0 &&
    outputTokens > THINK_TRAP_MIN_OUTPUT &&
    (outputTokens / inputTokens) > THINK_TRAP_RATIO_THRESHOLD
  ) {
    warnings.push(
      `think_trap_detected:output/input ratio=${(outputTokens / inputTokens).toFixed(1)} ` +
      `(${outputTokens} output / ${inputTokens} input)`,
    )
  }

  // Warn if approaching session limits
  const limits = record.limits
  if (limits.maxTokensPerSession !== undefined) {
    const totalUsed = record.inputTokens + record.outputTokens
    const usageRatio = totalUsed / limits.maxTokensPerSession
    if (usageRatio > 0.9) {
      warnings.push(
        `session_budget_warning:${(usageRatio * 100).toFixed(0)}% of token budget consumed`,
      )
    }
  }

  if (limits.maxCostPerSession !== undefined) {
    const costRatio = record.cost / limits.maxCostPerSession
    if (costRatio > 0.9) {
      warnings.push(
        `cost_budget_warning:${(costRatio * 100).toFixed(0)}% of cost budget consumed ($${record.cost.toFixed(4)})`,
      )
    }
  }

  return warnings
}

/**
 * Returns the current usage statistics for a session.
 *
 * @param sessionId - Session identifier
 * @returns Session usage statistics
 */
export function getUsage(sessionId: string): SessionUsage {
  const record = sessionUsage.get(sessionId)
  if (record === undefined) {
    return {
      totalInputTokens: 0,
      totalOutputTokens: 0,
      totalCost: 0,
      requestCount: 0,
    }
  }

  return {
    totalInputTokens: record.inputTokens,
    totalOutputTokens: record.outputTokens,
    totalCost: record.cost,
    requestCount: record.requestCount,
  }
}

/**
 * Sets resource limits for a session.
 *
 * @param sessionId - Session identifier
 * @param limits - Limits to configure
 */
export function setLimits(sessionId: string, limits: SessionLimits): void {
  const record = getOrCreateRecord(sessionId)
  record.limits = { ...record.limits, ...limits }
}

/**
 * Configures per-token pricing for cost estimation.
 *
 * @param input - Price per input token in USD
 * @param output - Price per output token in USD
 */
export function setPricing(input: number, output: number): void {
  inputTokenPrice = input
  outputTokenPrice = output
}

/**
 * Clears usage data for a session (cleanup).
 *
 * @param sessionId - Session to clear
 */
export function clearSession(sessionId: string): void {
  sessionUsage.delete(sessionId)
}
