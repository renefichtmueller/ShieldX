/**
 * RateLimiter — Token bucket rate limiting per session.
 *
 * Prevents brute-force probing of the ShieldX pipeline by limiting
 * the number of scans per session within a configurable time window.
 *
 * After repeated blocks, the suspicion baseline for the session is
 * elevated ("fever response" lite).
 */

export interface RateLimiterConfig {
  /** Max requests per window (default: 60) */
  readonly maxRequests: number
  /** Window duration in milliseconds (default: 60_000 = 1 min) */
  readonly windowMs: number
  /** Burst allowance above maxRequests (default: 10) */
  readonly burstAllowance: number
  /** Number of blocks before escalation (default: 5) */
  readonly escalationThreshold: number
}

export interface RateLimitResult {
  readonly allowed: boolean
  readonly remaining: number
  readonly resetMs: number
  readonly escalated: boolean
  readonly blockedCount: number
}

interface SessionBucket {
  readonly tokens: number
  readonly lastRefill: number
  readonly blockedCount: number
}

const DEFAULT_CONFIG: RateLimiterConfig = {
  maxRequests: 60,
  windowMs: 60_000,
  burstAllowance: 10,
  escalationThreshold: 5,
}

export class RateLimiter {
  private readonly config: RateLimiterConfig
  private readonly buckets: Map<string, SessionBucket> = new Map()

  constructor(config: Partial<RateLimiterConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Check if a request from the given session is allowed.
   * Returns immutable result with rate limit status.
   */
  check(sessionId: string): RateLimitResult {
    const now = Date.now()
    const bucket = this.getOrCreateBucket(sessionId, now)
    const refilled = this.refillBucket(bucket, now)

    if (refilled.tokens > 0) {
      const updated: SessionBucket = {
        tokens: refilled.tokens - 1,
        lastRefill: refilled.lastRefill,
        blockedCount: refilled.blockedCount,
      }
      this.buckets.set(sessionId, updated)

      return Object.freeze({
        allowed: true,
        remaining: updated.tokens,
        resetMs: this.config.windowMs - (now - updated.lastRefill),
        escalated: updated.blockedCount >= this.config.escalationThreshold,
        blockedCount: updated.blockedCount,
      })
    }

    const blocked: SessionBucket = {
      tokens: 0,
      lastRefill: refilled.lastRefill,
      blockedCount: refilled.blockedCount + 1,
    }
    this.buckets.set(sessionId, blocked)

    return Object.freeze({
      allowed: false,
      remaining: 0,
      resetMs: this.config.windowMs - (now - blocked.lastRefill),
      escalated: blocked.blockedCount >= this.config.escalationThreshold,
      blockedCount: blocked.blockedCount,
    })
  }

  /**
   * Reset rate limit state for a session.
   */
  reset(sessionId: string): void {
    this.buckets.delete(sessionId)
  }

  /**
   * Clean up expired sessions (call periodically).
   */
  cleanup(): number {
    const now = Date.now()
    let cleaned = 0
    for (const [id, bucket] of this.buckets) {
      if (now - bucket.lastRefill > this.config.windowMs * 10) {
        this.buckets.delete(id)
        cleaned++
      }
    }
    return cleaned
  }

  private getOrCreateBucket(sessionId: string, now: number): SessionBucket {
    const existing = this.buckets.get(sessionId)
    if (existing) return existing
    const fresh: SessionBucket = {
      tokens: this.config.maxRequests + this.config.burstAllowance,
      lastRefill: now,
      blockedCount: 0,
    }
    this.buckets.set(sessionId, fresh)
    return fresh
  }

  private refillBucket(bucket: SessionBucket, now: number): SessionBucket {
    const elapsed = now - bucket.lastRefill
    if (elapsed < this.config.windowMs) return bucket

    // Full refill after window expires
    return {
      tokens: this.config.maxRequests + this.config.burstAllowance,
      lastRefill: now,
      blockedCount: bucket.blockedCount,
    }
  }
}
