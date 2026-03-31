/**
 * Federated threat intelligence with differential privacy.
 * Pushes and pulls anonymized pattern hashes to/from a community
 * intelligence hub. NEVER sends raw text — only SHA-256 hashes.
 */

import { createHash, randomBytes } from 'node:crypto'

import type { PatternRecord } from '../types/learning.js'

/** Federated sync configuration */
interface FederatedSyncConfig {
  readonly syncUrl: string
  readonly syncIntervalMs: number
  readonly enabled: boolean
  readonly noiseEpsilon: number
}

/** Anonymized pattern payload for federation */
interface AnonymizedPattern {
  readonly patternHash: string
  readonly patternType: PatternRecord['patternType']
  readonly killChainPhase: PatternRecord['killChainPhase']
  readonly confidenceBase: number
  readonly hitCount: number
  readonly noisyFPRate: number
}

/** Default configuration — disabled by default */
const DEFAULT_CONFIG: FederatedSyncConfig = {
  syncUrl: '',
  syncIntervalMs: 3_600_000, // 1 hour
  enabled: false,
  noiseEpsilon: 1.0, // Differential privacy epsilon
} as const

/**
 * FederatedSync — federated threat intelligence sharing.
 *
 * Shares and receives detection patterns with a community hub
 * while preserving privacy through:
 * - SHA-256 hashing (never raw pattern text)
 * - Laplace noise on statistics (differential privacy)
 * - Community patterns get a -0.1 confidence offset
 *
 * DISABLED by default. Must be explicitly enabled.
 */
export class FederatedSync {
  private readonly config: FederatedSyncConfig
  private lastSync: number = 0

  constructor(config?: Partial<FederatedSyncConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Push local patterns to the community hub.
   * Anonymizes all patterns before transmission.
   * @param patterns - Local patterns to share
   */
  async pushPatterns(patterns: readonly PatternRecord[]): Promise<void> {
    if (!this.config.enabled || this.config.syncUrl === '') return

    const anonymized = patterns.map((p) => anonymizePattern(p, this.config.noiseEpsilon))

    const response = await fetch(`${this.config.syncUrl}/api/v1/patterns/push`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ patterns: anonymized }),
    })

    if (!response.ok) {
      throw new Error(`Federated push failed: ${response.status} ${response.statusText}`)
    }

    this.lastSync = Date.now()
  }

  /**
   * Pull community patterns from the hub.
   * Pulled patterns are marked as source='community' with -0.1 confidence offset.
   * @returns Array of community patterns
   */
  async pullPatterns(): Promise<readonly PatternRecord[]> {
    if (!this.config.enabled || this.config.syncUrl === '') return Object.freeze([])

    const response = await fetch(`${this.config.syncUrl}/api/v1/patterns/pull`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })

    if (!response.ok) {
      throw new Error(`Federated pull failed: ${response.status} ${response.statusText}`)
    }

    const data = await response.json() as { patterns: readonly AnonymizedPattern[] }

    const communityPatterns = data.patterns.map((ap) => toCommunityPattern(ap))
    this.lastSync = Date.now()

    return Object.freeze(communityPatterns)
  }

  /**
   * Check if sync is due based on configured interval.
   */
  isSyncDue(): boolean {
    if (!this.config.enabled) return false
    return Date.now() - this.lastSync >= this.config.syncIntervalMs
  }

  /**
   * Get whether sync is enabled.
   */
  isEnabled(): boolean {
    return this.config.enabled
  }

  /**
   * Get last sync timestamp.
   */
  getLastSyncTime(): number {
    return this.lastSync
  }
}

/**
 * Anonymize a pattern for federated sharing.
 * Hashes the pattern text and adds Laplace noise to statistics.
 */
function anonymizePattern(pattern: PatternRecord, epsilon: number): AnonymizedPattern {
  const patternHash = createHash('sha256')
    .update(pattern.patternText)
    .digest('hex')

  const totalChecks = pattern.hitCount + pattern.falsePositiveCount
  const rawFPRate = totalChecks > 0 ? pattern.falsePositiveCount / totalChecks : 0
  const noisyFPRate = Math.max(0, Math.min(1, rawFPRate + laplaceNoise(epsilon)))

  return Object.freeze({
    patternHash,
    patternType: pattern.patternType,
    killChainPhase: pattern.killChainPhase,
    confidenceBase: pattern.confidenceBase,
    hitCount: pattern.hitCount,
    noisyFPRate: Math.round(noisyFPRate * 1000) / 1000,
  })
}

/**
 * Convert an anonymized community pattern back to a PatternRecord.
 * Applies -0.1 confidence offset for community-sourced patterns.
 */
function toCommunityPattern(ap: AnonymizedPattern): PatternRecord {
  return Object.freeze({
    id: ap.patternHash.slice(0, 36), // Use hash prefix as ID
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    patternText: ap.patternHash, // Only the hash — never raw text
    patternType: ap.patternType,
    killChainPhase: ap.killChainPhase,
    confidenceBase: Math.max(0.1, ap.confidenceBase - 0.1), // -0.1 offset
    hitCount: ap.hitCount,
    falsePositiveCount: 0,
    source: 'community' as const,
    enabled: true,
    metadata: Object.freeze({ noisyFPRate: ap.noisyFPRate }),
  })
}

/**
 * Generate Laplace noise for differential privacy.
 * @param epsilon - Privacy budget (larger = less noise)
 */
function laplaceNoise(epsilon: number): number {
  // Laplace distribution: noise = -b * sign(u) * ln(1 - 2|u|)
  // where b = sensitivity/epsilon and u ~ Uniform(-0.5, 0.5)
  const b = 1.0 / epsilon
  const bytes = randomBytes(4)
  const u = (bytes.readUInt32BE(0) / 0xffffffff) - 0.5

  if (u === 0) return 0

  const sign = u < 0 ? -1 : 1
  return -b * sign * Math.log(1 - 2 * Math.abs(u))
}
