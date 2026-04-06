/**
 * FeverResponse — Elevated Alertness Mode After High-Severity Detection.
 *
 * When ShieldX detects a high-severity attack, FeverResponse activates
 * an elevated defense state for the attacker's session:
 *
 * - Lower all detection thresholds by a configurable percentage
 * - Apply suspicion boost to all subsequent inputs from the session
 * - Enable enhanced logging for the session
 * - Track additional detections made during the fever window
 *
 * Fever is time-bounded (default: 30 minutes) and auto-expires.
 * Multiple sessions can be in fever simultaneously (capped).
 * Fever does not stack — re-triggering extends the expiry.
 *
 * Biological analogy: systemic inflammation response that heightens
 * sensitivity after an initial pathogen detection.
 */

import type { ShieldXResult, ThreatLevel } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

/** Configuration for the FeverResponse module */
export interface FeverConfig {
  readonly enabled: boolean
  readonly durationMs: number              // default: 1_800_000 (30 min)
  readonly thresholdReduction: number      // default: 0.20 (20%)
  readonly triggerMinThreatLevel: ThreatLevel  // default: 'high'
  readonly autoRedTeam: boolean            // default: true
  readonly maxConcurrentFevers: number     // default: 5
}

/** State of an active fever for a session */
export interface FeverState {
  readonly sessionId: string
  readonly triggeredAt: string
  readonly expiresAt: string
  readonly triggerInput: string
  readonly triggerPhase: string
  readonly thresholdOverrides: Readonly<Record<string, number>>
  readonly redTeamVariantsGenerated: number
  readonly additionalDetections: number
}

/** Result of checking fever status for a session */
export interface FeverCheck {
  readonly inFever: boolean
  readonly suspicionBoost: number          // extra suspicion to add
  readonly thresholdReduction: number      // how much to lower thresholds
  readonly enhancedLogging: boolean
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Threat level numeric ordering for comparison */
const THREAT_SEVERITY: Readonly<Record<ThreatLevel, number>> = Object.freeze({
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
})

/** Default configuration */
const DEFAULT_CONFIG: FeverConfig = Object.freeze({
  enabled: true,
  durationMs: 1_800_000,         // 30 minutes
  thresholdReduction: 0.20,      // 20%
  triggerMinThreatLevel: 'high' as ThreatLevel,
  autoRedTeam: true,
  maxConcurrentFevers: 5,
})

/** Suspicion boost applied during fever */
const FEVER_SUSPICION_BOOST = 0.3

// ---------------------------------------------------------------------------
// Internal mutable state type (Map values)
// ---------------------------------------------------------------------------

interface MutableFeverEntry {
  sessionId: string
  triggeredAt: string
  expiresAt: string
  triggerInput: string
  triggerPhase: string
  thresholdOverrides: Record<string, number>
  redTeamVariantsGenerated: number
  additionalDetections: number
}

// ---------------------------------------------------------------------------
// FeverResponse
// ---------------------------------------------------------------------------

/**
 * FeverResponse — time-bounded elevated alertness after high-severity detection.
 *
 * Sessions in fever receive lowered thresholds and suspicion boosts
 * until the fever window expires.
 */
export class FeverResponse {
  private readonly config: FeverConfig
  private readonly fevers: Map<string, MutableFeverEntry> = new Map()

  constructor(config: Partial<FeverConfig> = {}) {
    this.config = Object.freeze({ ...DEFAULT_CONFIG, ...config })
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Trigger fever for a session after high-severity detection.
   *
   * If the session is already in fever, extends the expiry rather than
   * stacking. If max concurrent fevers is reached and the session is
   * new, the oldest fever is evicted.
   *
   * @param sessionId - Session identifier
   * @param triggerResult - The ShieldXResult that caused the trigger
   * @returns The created or extended FeverState
   */
  trigger(sessionId: string, triggerResult: ShieldXResult): FeverState {
    if (!this.config.enabled) {
      return this.buildInactiveFeverState(sessionId, triggerResult)
    }

    // Check if threat level meets minimum trigger threshold
    const triggerSeverity = THREAT_SEVERITY[triggerResult.threatLevel] ?? 0
    const minSeverity = THREAT_SEVERITY[this.config.triggerMinThreatLevel] ?? 3
    if (triggerSeverity < minSeverity) {
      return this.buildInactiveFeverState(sessionId, triggerResult)
    }

    // Clean expired fevers before checking capacity
    this.cleanup()

    const now = new Date()
    const expiresAt = new Date(now.getTime() + this.config.durationMs)

    // Check for existing fever — extend rather than stack
    const existing = this.fevers.get(sessionId)
    if (existing !== undefined) {
      const extended: MutableFeverEntry = {
        ...existing,
        expiresAt: expiresAt.toISOString(),
      }
      this.fevers.set(sessionId, extended)
      return this.toFrozenState(extended)
    }

    // Evict oldest fever if at capacity
    if (this.fevers.size >= this.config.maxConcurrentFevers) {
      this.evictOldest()
    }

    // Build threshold overrides — reduce all standard thresholds
    const thresholdOverrides: Record<string, number> = {
      low: this.config.thresholdReduction,
      medium: this.config.thresholdReduction,
      high: this.config.thresholdReduction,
      critical: this.config.thresholdReduction,
    }

    const entry: MutableFeverEntry = {
      sessionId,
      triggeredAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      triggerInput: triggerResult.input.slice(0, 200),
      triggerPhase: triggerResult.killChainPhase,
      thresholdOverrides,
      redTeamVariantsGenerated: 0,
      additionalDetections: 0,
    }

    this.fevers.set(sessionId, entry)
    return this.toFrozenState(entry)
  }

  /**
   * Check if a session is in fever mode.
   *
   * If the fever has expired, it is auto-cleaned and a non-fever
   * result is returned.
   *
   * @param sessionId - Session identifier
   * @returns FeverCheck with boost values and logging flag
   */
  check(sessionId: string): FeverCheck {
    if (!this.config.enabled) {
      return this.buildInactiveCheck()
    }

    const entry = this.fevers.get(sessionId)
    if (entry === undefined) {
      return this.buildInactiveCheck()
    }

    // Check expiry
    const now = Date.now()
    const expiresAt = new Date(entry.expiresAt).getTime()
    if (now >= expiresAt) {
      this.fevers.delete(sessionId)
      return this.buildInactiveCheck()
    }

    return Object.freeze({
      inFever: true,
      suspicionBoost: FEVER_SUSPICION_BOOST,
      thresholdReduction: this.config.thresholdReduction,
      enhancedLogging: true,
    })
  }

  /**
   * Get all currently active (non-expired) fever states.
   *
   * Performs cleanup before returning to ensure no stale entries.
   *
   * @returns Frozen array of active FeverState objects
   */
  getActiveFevers(): readonly FeverState[] {
    this.cleanup()

    const active: FeverState[] = []
    for (const entry of this.fevers.values()) {
      active.push(this.toFrozenState(entry))
    }
    return Object.freeze(active)
  }

  /**
   * Manually end fever for a session.
   *
   * @param sessionId - Session identifier to resolve
   */
  resolve(sessionId: string): void {
    this.fevers.delete(sessionId)
  }

  /**
   * Clean up expired fevers.
   *
   * @returns Number of expired fevers removed
   */
  cleanup(): number {
    const now = Date.now()
    const toRemove: string[] = []

    for (const [sessionId, entry] of this.fevers) {
      const expiresAt = new Date(entry.expiresAt).getTime()
      if (now >= expiresAt) {
        toRemove.push(sessionId)
      }
    }

    for (const sessionId of toRemove) {
      this.fevers.delete(sessionId)
    }

    return toRemove.length
  }

  /**
   * Record an additional detection during fever.
   * Called by ShieldX when a detection occurs on a session in fever.
   *
   * @param sessionId - Session identifier
   */
  recordAdditionalDetection(sessionId: string): void {
    const entry = this.fevers.get(sessionId)
    if (entry === undefined) return

    const updated: MutableFeverEntry = {
      ...entry,
      additionalDetections: entry.additionalDetections + 1,
    }
    this.fevers.set(sessionId, updated)
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /** Convert a mutable entry to a frozen FeverState */
  private toFrozenState(entry: MutableFeverEntry): FeverState {
    return Object.freeze({
      sessionId: entry.sessionId,
      triggeredAt: entry.triggeredAt,
      expiresAt: entry.expiresAt,
      triggerInput: entry.triggerInput,
      triggerPhase: entry.triggerPhase,
      thresholdOverrides: Object.freeze({ ...entry.thresholdOverrides }),
      redTeamVariantsGenerated: entry.redTeamVariantsGenerated,
      additionalDetections: entry.additionalDetections,
    })
  }

  /** Build an inactive fever state for disabled/below-threshold cases */
  private buildInactiveFeverState(sessionId: string, result: ShieldXResult): FeverState {
    return Object.freeze({
      sessionId,
      triggeredAt: new Date().toISOString(),
      expiresAt: new Date().toISOString(),
      triggerInput: result.input.slice(0, 200),
      triggerPhase: result.killChainPhase,
      thresholdOverrides: Object.freeze({}),
      redTeamVariantsGenerated: 0,
      additionalDetections: 0,
    })
  }

  /** Build an inactive fever check result */
  private buildInactiveCheck(): FeverCheck {
    return Object.freeze({
      inFever: false,
      suspicionBoost: 0,
      thresholdReduction: 0,
      enhancedLogging: false,
    })
  }

  /** Evict the oldest fever to make room for a new one */
  private evictOldest(): void {
    let oldestSession: string | null = null
    let oldestTime = Infinity

    for (const [sessionId, entry] of this.fevers) {
      const triggeredAt = new Date(entry.triggeredAt).getTime()
      if (triggeredAt < oldestTime) {
        oldestTime = triggeredAt
        oldestSession = sessionId
      }
    }

    if (oldestSession !== null) {
      this.fevers.delete(oldestSession)
    }
  }
}
