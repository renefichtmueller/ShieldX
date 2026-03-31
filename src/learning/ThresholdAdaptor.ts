/**
 * Dynamic threshold adaptation.
 * Adjusts detection thresholds based on pattern performance
 * statistics (hit rates, false positive rates).
 */

import type { LearningStats } from '../types/learning.js'

/** Minimum and maximum bounds for thresholds */
const THRESHOLD_MIN = 0.1
const THRESHOLD_MAX = 0.99

/** Default threshold configuration */
const DEFAULT_THRESHOLDS: Readonly<Record<string, number>> = {
  low: 0.3,
  medium: 0.5,
  high: 0.7,
  critical: 0.9,
} as const

/**
 * ThresholdAdaptor — dynamically adjusts detection thresholds.
 *
 * Analyzes pattern performance statistics and adjusts thresholds:
 * - Lower thresholds for patterns with high hit rate and low FP rate
 * - Raise thresholds for patterns with high FP rate
 * - Never goes below THRESHOLD_MIN (0.1) or above THRESHOLD_MAX (0.99)
 */
export class ThresholdAdaptor {
  private readonly currentThresholds: Map<string, number>

  constructor() {
    this.currentThresholds = new Map(Object.entries(DEFAULT_THRESHOLDS))
  }

  /**
   * Adapt thresholds based on current learning statistics.
   * @param stats - Current learning layer statistics
   * @returns Updated threshold map
   */
  adapt(stats: LearningStats): Readonly<Record<string, number>> {
    const result: Record<string, number> = {}

    for (const [level, baseThreshold] of this.currentThresholds) {
      let adjusted = baseThreshold

      // High false positive rate → raise thresholds (more conservative)
      if (stats.falsePositiveRate > 0.1) {
        const fpPenalty = Math.min(stats.falsePositiveRate * 0.2, 0.15)
        adjusted += fpPenalty
      }

      // Low false positive rate + significant incidents → lower thresholds (more aggressive)
      if (stats.falsePositiveRate < 0.05 && stats.totalIncidents > 10) {
        adjusted -= 0.03
      }

      // If top patterns have very high hit counts and low FP, lower threshold
      const topPatternAdjustment = computeTopPatternAdjustment(stats)
      adjusted += topPatternAdjustment

      // Drift detected → temporarily raise thresholds to reduce noise
      if (stats.driftDetected) {
        adjusted += 0.05
      }

      // Clamp to bounds
      adjusted = Math.max(THRESHOLD_MIN, Math.min(THRESHOLD_MAX, adjusted))

      result[level] = Math.round(adjusted * 1000) / 1000
      this.currentThresholds.set(level, result[level] ?? baseThreshold)
    }

    return Object.freeze(result)
  }

  /**
   * Get current thresholds without adaptation.
   */
  getCurrentThresholds(): Readonly<Record<string, number>> {
    return Object.freeze(Object.fromEntries(this.currentThresholds))
  }

  /**
   * Reset thresholds to defaults.
   */
  reset(): void {
    for (const [key, value] of Object.entries(DEFAULT_THRESHOLDS)) {
      this.currentThresholds.set(key, value)
    }
  }
}

/**
 * Compute threshold adjustment from top pattern performance.
 * High-performing patterns (high hits, low FP) → lower thresholds.
 * Poor-performing patterns (high FP) → higher thresholds.
 */
function computeTopPatternAdjustment(stats: LearningStats): number {
  if (stats.topPatterns.length === 0) return 0

  let totalAdjustment = 0
  let count = 0

  for (const pattern of stats.topPatterns) {
    const totalChecks = pattern.hitCount + pattern.falsePositiveCount
    if (totalChecks === 0) continue

    const fpRate = pattern.falsePositiveCount / totalChecks

    if (fpRate < 0.02 && pattern.hitCount > 5) {
      // Excellent pattern: lower threshold slightly
      totalAdjustment -= 0.01
    } else if (fpRate > 0.2) {
      // Poor pattern: raise threshold
      totalAdjustment += 0.02
    }

    count += 1
  }

  return count > 0 ? totalAdjustment / count : 0
}
