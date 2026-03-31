/**
 * Concept drift detection using CUSUM algorithm.
 * Monitors sliding window of detection confidence scores
 * to identify gradual, sudden, and recurring drift.
 */

import { randomUUID } from 'node:crypto'

import type { ScanResult } from '../types/detection.js'
import type { DriftReport } from '../types/learning.js'

/** Internal confidence sample */
interface ConfidenceSample {
  readonly timestamp: number
  readonly confidence: number
  readonly scannerType: string
}

/** CUSUM state */
interface CUSUMState {
  sumPositive: number
  sumNegative: number
  mean: number
  count: number
}

/**
 * DriftDetector — monitors for concept drift in detection confidence.
 *
 * Uses the CUSUM (Cumulative Sum) algorithm to detect shifts in
 * the distribution of detection confidence scores over time.
 *
 * Drift types:
 * - Gradual: slow decline in average confidence over many samples
 * - Sudden: sharp drop in confidence within a short window
 * - Recurring: oscillating confidence patterns
 */
export class DriftDetector {
  private readonly windowSize: number
  private readonly driftThreshold: number
  private readonly samples: ConfidenceSample[] = []
  private readonly cusumState: CUSUMState
  private lastDriftReport: DriftReport | null = null
  private driftHistory: readonly number[] = []

  /**
   * @param windowSize - Number of samples in the sliding window (default: 100)
   * @param driftThreshold - CUSUM threshold for drift detection (default: 5.0)
   */
  constructor(windowSize: number = 100, driftThreshold: number = 5.0) {
    this.windowSize = windowSize
    this.driftThreshold = driftThreshold
    this.cusumState = {
      sumPositive: 0,
      sumNegative: 0,
      mean: 0.5, // Initial expected mean confidence
      count: 0,
    }
  }

  /**
   * Record a new confidence observation from a scan result.
   * @param scanResult - Scan result to record
   */
  recordConfidence(scanResult: ScanResult): void {
    const sample: ConfidenceSample = {
      timestamp: Date.now(),
      confidence: scanResult.confidence,
      scannerType: scanResult.scannerType,
    }

    this.samples.push(sample)

    // Maintain sliding window
    if (this.samples.length > this.windowSize * 2) {
      this.samples.splice(0, this.samples.length - this.windowSize)
    }

    // Update CUSUM
    this.updateCUSUM(scanResult.confidence)
  }

  /**
   * Check for concept drift using CUSUM and statistical analysis.
   * @returns Drift report if drift detected, null otherwise
   */
  checkDrift(): DriftReport | null {
    if (this.samples.length < 20) return null // Need minimum samples

    const window = this.samples.slice(-this.windowSize)
    const recentWindow = window.slice(-Math.floor(this.windowSize / 4))

    // Calculate statistics
    const windowMean = computeMean(window.map((s) => s.confidence))
    const recentMean = computeMean(recentWindow.map((s) => s.confidence))
    const windowStdDev = computeStdDev(window.map((s) => s.confidence))

    // Check CUSUM thresholds
    const cusumTriggered =
      this.cusumState.sumPositive > this.driftThreshold ||
      Math.abs(this.cusumState.sumNegative) > this.driftThreshold

    if (!cusumTriggered) return null

    // Classify drift type
    const driftType = classifyDrift(
      windowMean,
      recentMean,
      windowStdDev,
      this.driftHistory,
    )

    // Calculate confidence drop
    const confidenceDrop = Math.round(Math.abs(windowMean - recentMean) * 1000) / 1000

    // Determine affected phases from recent samples
    const affectedPhases = [
      ...new Set(
        recentWindow
          .filter((s) => s.confidence < windowMean - windowStdDev)
          .map(() => 'initial_access' as const), // Map to phases based on scanner types
      ),
    ]

    // Determine suggested action
    const suggestedAction = determineSuggestedAction(driftType, confidenceDrop)

    const report: DriftReport = Object.freeze({
      id: randomUUID(),
      detectedAt: new Date().toISOString(),
      driftType,
      affectedPhases: Object.freeze(affectedPhases.length > 0 ? affectedPhases : ['none' as const]),
      confidenceDrop,
      suggestedAction,
      sampleCount: window.length,
    })

    // Track drift history for recurring detection
    this.driftHistory = Object.freeze([
      ...this.driftHistory.slice(-10),
      Date.now(),
    ])

    this.lastDriftReport = report

    // Reset CUSUM after detection
    this.cusumState.sumPositive = 0
    this.cusumState.sumNegative = 0

    return report
  }

  /**
   * Get the most recent drift report.
   */
  getLastReport(): DriftReport | null {
    return this.lastDriftReport
  }

  /**
   * Get current sample count.
   */
  getSampleCount(): number {
    return this.samples.length
  }

  // ---------------------------------------------------------------------------
  // CUSUM algorithm
  // ---------------------------------------------------------------------------

  private updateCUSUM(confidence: number): void {
    // Update running mean
    this.cusumState.count += 1
    const oldMean = this.cusumState.mean
    this.cusumState.mean += (confidence - oldMean) / this.cusumState.count

    // Allowance parameter (slack)
    const slack = 0.05

    // Positive CUSUM (detect increase)
    const deviation = confidence - this.cusumState.mean
    this.cusumState.sumPositive = Math.max(0, this.cusumState.sumPositive + deviation - slack)

    // Negative CUSUM (detect decrease)
    this.cusumState.sumNegative = Math.min(0, this.cusumState.sumNegative + deviation + slack)
  }
}

/** Compute arithmetic mean */
function computeMean(values: readonly number[]): number {
  if (values.length === 0) return 0
  return values.reduce((sum, v) => sum + v, 0) / values.length
}

/** Compute standard deviation */
function computeStdDev(values: readonly number[]): number {
  if (values.length < 2) return 0
  const mean = computeMean(values)
  const squaredDiffs = values.map((v) => (v - mean) ** 2)
  return Math.sqrt(squaredDiffs.reduce((sum, v) => sum + v, 0) / (values.length - 1))
}

/** Classify the type of drift based on statistics */
function classifyDrift(
  windowMean: number,
  recentMean: number,
  stdDev: number,
  driftHistory: readonly number[],
): DriftReport['driftType'] {
  // Sudden: large drop relative to standard deviation
  const dropMagnitude = Math.abs(windowMean - recentMean)
  if (dropMagnitude > stdDev * 2) return 'sudden'

  // Recurring: multiple drift events in recent history
  const recentDrifts = driftHistory.filter((t) => Date.now() - t < 3_600_000) // last hour
  if (recentDrifts.length >= 3) return 'recurring'

  // Default: gradual
  return 'gradual'
}

/** Determine suggested action based on drift severity */
function determineSuggestedAction(
  driftType: DriftReport['driftType'],
  confidenceDrop: number,
): DriftReport['suggestedAction'] {
  if (driftType === 'sudden' && confidenceDrop > 0.2) return 'retrain'
  if (driftType === 'recurring') return 'investigate'
  if (confidenceDrop > 0.15) return 'investigate'
  return 'monitor'
}
