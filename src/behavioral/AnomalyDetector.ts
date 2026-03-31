/**
 * Statistical anomaly detection for behavioral patterns.
 * Uses Z-score analysis to detect deviations from established baselines.
 *
 * Metrics tracked: message length, response time, tool call frequency, topic entropy.
 *
 * Part of Layer 6 — Behavioral Monitoring.
 */

import type { AnomalySignal } from '../types/behavioral.js'
import type { ThreatLevel } from '../types/detection.js'

/** Threshold in standard deviations for anomaly detection */
const Z_SCORE_THRESHOLD = 2.5

/** Metric identifiers for anomaly tracking */
type MetricName = 'message_length' | 'response_time' | 'tool_call_frequency' | 'topic_entropy'

/** Running statistics for a single metric */
interface MetricStats {
  readonly name: MetricName
  readonly count: number
  readonly mean: number
  readonly m2: number // Sum of squared differences from the mean (Welford's)
}

/** Internal mutable store for metric tracking */
const metricStore = new Map<string, MetricStats>()

/**
 * Build a storage key from session and metric name.
 * @param sessionId - The session identifier
 * @param metric - The metric name
 * @returns A composite key
 */
function storeKey(sessionId: string, metric: MetricName): string {
  return `${sessionId}:${metric}`
}

/**
 * Get the standard deviation from Welford's M2 accumulator.
 * @param m2 - The M2 accumulator value
 * @param count - Number of observations
 * @returns The population standard deviation
 */
function standardDeviation(m2: number, count: number): number {
  if (count < 2) return 0
  return Math.sqrt(m2 / count)
}

/**
 * Update running statistics for a metric using Welford's online algorithm.
 * Returns a new immutable stats object.
 *
 * @param stats - Current stats (or undefined for first observation)
 * @param value - The new observed value
 * @param metric - The metric name
 * @returns Updated statistics
 */
function updateStats(
  stats: MetricStats | undefined,
  value: number,
  metric: MetricName,
): MetricStats {
  if (stats === undefined) {
    return { name: metric, count: 1, mean: value, m2: 0 }
  }

  const newCount = stats.count + 1
  const delta = value - stats.mean
  const newMean = stats.mean + delta / newCount
  const delta2 = value - newMean
  const newM2 = stats.m2 + delta * delta2

  return { name: metric, count: newCount, mean: newMean, m2: newM2 }
}

/**
 * Record a metric observation and update the running baseline.
 *
 * @param sessionId - The session identifier
 * @param metric - The metric name
 * @param value - The observed value
 */
export function recordMetric(
  sessionId: string,
  metric: MetricName,
  value: number,
): void {
  const key = storeKey(sessionId, metric)
  const current = metricStore.get(key)
  const updated = updateStats(current, value, metric)
  metricStore.set(key, updated)
}

/**
 * Compute the Z-score of a value given running statistics.
 * @param value - The observed value
 * @param stats - The running statistics
 * @returns The Z-score (number of standard deviations from mean)
 */
function computeZScore(value: number, stats: MetricStats): number {
  const sd = standardDeviation(stats.m2, stats.count)
  if (sd === 0) return 0
  return Math.abs((value - stats.mean) / sd)
}

/**
 * Map a Z-score to a threat level.
 * @param zScore - The computed Z-score
 * @returns The corresponding threat level
 */
function zScoreToThreatLevel(zScore: number): ThreatLevel {
  if (zScore >= 5.0) return 'critical'
  if (zScore >= 4.0) return 'high'
  if (zScore >= 3.0) return 'medium'
  if (zScore >= Z_SCORE_THRESHOLD) return 'low'
  return 'none'
}

/**
 * Detect an anomaly by comparing current metric values against a baseline.
 * Uses Z-score analysis with a threshold of 2.5 standard deviations.
 *
 * @param current - Current observation vector (one value per metric)
 * @param baseline - Baseline vector (one value per metric, same order)
 * @returns An AnomalySignal if anomaly detected, null otherwise
 */
export function detectAnomaly(
  current: readonly number[],
  baseline: readonly number[],
): AnomalySignal | null {
  if (current.length === 0 || baseline.length === 0) return null
  if (current.length !== baseline.length) return null

  let maxZScore = 0
  let maxIndex = -1

  for (let i = 0; i < current.length; i++) {
    const c = current[i]
    const b = baseline[i]
    if (c === undefined || b === undefined) continue

    // Simple Z-score: treat baseline value as mean with assumed unit variance
    // For proper detection, use recordMetric + session-based stats
    const diff = Math.abs(c - b)
    if (diff > maxZScore) {
      maxZScore = diff
      maxIndex = i
    }
  }

  if (maxZScore < Z_SCORE_THRESHOLD) return null

  const metricNames: readonly MetricName[] = [
    'message_length',
    'response_time',
    'tool_call_frequency',
    'topic_entropy',
  ]
  const metricName = maxIndex >= 0 && maxIndex < metricNames.length
    ? metricNames[maxIndex] ?? 'message_length'
    : 'message_length'

  return {
    type: 'drift',
    severity: zScoreToThreatLevel(maxZScore),
    confidence: Math.min(1.0, maxZScore / 5.0),
    description: `Anomaly detected in ${metricName}: Z-score ${maxZScore.toFixed(2)} exceeds threshold ${Z_SCORE_THRESHOLD}`,
    relatedTurns: [],
    killChainPhase: 'reconnaissance',
  }
}

/**
 * Detect anomaly using session-specific running statistics.
 * Requires prior calls to recordMetric to establish baselines.
 *
 * @param sessionId - The session identifier
 * @param metrics - Map of metric name to current value
 * @returns An AnomalySignal if anomaly detected, null otherwise
 */
export function detectSessionAnomaly(
  sessionId: string,
  metrics: Readonly<Record<MetricName, number>>,
): AnomalySignal | null {
  let maxZScore = 0
  let worstMetric: MetricName = 'message_length'

  for (const [metric, value] of Object.entries(metrics) as ReadonlyArray<[MetricName, number]>) {
    const key = storeKey(sessionId, metric)
    const stats = metricStore.get(key)
    if (stats === undefined || stats.count < 3) continue

    const zScore = computeZScore(value, stats)
    if (zScore > maxZScore) {
      maxZScore = zScore
      worstMetric = metric
    }
  }

  if (maxZScore < Z_SCORE_THRESHOLD) return null

  return {
    type: 'drift',
    severity: zScoreToThreatLevel(maxZScore),
    confidence: Math.min(1.0, maxZScore / 5.0),
    description: `Session anomaly in ${worstMetric}: Z-score ${maxZScore.toFixed(2)}`,
    relatedTurns: [],
    killChainPhase: 'reconnaissance',
  }
}

/**
 * Clear all stored metrics for a session.
 * @param sessionId - The session to clear
 */
export function clearSessionMetrics(sessionId: string): void {
  const prefix = `${sessionId}:`
  for (const key of [...metricStore.keys()]) {
    if (key.startsWith(prefix)) {
      metricStore.delete(key)
    }
  }
}
