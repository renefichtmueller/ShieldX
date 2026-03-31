/**
 * Types for the automated LLM Resistance Test system.
 * Runs scheduled red-team tests and tracks detection rates over time.
 */

import type { KillChainPhase, ThreatLevel } from './detection.js'

/** Single test probe result */
export interface ResistanceProbeResult {
  readonly probeId: string
  readonly input: string
  readonly category: string
  readonly expectedPhase: KillChainPhase
  readonly detected: boolean
  readonly actualPhase: KillChainPhase
  readonly actualThreatLevel: ThreatLevel
  readonly confidence: number
  readonly latencyMs: number
  readonly matchedPatterns: readonly string[]
}

/** Summary of a single test run */
export interface ResistanceTestRun {
  readonly id: string
  readonly timestamp: string
  readonly durationMs: number
  readonly totalProbes: number
  readonly detected: number
  readonly missed: number
  readonly falsePositives: number
  /** True Positive Rate — attacks correctly detected */
  readonly tpr: number
  /** False Positive Rate — benign incorrectly flagged */
  readonly fpr: number
  /** Attack Success Rate — attacks NOT detected */
  readonly asr: number
  /** Phase accuracy — correct kill chain classification */
  readonly phaseAccuracy: number
  /** Average scan latency in ms */
  readonly avgLatencyMs: number
  /** P95 latency */
  readonly p95LatencyMs: number
  /** Per-category breakdown */
  readonly categories: readonly ResistanceCategoryResult[]
  /** Probes that were missed (for learning) */
  readonly missedProbes: readonly ResistanceProbeResult[]
  /** Status of the run */
  readonly status: 'completed' | 'failed' | 'running'
  readonly error?: string
}

/** Per-category result within a test run */
export interface ResistanceCategoryResult {
  readonly category: string
  readonly total: number
  readonly detected: number
  readonly tpr: number
  readonly asr: number
  readonly avgLatencyMs: number
}

/** Resistance test scheduler configuration */
export interface ResistanceTestConfig {
  /** Whether automated testing is enabled */
  readonly enabled: boolean
  /** Cron schedule — default: twice daily at 06:00 and 18:00 */
  readonly schedule: string
  /** How many test runs to retain in history */
  readonly maxHistory: number
  /** Whether to include mutation variants */
  readonly includeMutations: boolean
  /** Whether to auto-learn from missed probes */
  readonly autoLearnFromMissed: boolean
}

/** Trend data point for resistance over time */
export interface ResistanceTrendPoint {
  readonly timestamp: string
  readonly tpr: number
  readonly fpr: number
  readonly asr: number
  readonly phaseAccuracy: number
  readonly totalProbes: number
}
