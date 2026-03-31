/**
 * Types for the self-learning / evolution engine.
 */

import type { KillChainPhase, ThreatLevel } from './detection.js'

/** Stored pattern record (PostgreSQL) */
export interface PatternRecord {
  readonly id: string
  readonly createdAt: string
  readonly updatedAt: string
  readonly patternText: string
  readonly patternType: 'regex' | 'embedding' | 'yara' | 'rule'
  readonly killChainPhase: KillChainPhase
  readonly confidenceBase: number
  readonly hitCount: number
  readonly falsePositiveCount: number
  readonly source: 'builtin' | 'learned' | 'community' | 'red_team'
  readonly enabled: boolean
  readonly metadata?: Readonly<Record<string, unknown>>
}

/** Stored embedding record (pgvector) */
export interface EmbeddingRecord {
  readonly id: string
  readonly createdAt: string
  readonly inputHash: string
  readonly embedding: readonly number[]
  readonly killChainPhase: KillChainPhase
  readonly threatLevel: ThreatLevel
  readonly source: string
  readonly metadata?: Readonly<Record<string, unknown>>
}

/** Feedback on a scan result */
export interface FeedbackRecord {
  readonly id: string
  readonly submittedAt: string
  readonly scanId: string
  readonly incidentId?: string
  readonly isFalsePositive: boolean
  readonly notes?: string
  readonly patternAdjustment?: Readonly<Record<string, unknown>>
}

/** Statistics from the learning layer */
export interface LearningStats {
  readonly totalPatterns: number
  readonly builtinPatterns: number
  readonly learnedPatterns: number
  readonly communityPatterns: number
  readonly redTeamPatterns: number
  readonly totalIncidents: number
  readonly falsePositiveRate: number
  readonly topPatterns: readonly PatternRecord[]
  readonly recentIncidents: number
  readonly driftDetected: boolean
  readonly lastDriftReport?: DriftReport
}

/** Concept drift detection report */
export interface DriftReport {
  readonly id: string
  readonly detectedAt: string
  readonly driftType: 'gradual' | 'sudden' | 'recurring'
  readonly affectedPhases: readonly KillChainPhase[]
  readonly confidenceDrop: number
  readonly suggestedAction: 'retrain' | 'investigate' | 'monitor'
  readonly sampleCount: number
}

/** Node in the attack knowledge graph */
export interface AttackGraphNode {
  readonly id: string
  readonly technique: string
  readonly killChainPhase: KillChainPhase
  readonly firstSeen: string
  readonly lastSeen: string
  readonly frequency: number
  readonly successRate: number
  readonly variants: readonly string[]
}

/** Edge in the attack knowledge graph */
export interface AttackGraphEdge {
  readonly sourceId: string
  readonly targetId: string
  readonly relationship: 'evolved_from' | 'combined_with' | 'variant_of' | 'precedes'
  readonly weight: number
  readonly firstSeen: string
}
