/**
 * Types for behavioral monitoring, conversation tracking, and trust management.
 */

import type { KillChainPhase, ThreatLevel } from './detection.js'
import type { TrustTagType } from './trust.js'

/** Escalation pattern type detected across conversation turns */
export type EscalationPattern = 'crescendo' | 'foot_in_door' | 'jigsaw_puzzle'

/** State of a multi-turn conversation for attack detection */
export interface ConversationState {
  readonly sessionId: string
  readonly turns: readonly ConversationTurn[]
  readonly cumulativeIntentVector: IntentVector
  readonly suspicionScore: number
  readonly escalationDetected: boolean
  readonly topicDrift: number
  readonly authorityShifts: number
  readonly lastUpdated: string
  /** Per-turn harmfulness scores for crescendo detection */
  readonly crescendoScore?: number
  /** Count of consecutive low-harm turns at conversation start (FITD) */
  readonly initialBenignTurns?: number
  /** Map of sensitive topic category -> turn count for jigsaw detection */
  readonly jigsawTopics?: Readonly<Record<string, number>>
}

/** Single turn in a conversation */
export interface ConversationTurn {
  readonly index: number
  readonly timestamp: string
  readonly role: 'user' | 'assistant' | 'system' | 'tool'
  readonly contentHash: string
  readonly intentVector: IntentVector
  readonly trustTag: TrustTagType
  readonly threatSignals: readonly string[]
  readonly suspicionDelta: number
}

/** Semantic intent representation */
export interface IntentVector {
  readonly embedding: readonly number[]
  readonly dominantTopic: string
  readonly sensitivityScore: number
  readonly alignmentWithTask: number
}

/** Baseline behavioral profile for a session */
export interface SessionProfile {
  readonly sessionId: string
  readonly taskEmbedding: readonly number[]
  readonly allowedToolSet: ReadonlySet<string>
  readonly baselineDriftThreshold: number
  readonly messagePatterns: readonly number[]
  readonly averageIntentAlignment: number
  readonly createdAt: string
  readonly messageCount: number
}

/** Trust level for data origin tracking (CaMeL-inspired) */
export type TrustLevel = 'system' | 'developer' | 'user' | 'tool_output' | 'retrieved' | 'external' | 'untrusted'

/** Trust tag attached to data flowing through the pipeline */
export interface TrustTag {
  readonly source: TrustLevel
  readonly origin: string
  readonly timestamp: string
  readonly integrity: 'verified' | 'unverified' | 'compromised'
}

/** Partitioned context window section */
export interface ContextPartition {
  readonly id: string
  readonly trustLevel: TrustLevel
  readonly contentHash: string
  readonly createdAt: string
  readonly expiresAt?: string
  readonly contradictions: readonly string[]
}

/** Memory entry with provenance tracking */
export interface MemoryEntry {
  readonly id: string
  readonly sessionId: string
  readonly contentHash: string
  readonly trustTag: TrustTag
  readonly createdAt: string
  readonly signature?: string
  readonly isQuarantined: boolean
}

/** Anomaly signal from behavioral monitoring */
export interface AnomalySignal {
  readonly type: 'drift' | 'escalation' | 'tool_misuse' | 'authority_shift' | 'topic_pivot' | 'memory_tampering'
  readonly severity: ThreatLevel
  readonly confidence: number
  readonly description: string
  readonly relatedTurns: readonly number[]
  readonly killChainPhase: KillChainPhase
}
