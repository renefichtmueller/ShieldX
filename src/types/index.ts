/**
 * @module @shieldx/core/types
 * Core type definitions for the ShieldX defense system.
 */

export type {
  ThreatLevel,
  ScannerType,
  HealingAction,
  KillChainPhase,
  ScanResult,
  ShieldXResult,
  ShieldXConfig,
  BehavioralContext,
  IncidentReport,
} from './detection.js'

export type {
  HealingStrategy,
  HealingResponse,
  SessionCheckpoint,
  PhaseStrategyConfig,
} from './healing.js'

export type {
  PatternRecord,
  EmbeddingRecord,
  FeedbackRecord,
  LearningStats,
  DriftReport,
  AttackGraphNode,
  AttackGraphEdge,
} from './learning.js'

export type {
  ConversationState,
  ConversationTurn,
  IntentVector,
  SessionProfile,
  TrustLevel,
  TrustTag,
  ContextPartition,
  MemoryEntry,
  AnomalySignal,
} from './behavioral.js'

export type {
  KillChainMapping,
  KillChainPhaseDetail,
  KillChainClassification,
} from './killchain.js'

export type {
  ATLASMapping,
  OWASPMapping,
  ComplianceReport,
  EUAIActReport,
} from './compliance.js'

export type {
  TrustTagType,
  DataOrigin,
  TrustPolicy,
} from './trust.js'

export type {
  ShieldXDashboardAPI,
  TimeRange,
  IncidentFeedItem,
  ProtectedEndpoint,
  HealingLogEntry,
} from './dashboard.js'

export type {
  ResistanceProbeResult,
  ResistanceTestRun,
  ResistanceCategoryResult,
  ResistanceTestConfig,
  ResistanceTrendPoint,
} from './resistance.js'
