/**
 * Re-exported types from @shieldx/core for dashboard use.
 * In monorepo development, these resolve via relative path.
 * In published packages, consumers would install @shieldx/core.
 */

// Detection types
export type {
  ThreatLevel,
  ScannerType,
  HealingAction,
  KillChainPhase,
  ScanResult,
  ShieldXResult,
  ShieldXConfig,
  IncidentReport,
} from '../../src/types/detection'

// Learning types
export type {
  PatternRecord,
  LearningStats,
  DriftReport,
  AttackGraphNode,
  AttackGraphEdge,
} from '../../src/types/learning'

// Behavioral types
export type {
  ConversationState,
} from '../../src/types/behavioral'

// Compliance types
export type {
  ComplianceReport,
  EUAIActReport,
} from '../../src/types/compliance'

// Dashboard API types
export type {
  ShieldXDashboardAPI,
  TimeRange,
  IncidentFeedItem,
  ProtectedEndpoint,
  HealingLogEntry,
} from '../../src/types/dashboard'
