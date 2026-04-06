/**
 * Dashboard API types — exposes internal ShieldX subsystems
 * for the @shieldx/dashboard management UI.
 */

import type { ShieldXConfig, ScanResult, ShieldXResult, IncidentReport, ThreatLevel, KillChainPhase } from './detection.js'
import type { LearningStats, DriftReport, AttackGraphNode, AttackGraphEdge, PatternRecord } from './learning.js'
import type { ConversationState } from './behavioral.js'
import type { ComplianceReport, EUAIActReport } from './compliance.js'
import type { ResistanceTestConfig, ResistanceTestRun, ResistanceTrendPoint } from './resistance.js'
import type { EvolutionConfig, EvolutionCycleResult, DeployedRule } from '../learning/EvolutionEngine.js'

/** Time range filter for queries */
export type TimeRange = '1h' | '6h' | '24h' | '7d' | '30d' | 'all'

/** Incident with metadata for the feed */
export interface IncidentFeedItem extends IncidentReport {
  readonly scanResults?: readonly ScanResult[]
}

/** Protected LLM endpoint registration */
export interface ProtectedEndpoint {
  readonly id: string
  readonly name: string
  readonly provider: 'anthropic' | 'ollama' | 'openai' | 'custom'
  readonly endpoint: string
  readonly active: boolean
  readonly totalScans: number
  readonly threatsBlocked: number
  readonly lastIncident?: string
  readonly registeredAt: string
}

/** Healing log entry for the dashboard */
export interface HealingLogEntry {
  readonly id: string
  readonly timestamp: string
  readonly inputHash: string
  readonly action: string
  readonly phase: KillChainPhase
  readonly threatLevel: ThreatLevel
  readonly strategyUsed: string
  readonly sessionResetPerformed: boolean
  readonly incidentReported: boolean
}

/** Dashboard API exposed by ShieldX.getDashboardAPI() */
export interface ShieldXDashboardAPI {
  /** Current configuration (read-only snapshot) */
  getConfig(): ShieldXConfig

  /** Learning statistics */
  getStats(): Promise<LearningStats>

  /** Recent incidents within time range */
  getIncidents(timeRange?: TimeRange): Promise<readonly IncidentFeedItem[]>

  /** All stored patterns */
  getPatterns(): Promise<readonly PatternRecord[]>

  /** Update pattern enabled/confidence */
  updatePattern(patternId: string, updates: { enabled?: boolean; confidence?: number }): Promise<void>

  /** Attack graph data */
  getAttackGraph(): { nodes: readonly AttackGraphNode[]; edges: readonly AttackGraphEdge[] }

  /** Concept drift status */
  getDriftStatus(): DriftReport | null

  /** Active learning review queue */
  getReviewQueue(): readonly ScanResult[]

  /** Submit human verdict for review item */
  submitReview(scanId: string, isAttack: boolean): void

  /** Active conversation sessions */
  getActiveSessions(): readonly ConversationState[]

  /** Compliance report generation */
  generateComplianceReport(framework: 'mitre_atlas' | 'owasp_llm' | 'eu_ai_act' | 'combined'): ComplianceReport

  /** EU AI Act specific report */
  generateEUAIActReport(): Promise<EUAIActReport>

  /** Healing log entries */
  getHealingLog(timeRange?: TimeRange): readonly HealingLogEntry[]

  /** Protected endpoints registry */
  getProtectedEndpoints(): readonly ProtectedEndpoint[]

  /** Register a new protected endpoint */
  registerEndpoint(endpoint: Omit<ProtectedEndpoint, 'id' | 'totalScans' | 'threatsBlocked' | 'registeredAt'>): ProtectedEndpoint

  /** Run self-test (red team) */
  runSelfTest(): Promise<{ total: number; detected: number; missed: readonly string[] }>

  /** Scan a single input (for Try It page) */
  scanInput(input: string): Promise<ShieldXResult>

  // ---- Resistance Testing ----

  /** Get resistance test configuration */
  getResistanceConfig(): ResistanceTestConfig

  /** Update resistance test config (enable/disable, schedule, etc.) */
  updateResistanceConfig(updates: Partial<ResistanceTestConfig>): void

  /** Run a resistance test manually */
  runResistanceTest(): Promise<ResistanceTestRun>

  /** Get all historical test runs */
  getResistanceHistory(): readonly ResistanceTestRun[]

  /** Get the latest test run */
  getResistanceLatest(): ResistanceTestRun | null

  /** Get trend data for charts */
  getResistanceTrend(): readonly ResistanceTrendPoint[]

  /** Whether a test is currently running */
  isResistanceTestRunning(): boolean

  /** Total number of test probes */
  getResistanceProbeCount(): number

  // ---- Evolution Engine ----

  /** Run one full evolution cycle */
  runEvolutionCycle(): Promise<EvolutionCycleResult>

  /** Get history of all evolution cycles */
  getEvolutionHistory(): readonly EvolutionCycleResult[]

  /** Get current evolution config */
  getEvolutionConfig(): EvolutionConfig

  /** Get all rules deployed by evolution */
  getEvolutionDeployedRules(): readonly DeployedRule[]

  /** Pause the evolution engine */
  pauseEvolution(): void

  /** Resume the evolution engine */
  resumeEvolution(): void

  /** Whether evolution is paused */
  isEvolutionPaused(): boolean

  /** Whether an evolution cycle is running */
  isEvolutionRunning(): boolean
}
