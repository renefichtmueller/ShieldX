/**
 * Core detection types for the ShieldX defense system.
 */

/** Threat severity level */
export type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

/** Scanner module identifier */
export type ScannerType =
  | 'rule'
  | 'sentinel'
  | 'constitutional'
  | 'embedding'
  | 'embedding_anomaly'
  | 'entropy'
  | 'yara'
  | 'attention'
  | 'canary'
  | 'indirect'
  | 'self_consciousness'
  | 'cross_model'
  | 'behavioral'
  | 'conversation'
  | 'context_integrity'
  | 'memory_integrity'
  | 'unicode'
  | 'tokenizer'
  | 'compressed_payload'
  | 'rag_shield'
  | 'tool_chain'
  | 'resource'
  | 'supply_chain'
  | 'intent_guard'

/** Action taken in response to a detected threat */
export type HealingAction =
  | 'allow'
  | 'sanitize'
  | 'warn'
  | 'block'
  | 'reset'
  | 'incident'

/**
 * Promptware Kill Chain phases (Schneier et al. 2026).
 * Maps prompt injection attacks to a structured attack lifecycle.
 */
export type KillChainPhase =
  | 'none'
  | 'initial_access'
  | 'privilege_escalation'
  | 'reconnaissance'
  | 'persistence'
  | 'command_and_control'
  | 'lateral_movement'
  | 'actions_on_objective'

/** Result from a single scanner module */
export interface ScanResult {
  readonly scannerId: string
  readonly scannerType: ScannerType
  readonly detected: boolean
  readonly confidence: number
  readonly threatLevel: ThreatLevel
  readonly killChainPhase: KillChainPhase
  readonly matchedPatterns: readonly string[]
  readonly rawScore?: number
  readonly latencyMs: number
  readonly metadata?: Readonly<Record<string, unknown>>
}

/** Aggregated result from the ShieldX pipeline */
export interface ShieldXResult {
  readonly id: string
  readonly timestamp: string
  readonly input: string
  readonly sanitizedInput?: string
  readonly detected: boolean
  readonly threatLevel: ThreatLevel
  readonly killChainPhase: KillChainPhase
  readonly action: HealingAction
  readonly scanResults: readonly ScanResult[]
  readonly healingApplied: boolean
  readonly canaryToken?: string
  readonly sessionCheckpoint?: string
  readonly latencyMs: number
  readonly metadata?: Readonly<Record<string, unknown>>
  readonly ensemble?: Readonly<{
    finalVote: 'clean' | 'suspicious' | 'threat'
    finalConfidence: number
    unanimous: boolean
  }>
  readonly atlasMapping?: Readonly<{
    techniqueIds: readonly string[]
    tacticCoverage: Readonly<Record<string, number>>
    unmappedResults: number
  }>
}

/** Full ShieldX configuration */
export interface ShieldXConfig {
  readonly thresholds: {
    readonly low: number
    readonly medium: number
    readonly high: number
    readonly critical: number
  }

  readonly scanners: {
    readonly rules: boolean
    readonly sentinel: boolean
    readonly constitutional: boolean
    readonly embedding: boolean
    readonly embeddingAnomaly: boolean
    readonly entropy: boolean
    readonly yara: boolean
    readonly attention: boolean
    readonly canary: boolean
    readonly indirect: boolean
    readonly selfConsciousness: boolean
    readonly crossModel: boolean
    readonly behavioral: boolean
    readonly unicode: boolean
    readonly tokenizer: boolean
    readonly compressedPayload: boolean
  }

  readonly healing: {
    readonly enabled: boolean
    readonly autoSanitize: boolean
    readonly sessionReset: boolean
    readonly phaseStrategies: Partial<Record<KillChainPhase, HealingAction>>
  }

  readonly learning: {
    readonly enabled: boolean
    readonly storageBackend: 'postgresql' | 'sqlite' | 'memory'
    readonly connectionString?: string
    readonly feedbackLoop: boolean
    readonly communitySync: boolean
    readonly communitySyncUrl?: string
    readonly driftDetection: boolean
    readonly activelearning: boolean
    readonly attackGraph: boolean
  }

  readonly behavioral: {
    readonly enabled: boolean
    readonly baselineWindow: number
    readonly driftThreshold: number
    readonly intentTracking: boolean
    readonly conversationTracking: boolean
    readonly contextIntegrity: boolean
    readonly memoryIntegrity: boolean
    readonly bayesianTrustScoring: boolean
  }

  readonly mcpGuard: {
    readonly enabled: boolean
    readonly ollamaEndpoint?: string
    readonly validateToolCalls: boolean
    readonly privilegeCheck: boolean
    readonly toolChainGuard: boolean
    readonly resourceGovernor: boolean
    readonly decisionGraph: boolean
    readonly manifestVerification: boolean
  }

  readonly ppa: {
    readonly enabled: boolean
    readonly randomizationLevel: 'low' | 'medium' | 'high'
  }

  readonly canary: {
    readonly enabled: boolean
    readonly tokenCount: number
    readonly rotationInterval: number
  }

  readonly ragShield: {
    readonly enabled: boolean
    readonly documentIntegrityScoring: boolean
    readonly embeddingAnomalyDetection: boolean
    readonly provenanceTracking: boolean
  }

  readonly compliance: {
    readonly mitreAtlas: boolean
    readonly owaspLlm: boolean
    readonly euAiAct: boolean
  }

  readonly logging: {
    readonly level: 'silent' | 'error' | 'warn' | 'info' | 'debug'
    readonly structured: boolean
    readonly incidentLog: boolean
  }

  readonly supplyChain: {
    readonly enabled: boolean
    readonly trustedModelHashes?: Readonly<Record<string, string>>
    readonly trustedRegistries?: readonly string[]
    readonly maxAdapterSizeMB: number
    readonly enableDependencyAudit: boolean
    readonly runAuditOnStartup: boolean
  }

  readonly evolution: {
    readonly enabled: boolean
    readonly cycleIntervalMs: number
    readonly maxFPRIncrease: number
    readonly benignCorpusMinSize: number
    readonly autoDeployThreshold: number
    readonly maxRulesPerCycle: number
    readonly rollbackWindowMs: number
  }
}

/** Context for behavioral monitoring */
export interface BehavioralContext {
  readonly sessionId: string
  readonly userId?: string
  readonly taskDescription: string
  readonly allowedTools?: readonly string[]
  readonly sensitiveResources?: readonly string[]
  readonly startTime: string
  readonly messageCount: number
  readonly previousActions: readonly string[]
}

/** Structured incident report */
export interface IncidentReport {
  readonly id: string
  readonly timestamp: string
  readonly sessionId?: string
  readonly userId?: string
  readonly threatLevel: ThreatLevel
  readonly killChainPhase: KillChainPhase
  readonly action: HealingAction
  readonly attackVector: string
  readonly matchedPatterns: readonly string[]
  readonly inputHash: string
  readonly mitigationApplied: string
  readonly falsePositive?: boolean
  readonly atlasMapping?: string
  readonly owaspMapping?: string
  readonly metadata?: Readonly<Record<string, unknown>>
}
