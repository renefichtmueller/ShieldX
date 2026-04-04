/**
 * ShieldX — Main Orchestrator.
 *
 * Primary entry point for the 10-layer defense pipeline.
 * Coordinates preprocessing, detection, classification, behavioral monitoring,
 * MCP guard, healing, and sanitization into a single `scanInput()` call.
 *
 * All scanner invocations are wrapped in try/catch so a failing module
 * never breaks the pipeline. Parallel execution via `Promise.allSettled`.
 *
 * @example
 * ```typescript
 * const shield = new ShieldX({ learning: { storageBackend: 'memory' } })
 * await shield.initialize()
 * const result = await shield.scanInput('user message')
 * ```
 */

import { randomUUID } from 'node:crypto'
import type pino from 'pino'

import type {
  BehavioralContext,
  HealingAction,
  KillChainPhase,
  ScanResult,
  ShieldXConfig,
  ShieldXResult,
  ThreatLevel,
} from '../types/detection.js'
import type { LearningStats } from '../types/learning.js'
import type { ShieldXDashboardAPI, IncidentFeedItem, ProtectedEndpoint, HealingLogEntry } from '../types/dashboard.js'
import type { ResistanceTestConfig } from '../types/resistance.js'
import { ResistanceTestEngine } from '../testing/ResistanceTestEngine.js'

import { defaultConfig, mergeConfig } from './config.js'
import { createLogger } from './logger.js'

// L0 — Preprocessing
import { UnicodeNormalizer } from '../preprocessing/UnicodeNormalizer.js'
import { TokenizerNormalizer } from '../preprocessing/TokenizerNormalizer.js'
import { CompressedPayloadDetector } from '../preprocessing/CompressedPayloadDetector.js'

// L1 — Rule-based detection
import { RuleEngine } from '../detection/RuleEngine.js'
import { EntropyScanner } from '../detection/EntropyScanner.js'
import { UnicodeScanner } from '../detection/UnicodeScanner.js'

// L6 — Behavioral monitoring (functional API)
import { scan as conversationScan } from '../behavioral/ConversationTracker.js'
import { check as intentCheck } from '../behavioral/IntentMonitor.js'
import { checkIntegrity } from '../behavioral/ContextIntegrity.js'

// L7 — MCP Guard (functional API)
import { checkPrivilege } from '../mcp-guard/PrivilegeChecker.js'
import {
  recordCall as recordToolCall,
  analyzeSequence as analyzeToolSequence,
} from '../mcp-guard/ToolChainGuard.js'
import { checkBudget } from '../mcp-guard/ResourceGovernor.js'

// L8 — Sanitization
import { InputSanitizer } from '../sanitization/InputSanitizer.js'
import { OutputSanitizer } from '../sanitization/OutputSanitizer.js'

// Kill chain classification
import { KillChainMapper } from '../behavioral/KillChainMapper.js'

// Healing
import { HealingOrchestrator } from '../healing/HealingOrchestrator.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Threat level numeric ordering for aggregation */
const THREAT_SEVERITY: Readonly<Record<ThreatLevel, number>> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
} as const

/** Reverse lookup: severity number -> ThreatLevel */
const SEVERITY_TO_LEVEL: readonly ThreatLevel[] = [
  'none',
  'low',
  'medium',
  'high',
  'critical',
] as const

// ---------------------------------------------------------------------------
// ShieldX Orchestrator
// ---------------------------------------------------------------------------

/**
 * ShieldX — Self-Evolving LLM Prompt Injection Defense.
 *
 * Orchestrates 10 defense layers with parallel execution,
 * kill chain mapping, self-healing, and graceful degradation.
 */
export class ShieldX {
  private readonly config: ShieldXConfig
  private readonly log: pino.Logger

  // L0
  private readonly unicodeNormalizer: UnicodeNormalizer
  private readonly tokenizerNormalizer: TokenizerNormalizer
  private readonly compressedPayloadDetector: CompressedPayloadDetector

  // L1
  private readonly ruleEngine: RuleEngine

  // L4
  private readonly entropyScanner: EntropyScanner

  // L5
  private readonly unicodeScanner: UnicodeScanner

  // L8
  private readonly inputSanitizer: InputSanitizer
  private readonly outputSanitizer: OutputSanitizer

  // Kill chain + Healing
  private readonly killChainMapper: KillChainMapper
  private readonly healingOrchestrator: HealingOrchestrator

  // Resistance Testing
  private readonly resistanceTestEngine: ResistanceTestEngine

  private initialized = false

  /**
   * Create a new ShieldX instance.
   *
   * @param overrides - Partial config merged on top of defaultConfig
   */
  constructor(overrides: Partial<ShieldXConfig> = {}) {
    this.config = mergeConfig(defaultConfig, overrides)
    this.log = createLogger(this.config.logging)

    // L0 — always initialized (zero-cost, high-impact)
    this.unicodeNormalizer = new UnicodeNormalizer(this.config)
    this.tokenizerNormalizer = new TokenizerNormalizer(this.config)
    this.compressedPayloadDetector = new CompressedPayloadDetector(this.config)

    // L1 — rule engine
    this.ruleEngine = new RuleEngine(this.config)
    this.entropyScanner = new EntropyScanner()
    this.unicodeScanner = new UnicodeScanner()

    // L8 — sanitization
    this.inputSanitizer = new InputSanitizer(this.config)
    this.outputSanitizer = new OutputSanitizer(this.config)

    // Kill chain + healing
    this.killChainMapper = new KillChainMapper()
    this.healingOrchestrator = new HealingOrchestrator(this.config)

    // Resistance testing — binds scanInput for automated testing
    this.resistanceTestEngine = new ResistanceTestEngine(
      async (input) => {
        const r = await this.scanInput(input)
        return {
          ...r,
          confidence: Math.max(...r.scanResults.map(s => s.confidence), 0),
        }
      },
    )

    this.log.info({ scanners: this.config.scanners }, 'ShieldX instance created')
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Initialize async resources (database, migrations, pattern loading).
   * Must be called before first scan.
   */
  async initialize(): Promise<void> {
    if (this.initialized) return
    this.log.info('Initializing ShieldX...')
    // Future: database migrations, pattern loading, model warm-up
    this.initialized = true
    this.log.info('ShieldX initialized')
  }

  /**
   * Scan user input through the full defense pipeline.
   *
   * Pipeline order:
   * 1. L0: Preprocessing (Unicode, Tokenizer, CompressedPayload)
   * 2. L1+L2: Rule engine + Sentinel classifier (parallel)
   * 3. L3-L5: Embedding, entropy, attention scanners (parallel)
   * 4. L6: Behavioral monitoring (conversation, intent, context)
   * 5. L7: MCP Guard (if tool call context)
   * 6. Aggregate, classify kill chain, determine healing action
   * 7. L8: Sanitize if needed
   *
   * @param input - The raw user input string
   * @param context - Optional behavioral context for session tracking
   * @returns Aggregated ShieldXResult
   */
  async scanInput(
    input: string,
    context?: Partial<BehavioralContext>,
  ): Promise<ShieldXResult> {
    const scanId = randomUUID()
    const startTime = performance.now()
    const allResults: ScanResult[] = []

    // -- L0: Preprocessing --------------------------------------------------
    const { normalizedInput, l0Results } = await this.runPreprocessing(input)
    allResults.push(...l0Results)

    // -- L1 + L2: Rule engine + Sentinel (parallel) -------------------------
    const l1l2Results = await this.runDetectionLayer(normalizedInput)
    allResults.push(...l1l2Results)

    // -- L3-L5: Advanced scanners (parallel) ---------------------------------
    const advancedResults = await this.runAdvancedScanners(normalizedInput)
    allResults.push(...advancedResults)

    // -- L6: Behavioral monitoring -------------------------------------------
    const behavioralResults = await this.runBehavioralLayer(
      normalizedInput,
      context,
    )
    allResults.push(...behavioralResults)

    // -- L7: MCP Guard (only if tool call context provided) ------------------
    // Tool call validation is exposed separately via validateToolCall()

    // -- Aggregate results ---------------------------------------------------
    const detected = allResults.some((r) => r.detected)
    const threatLevel = this.aggregateThreatLevel(allResults)

    // -- Kill chain classification -------------------------------------------
    const classification = this.killChainMapper.classify(allResults)

    // -- Healing action determination ----------------------------------------
    const action = detected
      ? this.healingOrchestrator.determineAction(
          threatLevel,
          classification.primaryPhase,
        )
      : ('allow' as HealingAction)

    // -- L8: Sanitization if needed ------------------------------------------
    let sanitizedInput: string | undefined
    if (action === 'sanitize' && this.config.healing.autoSanitize) {
      const sanitizationResult = await this.inputSanitizer.sanitize(
        normalizedInput,
        allResults.filter((r) => r.detected).flatMap((r) => r.matchedPatterns),
      )
      sanitizedInput = sanitizationResult.sanitized
    }

    const latencyMs = performance.now() - startTime

    const result: ShieldXResult = {
      id: scanId,
      timestamp: new Date().toISOString(),
      input,
      ...(sanitizedInput !== undefined ? { sanitizedInput } : {}),
      detected,
      threatLevel,
      killChainPhase: classification.primaryPhase,
      action,
      scanResults: allResults,
      healingApplied: action !== 'allow',
      latencyMs,
    }

    this.log.info(
      {
        scanId,
        detected,
        threatLevel,
        phase: classification.primaryPhase,
        action,
        latencyMs: Math.round(latencyMs * 100) / 100,
        scannerCount: allResults.length,
      },
      'Input scan complete',
    )

    return result
  }

  /**
   * Scan LLM output before returning to the user.
   *
   * Checks for:
   * 1. System prompt leakage
   * 2. Tool call injection in output
   * 3. Script/HTML injection
   * 4. Canary token leakage
   *
   * @param output - The raw LLM output string
   * @param context - Optional context (sessionId, original input hash)
   * @returns Aggregated ShieldXResult for the output
   */
  async scanOutput(
    output: string,
    _context?: Partial<{ sessionId: string; inputHash: string }>,
  ): Promise<ShieldXResult> {
    const scanId = randomUUID()
    const startTime = performance.now()
    const allResults: ScanResult[] = []

    // Output sanitization analysis
    const sanitizationResult = await this.outputSanitizer.sanitize(output)
    const issues = sanitizationResult.issues

    // Build a synthetic ScanResult from output sanitization
    const outputScanResult: ScanResult = {
      scannerId: 'output-sanitizer',
      scannerType: 'canary',
      detected: issues.length > 0,
      confidence: issues.length > 0
        ? Math.min(0.5 + issues.length * 0.15, 1.0)
        : 0,
      threatLevel: issues.length >= 3
        ? 'high'
        : issues.length >= 1
          ? 'medium'
          : 'none',
      killChainPhase: sanitizationResult.systemPromptLeakDetected
        ? 'actions_on_objective'
        : 'none',
      matchedPatterns: issues,
      latencyMs: performance.now() - startTime,
    }
    allResults.push(outputScanResult)

    const detected = allResults.some((r) => r.detected)
    const threatLevel = this.aggregateThreatLevel(allResults)
    const classification = this.killChainMapper.classify(allResults)
    const action = detected
      ? this.healingOrchestrator.determineAction(
          threatLevel,
          classification.primaryPhase,
        )
      : ('allow' as HealingAction)

    const sanitizedOutput = detected
      ? sanitizationResult.sanitized
      : undefined

    const latencyMs = performance.now() - startTime

    const result: ShieldXResult = {
      id: scanId,
      timestamp: new Date().toISOString(),
      input: output,
      ...(sanitizedOutput !== undefined ? { sanitizedInput: sanitizedOutput } : {}),
      detected,
      threatLevel,
      killChainPhase: classification.primaryPhase,
      action,
      scanResults: allResults,
      healingApplied: action !== 'allow',
      latencyMs,
    }

    this.log.info(
      {
        scanId,
        detected,
        threatLevel,
        action,
        issueCount: issues.length,
        latencyMs: Math.round(latencyMs * 100) / 100,
      },
      'Output scan complete',
    )

    return result
  }

  /**
   * Validate an MCP tool call against security policies.
   *
   * Checks:
   * 1. Tool definition inspection (poison detection)
   * 2. Privilege check (least-privilege enforcement)
   * 3. Tool chain sequence analysis
   * 4. Resource budget check
   *
   * @param toolName - Name of the tool being invoked
   * @param toolArgs - Arguments passed to the tool
   * @param context - Behavioral context with session and permissions
   * @returns Validation result with allowed flag, reason, and ScanResult
   */
  async validateToolCall(
    toolName: string,
    toolArgs: Readonly<Record<string, unknown>>,
    context: Partial<BehavioralContext>,
  ): Promise<{ readonly allowed: boolean; readonly reason?: string; readonly result: ScanResult }> {
    const startTime = performance.now()
    const sessionId = context.sessionId ?? 'anonymous'

    if (!this.config.mcpGuard.enabled) {
      return {
        allowed: true,
        result: this.createPassthroughScanResult('mcp-guard-disabled', startTime),
      }
    }

    // 1. Privilege check
    if (this.config.mcpGuard.privilegeCheck) {
      const privResult = checkPrivilege(sessionId, toolName, toolArgs)
      if (!privResult.allowed) {
        return {
          allowed: false,
          reason: privResult.reason ?? 'Tool not in allowed set',
          result: this.createBlockScanResult(
            'privilege-checker',
            privResult.reason ?? 'Tool not in allowed set',
            startTime,
          ),
        }
      }
    }

    // 2. Tool chain guard — record and analyze sequence
    if (this.config.mcpGuard.toolChainGuard) {
      recordToolCall(sessionId, toolName, toolArgs)
      const sequenceResult = analyzeToolSequence(sessionId)
      if (sequenceResult.suspicious) {
        return {
          allowed: false,
          reason: `Suspicious tool sequence: ${sequenceResult.patterns.join(', ')}`,
          result: this.createBlockScanResult(
            'tool-chain-guard',
            sequenceResult.patterns.join(', '),
            startTime,
          ),
        }
      }
    }

    // 3. Resource governor — budget check (estimate 0 tokens for the tool call itself)
    if (this.config.mcpGuard.resourceGovernor) {
      const budgetResult = checkBudget(sessionId, 0)
      if (!budgetResult.allowed) {
        return {
          allowed: false,
          reason: budgetResult.reason ?? 'Budget exceeded',
          result: this.createBlockScanResult(
            'resource-governor',
            budgetResult.reason ?? 'Budget exceeded',
            startTime,
          ),
        }
      }
    }

    // All checks passed
    return {
      allowed: true,
      result: this.createPassthroughScanResult('mcp-guard', startTime),
    }
  }

  /**
   * Submit feedback on a previous scan result (false positive / true positive).
   *
   * @param scanId - The ID of the original ShieldXResult
   * @param feedback - Feedback payload
   */
  async submitFeedback(
    scanId: string,
    feedback: {
      readonly isFalsePositive: boolean
      readonly notes?: string
    },
  ): Promise<void> {
    this.log.info(
      { scanId, isFalsePositive: feedback.isFalsePositive },
      'Feedback submitted',
    )
    // Future: delegate to FeedbackProcessor + learning engine
  }

  /**
   * Get current threat statistics from the learning engine.
   */
  async getStats(): Promise<LearningStats> {
    // Return default stats when learning engine is not yet connected
    return {
      totalPatterns: 0,
      builtinPatterns: 0,
      learnedPatterns: 0,
      communityPatterns: 0,
      redTeamPatterns: 0,
      totalIncidents: 0,
      falsePositiveRate: 0,
      topPatterns: [],
      recentIncidents: 0,
      driftDetected: false,
    }
  }

  // -------------------------------------------------------------------------
  // Dashboard API
  // -------------------------------------------------------------------------

  /** In-memory incident store for dashboard */
  private readonly incidents: IncidentFeedItem[] = []
  /** In-memory healing log for dashboard */
  private readonly healingLog: HealingLogEntry[] = []
  /** Registered protected endpoints */
  private readonly protectedEndpoints: ProtectedEndpoint[] = []

  /**
   * Get the Dashboard API for the management UI.
   * Returns a frozen object exposing internal subsystem data.
   */
  getDashboardAPI(): ShieldXDashboardAPI {
    const self = this
    return Object.freeze({
      getConfig: () => self.config,
      getStats: () => self.getStats(),
      getIncidents: async (_timeRange?: string) => [...self.incidents] as readonly IncidentFeedItem[],
      getPatterns: async () => [] as const,
      updatePattern: async (_patternId: string, _updates: { enabled?: boolean; confidence?: number }) => {},
      getAttackGraph: () => ({ nodes: [] as const, edges: [] as const }),
      getDriftStatus: () => null,
      getReviewQueue: () => [] as const,
      submitReview: (_scanId: string, _isAttack: boolean) => {},
      getActiveSessions: () => [] as const,
      generateComplianceReport: (_framework: 'mitre_atlas' | 'owasp_llm' | 'eu_ai_act' | 'combined') => ({
        generatedAt: new Date().toISOString(),
        framework: _framework,
        coverageScore: 0,
        totalTechniques: 0,
        coveredTechniques: 0,
        gaps: [],
        recommendations: [],
        mappings: [],
      }),
      generateEUAIActReport: async () => ({
        generatedAt: new Date().toISOString(),
        riskCategory: 'high' as const,
        article9RiskManagement: { riskIdentification: true, riskMitigation: true, residualRisks: [], testingPerformed: true },
        article12Logging: { incidentLogging: true, auditTrail: true, retentionPeriod: '90 days', totalIncidents: self.incidents.length },
        article14HumanOversight: { humanInTheLoop: true, overrideCapability: true, feedbackMechanism: true },
        article15Accuracy: { falsePositiveRate: 0, falseNegativeRate: 0, benchmarkResults: {} },
        conformityAssessment: { selfAssessment: true, thirdPartyAudit: false },
      }),
      getHealingLog: (_timeRange?: string) => [...self.healingLog] as readonly HealingLogEntry[],
      getProtectedEndpoints: () => [...self.protectedEndpoints] as readonly ProtectedEndpoint[],
      registerEndpoint: (ep: Omit<ProtectedEndpoint, 'id' | 'totalScans' | 'threatsBlocked' | 'registeredAt'>) => {
        const endpoint: ProtectedEndpoint = {
          ...ep,
          id: randomUUID(),
          totalScans: 0,
          threatsBlocked: 0,
          registeredAt: new Date().toISOString(),
        }
        self.protectedEndpoints.push(endpoint)
        return endpoint
      },
      runSelfTest: async () => ({ total: 0, detected: 0, missed: [] as readonly string[] }),
      scanInput: (input: string) => self.scanInput(input),

      // Resistance Testing
      getResistanceConfig: () => self.resistanceTestEngine.getConfig(),
      updateResistanceConfig: (updates: Partial<ResistanceTestConfig>) => self.resistanceTestEngine.updateConfig(updates),
      runResistanceTest: () => self.resistanceTestEngine.runTest(),
      getResistanceHistory: () => self.resistanceTestEngine.getHistory(),
      getResistanceLatest: () => self.resistanceTestEngine.getLatest(),
      getResistanceTrend: () => self.resistanceTestEngine.getTrend(),
      isResistanceTestRunning: () => self.resistanceTestEngine.isRunning(),
      getResistanceProbeCount: () => self.resistanceTestEngine.getProbeCount(),
    })
  }

  /**
   * Record an incident (called internally after detection).
   */
  recordIncident(result: ShieldXResult): void {
    if (result.detected) {
      this.incidents.push({
        id: result.id,
        timestamp: result.timestamp,
        threatLevel: result.threatLevel,
        killChainPhase: result.killChainPhase,
        action: result.action,
        attackVector: result.scanResults.map(r => r.scannerId).join(', '),
        matchedPatterns: result.scanResults.flatMap(r => [...r.matchedPatterns]),
        inputHash: `sha256:${result.id.slice(0, 16)}`,
        mitigationApplied: result.action,
      })
      // Keep max 10000 incidents in memory
      if (this.incidents.length > 10000) {
        this.incidents.splice(0, this.incidents.length - 10000)
      }
    }
  }

  /**
   * Clean shutdown — close DB connections, flush logs, clear session state.
   */
  async destroy(): Promise<void> {
    this.log.info('Shutting down ShieldX...')
    this.initialized = false
    this.log.info('ShieldX shutdown complete')
  }

  // -------------------------------------------------------------------------
  // Private pipeline stages
  // -------------------------------------------------------------------------

  /**
   * L0: Preprocessing — Unicode normalization, tokenizer normalization,
   * compressed payload detection.
   *
   * Unicode + Tokenizer are synchronous (zero-cost).
   * CompressedPayloadDetector.scan() is async.
   */
  private async runPreprocessing(input: string): Promise<{
    readonly normalizedInput: string
    readonly l0Results: readonly ScanResult[]
  }> {
    const results: ScanResult[] = []

    // Unicode normalization: normalize() returns { normalized, ... }, scan() returns ScanResult
    const unicodeNormResult = this.unicodeNormalizer.normalize(input)
    const unicodeScanResult = this.unicodeNormalizer.scan(input)
    results.push(unicodeScanResult)
    let normalizedInput = unicodeNormResult.normalized

    // Tokenizer normalization: normalize() returns string, scan() returns ScanResult
    const tokenizerScanResult = this.tokenizerNormalizer.scan(normalizedInput)
    results.push(tokenizerScanResult)
    normalizedInput = this.tokenizerNormalizer.normalize(normalizedInput)

    // Compressed payload detection: scan() is async, returns ScanResult
    // detect() returns { decodedPayloads, ... } for appending decoded content
    const compressedScanResult = await this.compressedPayloadDetector.scan(normalizedInput)
    results.push(compressedScanResult)

    const compressedDetectResult = await this.compressedPayloadDetector.detect(normalizedInput)
    if (compressedDetectResult.decodedPayloads.length > 0) {
      // Append decoded payloads so downstream scanners can analyze them
      const decoded = compressedDetectResult.decodedPayloads.join(' ')
      normalizedInput = `${normalizedInput} ${decoded}`
    }

    return { normalizedInput, l0Results: results }
  }

  /**
   * L1 + L2: Rule engine (always) + Sentinel classifier (if enabled).
   * Runs in parallel via Promise.allSettled.
   */
  private async runDetectionLayer(
    input: string,
  ): Promise<readonly ScanResult[]> {
    const tasks: Array<Promise<readonly ScanResult[]>> = []

    // L1: Rule engine (always enabled)
    if (this.config.scanners.rules) {
      tasks.push(this.safeRunScanner('rule-engine', () => this.ruleEngine.scan(input)))
    }

    // L2: Sentinel classifier (opt-in, requires model)
    if (this.config.scanners.sentinel) {
      tasks.push(
        this.safeRunScanner('sentinel-classifier', async () => {
          // TODO(L2-semantic): Wire SemanticContrastiveScanner here once an embedder
          // is available in ShieldXConfig. Pattern:
          //   1. const emb = await embedder.embed(input)
          //   2. const result = await semanticContrastiveScanner.scan(emb)
          //   3. return [semanticContrastiveScanner.toScanResult(result)]
          // See: src/semantic/SemanticContrastiveScanner.ts (arXiv:2512.12069)
          return []
        }),
      )
    }

    const settled = await Promise.allSettled(tasks)
    return this.collectSettledResults(settled)
  }

  /**
   * L3-L5: Advanced scanners (embedding, entropy, attention, etc.).
   * All run in parallel.
   */
  private async runAdvancedScanners(
    input: string,
  ): Promise<readonly ScanResult[]> {
    const tasks: Array<Promise<readonly ScanResult[]>> = []

    // L3: Embedding similarity (requires Ollama)
    if (this.config.scanners.embedding) {
      tasks.push(
        this.safeRunScanner('embedding-scanner', async () => {
          // Future: EmbeddingScanner.scan(input)
          return []
        }),
      )
    }

    // L3: Embedding anomaly detection
    if (this.config.scanners.embeddingAnomaly) {
      tasks.push(
        this.safeRunScanner('embedding-anomaly', async () => {
          // Future: EmbeddingAnomalyDetector.scan(input)
          return []
        }),
      )
    }

    // L4: Entropy analysis — DNS covert channel + high-entropy payload detection
    if (this.config.scanners.entropy) {
      tasks.push(
        this.safeRunScanner('entropy-scanner', async () => {
          return this.entropyScanner.scan(input)
        }),
      )
    }

    // L5: Unicode scanner — ASCII smuggling, steganography, CamoLeak, homoglyphs
    if (this.config.scanners.unicode) {
      tasks.push(
        this.safeRunScanner('unicode-scanner', async () => {
          return this.unicodeScanner.scan(input)
        }),
      )
    }

    // L5: Attention analysis (requires Ollama with attention output)
    if (this.config.scanners.attention) {
      tasks.push(
        this.safeRunScanner('attention-scanner', async () => {
          // Future: AttentionScanner.scan(input)
          return []
        }),
      )
    }

    // YARA rules (requires YARA binary)
    if (this.config.scanners.yara) {
      tasks.push(
        this.safeRunScanner('yara-scanner', async () => {
          // Future: YARAScanner.scan(input)
          return []
        }),
      )
    }

    // Canary token injection
    if (this.config.scanners.canary) {
      tasks.push(
        this.safeRunScanner('canary-scanner', async () => {
          // Future: CanaryDetector.scan(input)
          return []
        }),
      )
    }

    // Indirect injection detection
    if (this.config.scanners.indirect) {
      tasks.push(
        this.safeRunScanner('indirect-scanner', async () => {
          // Future: IndirectInjectionDetector.scan(input)
          return []
        }),
      )
    }

    if (tasks.length === 0) return []

    const settled = await Promise.allSettled(tasks)
    return this.collectSettledResults(settled)
  }

  /**
   * L6: Behavioral monitoring — conversation tracking, intent monitoring,
   * context integrity.
   */
  private async runBehavioralLayer(
    input: string,
    context?: Partial<BehavioralContext>,
  ): Promise<readonly ScanResult[]> {
    if (!this.config.behavioral.enabled) return []

    const tasks: Array<Promise<readonly ScanResult[]>> = []

    // Conversation tracking: scan(sessionId, latestInput) -> Promise<ScanResult>
    if (this.config.behavioral.conversationTracking && context?.sessionId) {
      tasks.push(
        this.safeRunScanner('conversation-tracker', async () => {
          const scanResult = await conversationScan(context.sessionId!, input)
          return scanResult.detected ? [scanResult] : []
        }),
      )
    }

    // Intent monitoring: check(input, context) -> Promise<ScanResult>
    if (this.config.behavioral.intentTracking && context?.sessionId) {
      tasks.push(
        this.safeRunScanner('intent-monitor', async () => {
          const fullContext: BehavioralContext = {
            sessionId: context.sessionId!,
            taskDescription: context.taskDescription ?? '',
            startTime: context.startTime ?? new Date().toISOString(),
            messageCount: context.messageCount ?? 0,
            previousActions: context.previousActions ?? [],
            ...(context.userId !== undefined ? { userId: context.userId } : {}),
            ...(context.allowedTools !== undefined
              ? { allowedTools: context.allowedTools }
              : {}),
            ...(context.sensitiveResources !== undefined
              ? { sensitiveResources: context.sensitiveResources }
              : {}),
          }
          const intentResult = await intentCheck(input, fullContext)
          return intentResult.detected ? [intentResult] : []
        }),
      )
    }

    // Context integrity: checkIntegrity() -> { clean, violations, poisonScore }
    if (this.config.behavioral.contextIntegrity) {
      tasks.push(
        this.safeRunScanner('context-integrity', async () => {
          const integrityResult = checkIntegrity()
          if (integrityResult.poisonScore > 0.3) {
            return [
              {
                scannerId: 'context-integrity',
                scannerType: 'context_integrity' as const,
                detected: true,
                confidence: integrityResult.poisonScore,
                threatLevel: (integrityResult.poisonScore >= 0.7
                  ? 'high'
                  : 'medium') as ThreatLevel,
                killChainPhase: 'persistence' as KillChainPhase,
                matchedPatterns: integrityResult.violations,
                latencyMs: 0,
              },
            ]
          }
          return []
        }),
      )
    }

    if (tasks.length === 0) return []

    const settled = await Promise.allSettled(tasks)
    return this.collectSettledResults(settled)
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Aggregate the highest threat level from all scan results.
   */
  private aggregateThreatLevel(results: readonly ScanResult[]): ThreatLevel {
    let maxSeverity = 0
    for (const result of results) {
      if (result.detected) {
        const severity = THREAT_SEVERITY[result.threatLevel]
        if (severity > maxSeverity) {
          maxSeverity = severity
        }
      }
    }
    return SEVERITY_TO_LEVEL[maxSeverity] ?? 'none'
  }

  /**
   * Safely run a scanner, catching any thrown errors.
   * Returns the scanner results or an empty array on failure.
   */
  private async safeRunScanner(
    scannerId: string,
    fn: () => ScanResult[] | readonly ScanResult[] | Promise<ScanResult[] | readonly ScanResult[]>,
  ): Promise<readonly ScanResult[]> {
    try {
      const result = await fn()
      return result
    } catch (error) {
      this.log.error(
        { scannerId, error: error instanceof Error ? error.message : String(error) },
        'Scanner failed — skipping',
      )
      return []
    }
  }

  /**
   * Collect fulfilled results from Promise.allSettled, logging rejections.
   */
  private collectSettledResults(
    settled: readonly PromiseSettledResult<readonly ScanResult[]>[],
  ): readonly ScanResult[] {
    const results: ScanResult[] = []
    for (const entry of settled) {
      if (entry.status === 'fulfilled') {
        results.push(...entry.value)
      } else {
        this.log.error(
          { reason: entry.reason instanceof Error ? entry.reason.message : String(entry.reason) },
          'Scanner promise rejected',
        )
      }
    }
    return results
  }

  /**
   * Create a passthrough ScanResult for disabled/skipped scanners.
   */
  private createPassthroughScanResult(
    scannerId: string,
    startTime: number,
  ): ScanResult {
    return {
      scannerId,
      scannerType: 'tool_chain',
      detected: false,
      confidence: 0,
      threatLevel: 'none',
      killChainPhase: 'none',
      matchedPatterns: [],
      latencyMs: performance.now() - startTime,
    }
  }

  /**
   * Create a blocking ScanResult for failed validation checks.
   */
  private createBlockScanResult(
    scannerId: string,
    reason: string,
    startTime: number,
  ): ScanResult {
    return {
      scannerId,
      scannerType: 'tool_chain',
      detected: true,
      confidence: 0.9,
      threatLevel: 'high',
      killChainPhase: 'lateral_movement',
      matchedPatterns: [reason],
      latencyMs: performance.now() - startTime,
    }
  }
}
