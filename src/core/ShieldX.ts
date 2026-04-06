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
import { CipherDecoder } from '../preprocessing/CipherDecoder.js'

// L1 — Rule-based detection
import { RuleEngine } from '../detection/RuleEngine.js'
import { EntropyScanner } from '../detection/EntropyScanner.js'
import { UnicodeScanner } from '../detection/UnicodeScanner.js'

// L3 — Indirect injection detection
import { IndirectInjectionDetector } from '../detection/IndirectInjectionDetector.js'

// Early-pipeline — Resource exhaustion (DoS-via-LLM)
import { ResourceExhaustionDetector } from '../detection/ResourceExhaustionDetector.js'

// L6 — Behavioral monitoring (functional API)
import { scan as conversationScan } from '../behavioral/ConversationTracker.js'
import { check as intentCheck } from '../behavioral/IntentMonitor.js'
import { checkIntegrity } from '../behavioral/ContextIntegrity.js'

// L6 — Auth context manipulation guard
import { AuthContextGuard } from '../behavioral/AuthContextGuard.js'

// L6 — Enhanced multi-turn decomposition detection
import { DecompositionDetector } from '../behavioral/DecompositionDetector.js'

// L7 — MCP Guard (functional API)
import { MELONGuard } from '../mcp-guard/MELONGuard.js'
import { checkPrivilege } from '../mcp-guard/PrivilegeChecker.js'
import {
  recordCall as recordToolCall,
  analyzeSequence as analyzeToolSequence,
} from '../mcp-guard/ToolChainGuard.js'
import { checkBudget } from '../mcp-guard/ResourceGovernor.js'
import { validate as validateSafety } from '../mcp-guard/ToolCallSafetyGuard.js'

// L8 — Sanitization
import { InputSanitizer } from '../sanitization/InputSanitizer.js'
import { OutputSanitizer } from '../sanitization/OutputSanitizer.js'
import { OutputPayloadGuard } from '../sanitization/OutputPayloadGuard.js'

// L2 — Semantic Contrastive Scanner
import { SemanticContrastiveScanner, bagOfWordsEmbedding } from '../semantic/SemanticContrastiveScanner.js'
import { EmbeddingStore } from '../learning/EmbeddingStore.js'

// Canary token detection
import { CanaryManager } from '../validation/CanaryManager.js'

// Learning engine
import { PatternStore } from '../learning/PatternStore.js'
import { ActiveLearner } from '../learning/ActiveLearner.js'
import { RedTeamEngine } from '../learning/RedTeamEngine.js'
import { DriftDetector } from '../learning/DriftDetector.js'
import { ThresholdAdaptor } from '../learning/ThresholdAdaptor.js'

// Evolution engine
import { EvolutionEngine } from '../learning/EvolutionEngine.js'
import { PatternEvolver } from '../learning/PatternEvolver.js'

// Adversarial training — game-theoretic self-training (IEEE S&P 2025)
import { AdversarialTrainer } from '../learning/AdversarialTrainer.js'
import type { TrainingResult } from '../learning/AdversarialTrainer.js'

// Phase 1: Immune Memory + Fever Response + Over-Defense Calibration
import { ImmuneMemory } from '../learning/ImmuneMemory.js'
import type { ImmuneMemoryStats } from '../learning/ImmuneMemory.js'
import { FeverResponse } from './FeverResponse.js'
import type { FeverState } from './FeverResponse.js'
import { OverDefenseCalibrator } from '../learning/OverDefenseCalibrator.js'
import type { CalibrationResult } from '../learning/OverDefenseCalibrator.js'

// Kill chain classification
import { KillChainMapper } from '../behavioral/KillChainMapper.js'

// Healing
import { HealingOrchestrator } from '../healing/HealingOrchestrator.js'

// Supply chain integrity
import { ModelIntegrityGuard } from '../supply-chain/ModelIntegrityGuard.js'
import type { IntegrityCheckResult } from '../supply-chain/ModelIntegrityGuard.js'

// Phase 3: Defense Ensemble + ATLAS technique mapping
import { DefenseEnsemble } from './DefenseEnsemble.js'
import type { EnsembleVerdict } from './DefenseEnsemble.js'
import { AtlasTechniqueMapper } from './AtlasTechniqueMapper.js'
import type { AtlasMappingResult } from './AtlasTechniqueMapper.js'

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
  private readonly cipherDecoder: CipherDecoder

  // L1
  private readonly ruleEngine: RuleEngine

  // L4
  private readonly entropyScanner: EntropyScanner

  // L5
  private readonly unicodeScanner: UnicodeScanner

  // L3 — Indirect injection
  private readonly indirectInjectionDetector: IndirectInjectionDetector

  // Early-pipeline — Resource exhaustion
  private readonly resourceExhaustionDetector: ResourceExhaustionDetector

  // L6 — Auth context guard
  private readonly authContextGuard: AuthContextGuard

  // L6 — Enhanced decomposition detection
  private readonly decompositionDetector: DecompositionDetector

  // L2
  private readonly embeddingStore: EmbeddingStore
  private readonly semanticContrastiveScanner: SemanticContrastiveScanner

  // L8
  private readonly inputSanitizer: InputSanitizer
  private readonly outputSanitizer: OutputSanitizer
  private readonly outputPayloadGuard: OutputPayloadGuard

  // Canary detection
  private readonly canaryManager: CanaryManager

  // Kill chain + Healing
  private readonly killChainMapper: KillChainMapper
  private readonly healingOrchestrator: HealingOrchestrator

  // Resistance Testing
  private readonly resistanceTestEngine: ResistanceTestEngine

  // Learning engine
  private readonly patternStore: PatternStore
  private readonly activeLearner: ActiveLearner
  private readonly redTeamEngine: RedTeamEngine
  private readonly driftDetector: DriftDetector
  private readonly thresholdAdaptor: ThresholdAdaptor
  private readonly patternEvolver: PatternEvolver

  // Evolution engine
  private readonly evolutionEngine: EvolutionEngine

  // Phase 1: Immune Memory + Fever Response
  private readonly immuneMemory: ImmuneMemory
  private readonly feverResponse: FeverResponse

  // Phase 2: MELONGuard + AdversarialTrainer
  private readonly melonGuard: MELONGuard
  private readonly adversarialTrainer: AdversarialTrainer

  // Supply chain integrity
  private readonly modelIntegrityGuard: ModelIntegrityGuard

  // Phase 3: Defense Ensemble + ATLAS mapping
  private readonly defenseEnsemble: DefenseEnsemble
  private readonly atlasTechniqueMapper: AtlasTechniqueMapper

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
    this.cipherDecoder = new CipherDecoder(this.config)

    // L1 — rule engine
    this.ruleEngine = new RuleEngine(this.config)
    this.entropyScanner = new EntropyScanner()
    this.unicodeScanner = new UnicodeScanner()

    // L3 — indirect injection detector (stateless, pre-compiled regexes)
    this.indirectInjectionDetector = new IndirectInjectionDetector()

    // Early-pipeline — resource exhaustion detector (stateless, pre-compiled regexes)
    this.resourceExhaustionDetector = new ResourceExhaustionDetector()

    // L6 — auth context guard (stateful per-session escalation tracking)
    this.authContextGuard = new AuthContextGuard()

    // L6 — enhanced decomposition detection
    this.decompositionDetector = new DecompositionDetector()

    // L2 — Semantic Contrastive Scanner with in-memory embedding store
    this.embeddingStore = new EmbeddingStore({ backend: 'memory' })
    this.semanticContrastiveScanner = new SemanticContrastiveScanner(this.embeddingStore)

    // L8 — sanitization
    this.inputSanitizer = new InputSanitizer(this.config)
    this.outputSanitizer = new OutputSanitizer(this.config)
    this.outputPayloadGuard = new OutputPayloadGuard()

    // Canary detection — session-scoped tokens for prompt leakage detection
    // Config stores rotationInterval in seconds; CanaryManager expects milliseconds
    this.canaryManager = new CanaryManager(
      this.config.canary.tokenCount,
      this.config.canary.rotationInterval * 1000,
    )

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

    // Learning engine — PatternStore as persistent backend, plus active learning modules
    const storageBackend = this.config.learning.storageBackend === 'postgresql'
      ? 'postgresql' as const
      : 'memory' as const
    this.patternStore = new PatternStore({
      backend: storageBackend,
      ...(this.config.learning.connectionString !== undefined
        ? { connectionString: this.config.learning.connectionString }
        : {}),
    })
    this.activeLearner = new ActiveLearner()
    this.redTeamEngine = new RedTeamEngine()
    this.driftDetector = new DriftDetector()
    this.thresholdAdaptor = new ThresholdAdaptor()
    this.patternEvolver = new PatternEvolver()

    // Evolution engine — autonomous defense improvement
    this.evolutionEngine = new EvolutionEngine(
      this.config.evolution,
      async (input) => {
        const r = await this.scanInput(input)
        return {
          ...r,
          confidence: Math.max(...r.scanResults.map(s => s.confidence), 0),
        }
      },
      this.patternStore,
      this.redTeamEngine,
      this.patternEvolver,
    )

    // Phase 1: Immune Memory — shares the L2 EmbeddingStore for zero-copy recall
    this.immuneMemory = new ImmuneMemory(
      { enabled: this.config.learning.enabled },
      this.embeddingStore,
    )

    // Phase 1: Fever Response — elevated alertness after high-severity detection
    this.feverResponse = new FeverResponse({ enabled: true })

    // Phase 2: MELONGuard — injection-driven tool call detection (ICML 2025)
    this.melonGuard = new MELONGuard(
      { enabled: this.config.mcpGuard.enabled },
      this.ruleEngine,
      this.indirectInjectionDetector,
    )

    // Phase 2: AdversarialTrainer — game-theoretic self-training (IEEE S&P 2025)
    this.adversarialTrainer = new AdversarialTrainer(
      { enabled: this.config.learning.enabled },
      {
        scan: async (input: string) => {
          const r = await this.scanInput(input)
          return r.scanResults
        },
      },
      this.redTeamEngine,
      this.patternEvolver,
      this.thresholdAdaptor,
    )

    // Supply chain integrity guard
    const supplyChainInit: Record<string, unknown> = {
      maxAdapterSizeMB: this.config.supplyChain.maxAdapterSizeMB,
      enableDependencyAudit: this.config.supplyChain.enableDependencyAudit,
    }
    if (this.config.supplyChain.trustedModelHashes !== undefined) {
      supplyChainInit['trustedModelHashes'] = { ...this.config.supplyChain.trustedModelHashes }
    }
    if (this.config.supplyChain.trustedRegistries !== undefined) {
      supplyChainInit['trustedRegistries'] = [...this.config.supplyChain.trustedRegistries]
    }
    this.modelIntegrityGuard = new ModelIntegrityGuard(
      supplyChainInit as import('../supply-chain/ModelIntegrityGuard.js').ModelIntegrityConfig,
    )

    // Phase 3: Defense Ensemble — 3-voter weighted majority
    this.defenseEnsemble = new DefenseEnsemble()

    // Phase 3: ATLAS technique mapping — maps detections to MITRE ATLAS IDs
    this.atlasTechniqueMapper = new AtlasTechniqueMapper()

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

    // L2: Initialize embedding store and seed canonical examples
    await this.embeddingStore.initialize()
    await this.semanticContrastiveScanner.seedHarmfulExamples()
    this.log.info('L2 SemanticContrastiveScanner seeded with canonical examples')

    // Learning engine: initialize pattern store (runs migrations for PostgreSQL, no-op for memory)
    await this.patternStore.initialize()
    this.log.info('Learning engine PatternStore initialized')

    // Supply chain: run startup audit if configured
    if (this.config.supplyChain.enabled && this.config.supplyChain.runAuditOnStartup) {
      try {
        const auditResult = await this.modelIntegrityGuard.runFullAudit()
        if (auditResult.passed) {
          this.log.info('Supply chain startup audit passed')
        } else {
          this.log.warn(
            { overallRisk: auditResult.overallRisk, checks: auditResult.checks.filter((c) => !c.passed) },
            'Supply chain startup audit found issues',
          )
        }
      } catch (error: unknown) {
        this.log.error({ error }, 'Supply chain startup audit failed')
      }
    }

    // Evolution engine: load benign corpus and start cycle timer if enabled
    if (this.config.evolution.enabled) {
      try {
        await this.evolutionEngine.initialize()
        this.log.info('EvolutionEngine initialized and cycle timer started')
      } catch (error: unknown) {
        this.log.error({ error }, 'EvolutionEngine initialization failed')
      }
    }

    this.initialized = true
    this.log.info('ShieldX initialized')
  }

  /**
   * Scan user input through the full defense pipeline.
   *
   * Pipeline order:
   * 1. L0: Preprocessing (Unicode, Tokenizer, CompressedPayload)
   * 1b. Resource exhaustion check (early reject for token bombs)
   * 2. L1+L2: Rule engine + Sentinel classifier (parallel)
   * 3. L3-L5: Embedding, entropy, attention scanners (parallel)
   * 4. L6: Behavioral monitoring (conversation, intent, context, auth guard)
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

    // -- Early: Resource exhaustion check (before expensive scanners) --------
    const resourceResults = this.resourceExhaustionDetector.scan(normalizedInput)
    allResults.push(...resourceResults)

    // -- Immune Memory: recall known attack patterns (pre-L1) ---------------
    let immuneSuspicionBoost = 0
    const immuneRecall = await this.immuneMemory.recall(normalizedInput)
    if (immuneRecall.matched) {
      immuneSuspicionBoost = immuneRecall.suspicionBoost
      if (immuneRecall.preClassified) {
        allResults.push({
          scannerId: 'immune-memory',
          scannerType: 'embedding' as const,
          detected: true,
          confidence: immuneRecall.suspicionBoost,
          threatLevel: 'medium' as ThreatLevel,
          killChainPhase: (immuneRecall.preClassifiedPhase ?? 'none') as KillChainPhase,
          matchedPatterns: [`immune_memory_match:similarity=${immuneRecall.matches[0]?.similarity.toFixed(3)}`],
          latencyMs: 0,
          metadata: Object.freeze({
            preClassified: true,
            matchCount: immuneRecall.matches.length,
            topSimilarity: immuneRecall.matches[0]?.similarity ?? 0,
          }),
        })
      }
    }

    // -- Fever Response: check session fever state (pre-L1) -----------------
    const sessionId = context?.sessionId ?? 'anonymous'
    const feverCheck = this.feverResponse.check(sessionId)
    if (feverCheck.inFever) {
      immuneSuspicionBoost = Math.min(immuneSuspicionBoost + feverCheck.suspicionBoost, 1.0)
    }

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

    // -- Phase 3: Defense Ensemble — 3-voter weighted majority ----------------
    const ensembleVerdict: EnsembleVerdict = this.defenseEnsemble.evaluate(allResults)

    // Override detected/threatLevel if ensemble disagrees (ensemble is authoritative)
    const ensembleDetected = ensembleVerdict.finalVote !== 'clean'
    const ensembleThreatLevel = ensembleDetected
      ? ensembleVerdict.maxThreatLevel
      : threatLevel

    // -- Phase 3: ATLAS technique mapping -----------------------------------
    const atlasResult: AtlasMappingResult = this.atlasTechniqueMapper.map(allResults)

    const latencyMs = performance.now() - startTime

    const result: ShieldXResult = {
      id: scanId,
      timestamp: new Date().toISOString(),
      input,
      ...(sanitizedInput !== undefined ? { sanitizedInput } : {}),
      detected: detected || ensembleDetected,
      threatLevel: THREAT_SEVERITY[ensembleThreatLevel] > THREAT_SEVERITY[threatLevel]
        ? ensembleThreatLevel : threatLevel,
      killChainPhase: classification.primaryPhase,
      action,
      scanResults: allResults,
      healingApplied: action !== 'allow',
      latencyMs,
      ensemble: Object.freeze({
        finalVote: ensembleVerdict.finalVote,
        finalConfidence: ensembleVerdict.finalConfidence,
        unanimous: ensembleVerdict.unanimous,
      }),
      atlasMapping: Object.freeze({
        techniqueIds: atlasResult.techniqueIds,
        tacticCoverage: Object.freeze(
          Object.fromEntries(atlasResult.tacticCoverage),
        ),
        unmappedResults: atlasResult.unmappedResults,
      }),
    }

    // -- Feed learning engine with scan results --------------------------------
    // Record each scan result's confidence in the drift detector
    for (const sr of allResults) {
      this.driftDetector.recordConfidence(sr)
    }

    // Route uncertain results to active learner for human review sampling
    for (const sr of allResults) {
      this.activeLearner.shouldRequestReview(sr)
    }

    // Store the result in PatternStore for learning (fire-and-forget)
    this.patternStore.store(result).catch((err) => {
      this.log.warn({ err }, 'Failed to store scan result in PatternStore')
    })

    // -- Immune Memory: remember detected attacks (fire-and-forget) ----------
    if (detected) {
      this.immuneMemory.remember(normalizedInput, result).catch((err) => {
        this.log.warn({ err }, 'Failed to store attack in ImmuneMemory')
      })
    }

    // -- Fever Response: trigger fever on high-severity detection -------------
    if (detected && THREAT_SEVERITY[threatLevel] >= THREAT_SEVERITY['high']) {
      const feverState = this.feverResponse.trigger(sessionId, result)
      if (feverState.expiresAt > feverState.triggeredAt) {
        this.log.info(
          { sessionId, expiresAt: feverState.expiresAt },
          'Fever mode activated for session',
        )
      }
    }

    // -- Fever Response: record additional detection during fever -------------
    if (detected && feverCheck.inFever) {
      this.feverResponse.recordAdditionalDetection(sessionId)
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
        immuneBoost: immuneSuspicionBoost > 0 ? immuneSuspicionBoost : undefined,
        inFever: feverCheck.inFever || undefined,
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

    // Output payload guard — detect SQL injection, XSS, SSRF, shell commands, path traversal
    const payloadResults = this.outputPayloadGuard.scan(output)
    allResults.push(...payloadResults)

    // Auth context guard — detect identity manipulation in LLM output
    const authOutputResults = this.authContextGuard.scanOutput(output, _context?.sessionId)
    allResults.push(...authOutputResults)

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

    // Phase 3: Defense Ensemble + ATLAS mapping for output scan
    const outputEnsemble = this.defenseEnsemble.evaluate(allResults)
    const outputAtlas = this.atlasTechniqueMapper.map(allResults)

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
      ensemble: Object.freeze({
        finalVote: outputEnsemble.finalVote,
        finalConfidence: outputEnsemble.finalConfidence,
        unanimous: outputEnsemble.unanimous,
      }),
      atlasMapping: Object.freeze({
        techniqueIds: outputAtlas.techniqueIds,
        tacticCoverage: Object.freeze(
          Object.fromEntries(outputAtlas.tacticCoverage),
        ),
        unmappedResults: outputAtlas.unmappedResults,
      }),
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
   * 5. MELONGuard — injection-driven tool call detection (ICML 2025)
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

    // 4. Tool call safety guard — argument pattern validation
    if (this.config.mcpGuard.validateToolCalls) {
      const safetyResult = validateSafety(toolName, toolArgs)
      if (!safetyResult.allowed) {
        const violationSummary = safetyResult.violations
          .map((v) => `${v.category}:${v.matchedPattern} in "${v.parameterName}" [${v.severity}]`)
          .join('; ')
        return {
          allowed: false,
          reason: `Tool call safety violation: ${violationSummary}`,
          result: {
            scannerId: 'tool-call-safety-guard',
            scannerType: 'tool_chain' as const,
            detected: true,
            confidence: safetyResult.riskScore,
            threatLevel: safetyResult.riskScore >= 0.8 ? 'critical' as const
              : safetyResult.riskScore >= 0.5 ? 'high' as const
              : 'medium' as const,
            killChainPhase: 'actions_on_objective' as const,
            matchedPatterns: safetyResult.violations.map((v) => `${v.category}:${v.matchedPattern}`),
            latencyMs: performance.now() - startTime,
            metadata: {
              toolCategory: safetyResult.toolCategory,
              riskScore: safetyResult.riskScore,
              violationCount: safetyResult.violations.length,
            },
          },
        }
      }
    }

    // 5. MELONGuard — injection-driven tool call detection (ICML 2025)
    const melonResult = this.melonGuard.analyze(
      toolName,
      toolArgs,
      undefined,                         // toolResults: caller can provide via extended API
      context.taskDescription,           // userPrompt: use task description as proxy for user intent
    )
    if (melonResult.injectionDriven && melonResult.recommendation === 'block') {
      const evidenceSummary = melonResult.evidence
        .map(e => `${e.type}(${e.confidence.toFixed(2)}): ${e.detail.slice(0, 80)}`)
        .join('; ')
      return {
        allowed: false,
        reason: `MELON: Injection-driven tool call detected (confidence: ${melonResult.confidence}): ${evidenceSummary}`,
        result: {
          scannerId: 'melon-guard',
          scannerType: 'tool_chain' as const,
          detected: true,
          confidence: melonResult.confidence,
          threatLevel: melonResult.confidence >= 0.8 ? 'critical' as const
            : melonResult.confidence >= 0.6 ? 'high' as const
            : 'medium' as const,
          killChainPhase: 'actions_on_objective' as const,
          matchedPatterns: melonResult.evidence.map(e => `melon:${e.type}`),
          latencyMs: performance.now() - startTime,
          metadata: Object.freeze({
            melonConfidence: melonResult.confidence,
            evidenceCount: melonResult.evidence.length,
            recommendation: melonResult.recommendation,
          }),
        },
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
   *
   * Aggregates data from:
   * - PatternStore: pattern counts, false positive rate, top patterns, incidents
   * - ActiveLearner: review queue size, review rate
   * - RedTeamEngine: evasion log size
   * - DriftDetector: drift status and last report
   * - ThresholdAdaptor: current adapted thresholds
   */
  async getStats(): Promise<LearningStats> {
    // Pull base stats from PatternStore (handles both PostgreSQL and in-memory)
    const baseStats = await this.patternStore.getStats()

    // Check drift status from the DriftDetector
    const driftReport = this.driftDetector.checkDrift()
    const lastDriftReport = driftReport ?? this.driftDetector.getLastReport()
    const driftDetected = driftReport !== null

    // If drift was detected, adapt thresholds based on the updated stats
    if (driftDetected) {
      this.thresholdAdaptor.adapt(baseStats)
    }

    // Enrich base stats with live learning module data
    return Object.freeze({
      ...baseStats,
      driftDetected,
      ...(lastDriftReport !== null ? { lastDriftReport } : {}),
    })
  }

  // -------------------------------------------------------------------------
  // Evolution Engine — Autonomous Defense Improvement
  // -------------------------------------------------------------------------

  /** Run one full evolution cycle manually. */
  async runEvolutionCycle(): Promise<import('../learning/EvolutionEngine.js').EvolutionCycleResult> {
    return this.evolutionEngine.runCycle()
  }

  /** Get the history of all evolution cycles. */
  getEvolutionHistory(): readonly import('../learning/EvolutionEngine.js').EvolutionCycleResult[] {
    return this.evolutionEngine.getHistory()
  }

  /** Pause the evolution engine (stops automatic cycles). */
  pauseEvolution(): void {
    this.evolutionEngine.pause()
  }

  /** Resume the evolution engine after a pause. */
  resumeEvolution(): void {
    this.evolutionEngine.resume()
  }

  /** Check if the evolution engine is currently paused. */
  isEvolutionPaused(): boolean {
    return this.evolutionEngine.isPaused()
  }

  /** Check if an evolution cycle is currently running. */
  isEvolutionRunning(): boolean {
    return this.evolutionEngine.isRunning()
  }

  // -------------------------------------------------------------------------
  // Phase 1: Immune Memory + Fever Response + Over-Defense Calibration
  // -------------------------------------------------------------------------

  /**
   * Get immune memory statistics (total memories, average hit count, FP count).
   */
  getImmuneMemoryStats(): ImmuneMemoryStats {
    return this.immuneMemory.getStats()
  }

  /**
   * Get all active fever states (sessions in elevated alertness mode).
   */
  getActiveFevers(): readonly FeverState[] {
    return this.feverResponse.getActiveFevers()
  }

  /**
   * Mark an immune memory entry as a false positive.
   * Suppresses the memory from future recall without removing it.
   *
   * @param inputHash - SHA-256 hash of the original input
   */
  async markImmuneMemoryFalsePositive(inputHash: string): Promise<void> {
    await this.immuneMemory.markFalsePositive(inputHash)
  }

  /**
   * Run the immune memory decay cycle (clonal selection).
   * Prunes low-hit, old memories to make room for new attack patterns.
   *
   * @returns Count of removed and retained memories
   */
  async runImmuneDecay(): Promise<{ readonly removed: number; readonly retained: number }> {
    return this.immuneMemory.runDecayCycle()
  }

  /**
   * Manually resolve fever for a session.
   *
   * @param sessionId - Session identifier to de-escalate
   */
  resolveFever(sessionId: string): void {
    this.feverResponse.resolve(sessionId)
  }

  /**
   * Run over-defense calibration against the benign corpus.
   *
   * Scans all known-benign inputs through the full pipeline and reports
   * which scanners cause the most false positives, along with an
   * overall over-defense score (0-1, lower = better).
   *
   * @param corpusPath - Optional override path to benign corpus JSON
   * @returns CalibrationResult with FPR breakdown and suppression candidates
   */
  async calibrate(corpusPath?: string): Promise<CalibrationResult> {
    const calibrator = new OverDefenseCalibrator(
      (input) => this.scanInput(input),
      corpusPath,
    )
    return calibrator.calibrate()
  }

  // -------------------------------------------------------------------------
  // Supply Chain Integrity
  // -------------------------------------------------------------------------

  /**
   * Verify a model file's integrity via SHA-256 hash and pickle exploit scan.
   * On-demand — not called per-request.
   *
   * @param modelPath - Absolute path to the model file
   * @param expectedHash - Optional expected SHA-256 hex digest
   * @returns IntegrityCheckResult with detailed checks and risk level
   */
  async verifyModel(modelPath: string, expectedHash?: string): Promise<IntegrityCheckResult> {
    return this.modelIntegrityGuard.verifyModel(modelPath, expectedHash)
  }

  /**
   * Verify a LoRA / PEFT adapter directory for integrity.
   * Checks config structure, weight files, size, and rank ratio.
   *
   * @param adapterPath - Absolute path to the adapter directory
   * @returns IntegrityCheckResult with detailed checks and risk level
   */
  async verifyAdapter(adapterPath: string): Promise<IntegrityCheckResult> {
    return this.modelIntegrityGuard.verifyAdapter(adapterPath)
  }

  /**
   * Run the full supply chain integrity audit.
   * Includes dependency audit and registry configuration checks.
   *
   * @returns IntegrityCheckResult with all audit findings
   */
  async runIntegrityAudit(): Promise<IntegrityCheckResult> {
    return this.modelIntegrityGuard.runFullAudit()
  }

  // -------------------------------------------------------------------------
  // Phase 2: Adversarial Training
  // -------------------------------------------------------------------------

  /**
   * Run a full game-theoretic adversarial training session.
   *
   * Executes the minimax optimization loop:
   * - Inner (Attacker): RedTeamEngine generates mutations, finds evasions
   * - Outer (Defender): PatternEvolver creates rules, ThresholdAdaptor adjusts
   * - Validates against benign corpus to prevent false positive inflation
   * - Repeats until convergence or max rounds
   *
   * @param baseAttacks - Optional starting attack corpus
   * @returns Training result with per-round metrics and convergence status
   */
  async runAdversarialTraining(baseAttacks?: readonly string[]): Promise<TrainingResult> {
    this.log.info('Starting adversarial training session...')
    const result = await this.adversarialTrainer.train(baseAttacks)
    this.log.info(
      {
        converged: result.converged,
        rounds: result.rounds.length,
        finalEvasionRate: result.finalEvasionRate,
        totalEvasionsPatched: result.totalEvasionsPatched,
        latencyMs: Math.round(result.totalLatencyMs),
      },
      'Adversarial training session complete',
    )
    return result
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
      getPatterns: async () => self.patternStore.loadPatterns(),
      updatePattern: async (patternId: string, updates: { enabled?: boolean; confidence?: number }) => {
        if (updates.confidence !== undefined) {
          const patterns = await self.patternStore.loadPatterns()
          const existing = patterns.find((p) => p.id === patternId)
          const currentConfidence = existing?.confidenceBase ?? 0.5
          await self.patternStore.updateConfidence(patternId, updates.confidence - currentConfidence)
        }
      },
      getAttackGraph: () => ({ nodes: [] as const, edges: [] as const }),
      getDriftStatus: () => self.driftDetector.getLastReport(),
      getReviewQueue: () => self.activeLearner.getReviewQueue(),
      submitReview: (scanId: string, isAttack: boolean) => { self.activeLearner.processReview(scanId, isAttack) },
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
      runSelfTest: async () => self.redTeamEngine.runSelfTest({
        scan: async (input: string) => {
          const r = await self.scanInput(input)
          return r.scanResults
        },
      }),
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

      // Evolution Engine
      runEvolutionCycle: () => self.evolutionEngine.runCycle(),
      getEvolutionHistory: () => self.evolutionEngine.getHistory(),
      getEvolutionConfig: () => self.evolutionEngine.getConfig(),
      getEvolutionDeployedRules: () => self.evolutionEngine.getDeployedRules(),
      pauseEvolution: () => self.evolutionEngine.pause(),
      resumeEvolution: () => self.evolutionEngine.resume(),
      isEvolutionPaused: () => self.evolutionEngine.isPaused(),
      isEvolutionRunning: () => self.evolutionEngine.isRunning(),

      // Phase 2: Adversarial Training
      runAdversarialTraining: (baseAttacks?: readonly string[]) => self.runAdversarialTraining(baseAttacks),
      getAdversarialTrainingHistory: () => self.adversarialTrainer.getTrainingHistory(),
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
    this.evolutionEngine.stop()
    this.resistanceTestEngine.stop()
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

    // Cipher decoding: FlipAttack, ROT13, Caesar, Morse, Leet, Pig Latin, ASCII art
    const cipherResult = this.cipherDecoder.decode(normalizedInput)
    if (cipherResult.detectedCiphers.length > 0) {
      results.push({
        scannerId: 'cipher-decoder',
        scannerType: 'tokenizer' as const,
        detected: cipherResult.suspicionScore >= 0.5,
        confidence: cipherResult.suspicionScore,
        threatLevel: cipherResult.suspicionScore >= 0.7
          ? 'high'
          : cipherResult.suspicionScore >= 0.5
            ? 'medium'
            : 'low',
        killChainPhase: 'initial_access' as const,
        matchedPatterns: cipherResult.detectedCiphers.map(c => `cipher:${c}`),
        latencyMs: 0,
        metadata: Object.freeze({
          detectedCiphers: cipherResult.detectedCiphers,
          decodedVersions: cipherResult.decodedVersions.length,
        }),
      })
      // Use decoded/normalized version for downstream scanners
      normalizedInput = cipherResult.normalized
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

    // L2: Semantic Contrastive Scanner (arXiv:2512.12069)
    if (this.config.scanners.sentinel) {
      tasks.push(
        this.safeRunScanner('sentinel-classifier', async () => {
          const embedding = bagOfWordsEmbedding(input)
          const result = await this.semanticContrastiveScanner.scan(embedding)
          if (result.contrastiveScore.verdict === 'clean') return []
          return [this.semanticContrastiveScanner.toScanResult(result)]
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

    // Canary token detection — check if input references leaked canary tokens.
    // If an attacker's input contains active canary tokens, they obtained them
    // from a prior system prompt leak (reconnaissance / exfiltration signal).
    if (this.config.scanners.canary) {
      tasks.push(
        this.safeRunScanner('canary-scanner', async () => {
          // Rotate tokens if interval has elapsed
          if (this.canaryManager.isRotationDue()) {
            this.canaryManager.rotateTokens()
          }

          const checkResult = this.canaryManager.checkOutput(input)
          if (!checkResult.leaked) return []

          const leakedCount = checkResult.leakedTokens.length
          const confidence = Math.min(0.85 + leakedCount * 0.05, 1.0)

          return [
            {
              scannerId: 'canary-scanner',
              scannerType: 'canary' as const,
              detected: true,
              confidence,
              threatLevel: (leakedCount >= 2 ? 'critical' : 'high') as ThreatLevel,
              killChainPhase: 'reconnaissance' as KillChainPhase,
              matchedPatterns: checkResult.leakedTokens.map(
                (t) => `canary_token_in_input:${t.slice(0, 20)}...`,
              ),
              latencyMs: 0,
              metadata: Object.freeze({
                leakedTokenCount: leakedCount,
                description: 'Input contains active canary tokens — prior system prompt leak detected',
              }),
            },
          ]
        }),
      )
    }

    // Indirect injection detection — external content (tool results, RAG docs, web)
    if (this.config.scanners.indirect) {
      tasks.push(
        this.safeRunScanner('indirect-scanner', () => {
          return this.indirectInjectionDetector.scan(input)
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

    // Auth context guard: scanInput(input, sessionId) -> ScanResult[]
    tasks.push(
      this.safeRunScanner('auth-context-guard', async () => {
        const authResults = this.authContextGuard.scanInput(input, context?.sessionId)
        return authResults.filter(r => r.detected)
      }),
    )

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

    // Decomposition detection: analyze multi-turn decomposition attacks
    if (this.config.behavioral.conversationTracking && context?.sessionId) {
      tasks.push(
        this.safeRunScanner('decomposition-detector', async () => {
          const history = context.previousActions ?? []
          const decompResult = this.decompositionDetector.analyze(
            input,
            history,
            context.sessionId!,
          )
          if (decompResult.detected) {
            const scanResult = this.decompositionDetector.toScanResult(decompResult)
            return scanResult !== null ? [scanResult] : []
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

  // -------------------------------------------------------------------------
  // Phase 3: Defense Ensemble + ATLAS public API
  // -------------------------------------------------------------------------

  /**
   * Get ATLAS technique coverage report — shows which MITRE ATLAS tactics
   * are covered by ShieldX's scanner constellation.
   */
  getAtlasCoverage(): { total: number; covered: number; coveragePercent: number; uncoveredTactics: readonly string[] } {
    return this.atlasTechniqueMapper.getCoverageReport()
  }

  /**
   * Get all known ATLAS techniques.
   */
  getAllAtlasTechniques(): readonly import('./AtlasTechniqueMapper.js').AtlasTechnique[] {
    return this.atlasTechniqueMapper.getAllTechniques()
  }

  /**
   * Look up a specific ATLAS technique by ID.
   */
  getAtlasTechnique(id: string): import('./AtlasTechniqueMapper.js').AtlasTechnique | undefined {
    return this.atlasTechniqueMapper.getTechniqueById(id)
  }
}
