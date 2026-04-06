/**
 * @shieldx/core — Self-Evolving LLM Prompt Injection Defense
 *
 * 10-layer defense pipeline with kill chain mapping,
 * self-healing, and self-learning capabilities.
 *
 * @example
 * ```typescript
 * import { ShieldX } from '@shieldx/core'
 *
 * const shield = new ShieldX({
 *   learning: { storageBackend: 'postgresql', connectionString: process.env.DATABASE_URL }
 * })
 * await shield.initialize()
 *
 * const result = await shield.scanInput('user message here')
 * if (result.detected) {
 *   console.log(`Threat: ${result.threatLevel}, Phase: ${result.killChainPhase}`)
 * }
 * ```
 *
 * @packageDocumentation
 */

// Core
export { ShieldX } from './core/ShieldX.js'
export { defaultConfig, mergeConfig } from './core/config.js'
export { createLogger } from './core/logger.js'
export { RateLimiter } from './core/RateLimiter.js'
export type { RateLimiterConfig, RateLimitResult } from './core/RateLimiter.js'

// Sanitization — standalone guards
export { OutputPayloadGuard } from './sanitization/OutputPayloadGuard.js'

// Supply chain integrity
export { ModelIntegrityGuard } from './supply-chain/ModelIntegrityGuard.js'
export type {
  ModelIntegrityConfig,
  IntegrityCheck,
  IntegrityCheckResult,
  DependencyAuditFinding,
  DependencyAuditScanner,
} from './supply-chain/ModelIntegrityGuard.js'

// Evolution engine
export { EvolutionEngine } from './learning/EvolutionEngine.js'
export type {
  EvolutionConfig,
  EvolutionCycleResult,
  EvolutionMetrics,
  ProbeOutcome,
  GapReport,
  CandidateRule,
  ValidationResult,
  DeployedRule,
} from './learning/EvolutionEngine.js'

// Phase 1: Immune Memory + Fever Response + Over-Defense Calibration
export { ImmuneMemory } from './learning/ImmuneMemory.js'
export type { ImmuneMemoryConfig, MemoryMatch, ImmuneMemoryResult, ImmuneMemoryStats } from './learning/ImmuneMemory.js'
export { FeverResponse } from './core/FeverResponse.js'
export type { FeverConfig, FeverState, FeverCheck } from './core/FeverResponse.js'
export { OverDefenseCalibrator } from './learning/OverDefenseCalibrator.js'
export type { CalibrationResult } from './learning/OverDefenseCalibrator.js'

// Phase 2: MELONGuard + AdversarialTrainer + DecompositionDetector
export { MELONGuard } from './mcp-guard/MELONGuard.js'
export type { MELONConfig, MELONEvidence, MELONResult } from './mcp-guard/MELONGuard.js'
export { AdversarialTrainer } from './learning/AdversarialTrainer.js'
export type { AdversarialConfig, TrainingRound, TrainingResult } from './learning/AdversarialTrainer.js'
export { DecompositionDetector } from './behavioral/DecompositionDetector.js'
export type { DecompositionTechnique, DecompositionResult } from './behavioral/DecompositionDetector.js'

// Phase 3: Defense Ensemble + ATLAS Technique Mapper
export { DefenseEnsemble } from './core/DefenseEnsemble.js'
export type { VoterVerdict, EnsembleVerdict } from './core/DefenseEnsemble.js'
export { AtlasTechniqueMapper } from './core/AtlasTechniqueMapper.js'
export type { AtlasTechnique, AtlasMapping, AtlasMappingResult } from './core/AtlasTechniqueMapper.js'

// Types — re-export everything
export type * from './types/index.js'
export type * from './types/dashboard.js'
