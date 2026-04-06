/**
 * @module @shieldx/core/learning
 * Self-evolution engine — pattern storage, feedback processing,
 * drift detection, attack graph, red team, active learning,
 * federated sync, and conversation learning.
 */

export { PatternStore } from './PatternStore.js'
export { EmbeddingStore } from './EmbeddingStore.js'
export { FeedbackProcessor } from './FeedbackProcessor.js'
export { ThresholdAdaptor } from './ThresholdAdaptor.js'
export { PatternEvolver } from './PatternEvolver.js'
export { RedTeamEngine } from './RedTeamEngine.js'
export { DriftDetector } from './DriftDetector.js'
export { AttackGraph } from './AttackGraph.js'
export { ActiveLearner } from './ActiveLearner.js'
export { FederatedSync } from './FederatedSync.js'
export { ConversationLearner } from './ConversationLearner.js'
export { EvolutionEngine } from './EvolutionEngine.js'
export { ImmuneMemory } from './ImmuneMemory.js'
export type { ImmuneMemoryConfig, MemoryMatch, ImmuneMemoryResult, ImmuneMemoryStats } from './ImmuneMemory.js'
export { OverDefenseCalibrator } from './OverDefenseCalibrator.js'
export type { CalibrationResult } from './OverDefenseCalibrator.js'
export type {
  EvolutionConfig,
  EvolutionCycleResult,
  EvolutionMetrics,
  ProbeOutcome,
  GapReport,
  CandidateRule,
  ValidationResult,
  DeployedRule,
} from './EvolutionEngine.js'

// Adversarial training — game-theoretic self-training (IEEE S&P 2025-inspired)
export { AdversarialTrainer } from './AdversarialTrainer.js'
export type {
  AdversarialConfig,
  TrainingRound,
  TrainingResult,
} from './AdversarialTrainer.js'
