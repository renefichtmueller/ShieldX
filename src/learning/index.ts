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
