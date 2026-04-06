/**
 * @module @shieldx/core/behavioral
 * Layer 6 — Behavioral Monitoring.
 *
 * Runtime behavioral analysis for multi-turn conversations,
 * intent monitoring, context integrity, memory integrity,
 * anomaly detection, trust tagging, and session profiling.
 */

// P0: Intent monitoring with Bayesian trust scoring
export {
  createSession,
  check,
  validateToolCall,
  getSessionProfile,
  updateTrustScore,
  getAdversarialProbability,
  destroySession,
} from './IntentMonitor.js'

// P0: Multi-turn conversation tracking
export {
  addTurn,
  getState,
  scan,
  detectEscalation,
  reset,
} from './ConversationTracker.js'

// P1: Context window integrity
export {
  addContent,
  checkIntegrity,
  getPartitions,
  detectContradictions,
  clearContext,
} from './ContextIntegrity.js'

// P0: Memory integrity guard (HMAC-signed entries)
export {
  writeMemory,
  readMemory,
  verifyIntegrity,
  quarantineEntry,
  auditAllEntries,
  clearSessionMemory,
} from './MemoryIntegrityGuard.js'

// Anomaly detection (Z-score statistical analysis)
export {
  detectAnomaly,
  detectSessionAnomaly,
  recordMetric,
  clearSessionMetrics,
} from './AnomalyDetector.js'

// Tool call validation
export { validate as validateToolCallDirect } from './ToolCallValidator.js'

// Context drift detection
export {
  measureDrift,
  isHijacked,
} from './ContextDriftDetector.js'

// Session behavioral profiling
export {
  buildProfile,
  updateProfile,
  compareToBaseline,
  getProfile,
  removeProfile,
  simpleEmbedding,
} from './SessionProfiler.js'

// CaMeL-inspired trust tagging
export {
  tag,
  getPolicy,
  checkViolation,
  getTrustRank,
  canFlowTo,
} from './TrustTagger.js'

// Auth context manipulation guard
export { AuthContextGuard } from './AuthContextGuard.js'

// Enhanced multi-turn decomposition detection
export { DecompositionDetector } from './DecompositionDetector.js'
export type {
  DecompositionTechnique,
  DecompositionResult,
} from './DecompositionDetector.js'
