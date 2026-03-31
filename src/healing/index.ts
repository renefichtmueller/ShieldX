/**
 * Healing subsystem — Self-repair and incident response for ShieldX.
 *
 * Exports the full healing pipeline: orchestrator, session management,
 * prompt reconstruction, fallback generation, and incident reporting.
 */

// Core orchestrator
export { HealingOrchestrator } from './HealingOrchestrator.js'

// Session management
export { SessionManager } from './SessionManager.js'
export type { SessionManagerConfig, MemoryZone, MemoryEntry } from './SessionManager.js'

// Prompt reconstruction
export { PromptReconstructor } from './PromptReconstructor.js'
export type { ReconstructionResult } from './PromptReconstructor.js'

// Fallback response generation
export { FallbackResponder } from './FallbackResponder.js'

// Incident reporting
export { IncidentReporter } from './IncidentReporter.js'
export type { IncidentReporterConfig } from './IncidentReporter.js'

// Phase strategies
export { executePhase1, PHASE1_STRATEGY } from './strategies/phase1.strategy.js'
export { executePhase2, PHASE2_STRATEGY } from './strategies/phase2.strategy.js'
export { executePhase3, PHASE3_STRATEGY } from './strategies/phase3.strategy.js'
export { executePhase4, PHASE4_STRATEGY } from './strategies/phase4.strategy.js'
export { executePhase5, PHASE5_STRATEGY } from './strategies/phase5.strategy.js'
export { executePhase6, PHASE6_STRATEGY } from './strategies/phase6.strategy.js'
export { executePhase7, PHASE7_STRATEGY } from './strategies/phase7.strategy.js'
