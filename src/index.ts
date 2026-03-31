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

// Types — re-export everything
export type * from './types/index.js'
export type * from './types/dashboard.js'
