/**
 * @module @shieldx/core/validation
 * Output validation layer — canary tokens, leakage detection,
 * scope validation, role integrity, intent guard, and RAG defense.
 */

export { OutputValidator } from './OutputValidator.js'
export { CanaryManager } from './CanaryManager.js'
export { ScopeValidator } from './ScopeValidator.js'
export { LeakageDetector } from './LeakageDetector.js'
export { RoleIntegrityChecker } from './RoleIntegrityChecker.js'
export { IntentGuardValidator } from './IntentGuardValidator.js'
export { RAGShield } from './RAGShield.js'
