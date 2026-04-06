/**
 * @module @shieldx/core/supply-chain
 * ML model supply chain security — hash verification,
 * pickle exploit scanning, provenance checking, and
 * unified integrity orchestration.
 */

export { SupplyChainVerifier } from './SupplyChainVerifier.js'
export { ModelProvenanceChecker } from './ModelProvenanceChecker.js'
export { ModelIntegrityGuard } from './ModelIntegrityGuard.js'
export type {
  ModelIntegrityConfig,
  IntegrityCheck,
  IntegrityCheckResult,
  DependencyAuditFinding,
  DependencyAuditScanner,
} from './ModelIntegrityGuard.js'
