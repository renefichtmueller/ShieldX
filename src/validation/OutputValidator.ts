/**
 * LLM output safety validation.
 * Orchestrates canary checking, leakage detection, scope validation,
 * role integrity, and schema-bounded output enforcement (FIDES).
 */

import type { ScanResult, ThreatLevel, KillChainPhase } from '../types/detection.js'

import { CanaryManager } from './CanaryManager.js'
import { LeakageDetector } from './LeakageDetector.js'
import { ScopeValidator } from './ScopeValidator.js'
import { RoleIntegrityChecker } from './RoleIntegrityChecker.js'

/** Context provided for output validation */
interface ValidationContext {
  readonly canaryToken?: string
  readonly originalInput?: string
  readonly taskScope?: string
  readonly expectedRole?: string
  readonly outputType?: 'boolean' | 'enum' | 'short_string' | 'full_string'
}

/**
 * OutputValidator — validates LLM output safety.
 *
 * Combines multiple checks:
 * 1. Canary token leakage detection
 * 2. System prompt leakage pattern matching
 * 3. Task scope adherence
 * 4. Role integrity verification
 * 5. Schema-bounded output enforcement (FIDES: constrained types get higher trust)
 */
export class OutputValidator {
  private readonly canaryManager: CanaryManager
  private readonly leakageDetector: LeakageDetector
  private readonly scopeValidator: ScopeValidator
  private readonly roleChecker: RoleIntegrityChecker

  constructor(canaryManager?: CanaryManager) {
    this.canaryManager = canaryManager ?? new CanaryManager()
    this.leakageDetector = new LeakageDetector()
    this.scopeValidator = new ScopeValidator()
    this.roleChecker = new RoleIntegrityChecker()
  }

  /**
   * Validate an LLM output for safety issues.
   * @param output - The raw LLM output text
   * @param context - Optional context for canary, scope, and role checks
   * @returns Scan result with combined confidence and matched patterns
   */
  async validate(output: string, context?: ValidationContext): Promise<ScanResult> {
    const startTime = performance.now()
    const patterns: string[] = []
    let maxConfidence = 0
    let detectedPhase: KillChainPhase = 'none'

    // 1. Canary token check
    if (context?.canaryToken !== undefined) {
      const canaryResult = this.canaryManager.checkOutput(output, [context.canaryToken])
      if (canaryResult.leaked) {
        patterns.push('canary-token-leaked')
        maxConfidence = Math.max(maxConfidence, 0.95)
        detectedPhase = 'actions_on_objective'
      }
    }

    // Also check all active tokens
    const activeTokenCheck = this.canaryManager.checkOutput(output)
    if (activeTokenCheck.leaked) {
      patterns.push('active-canary-leaked')
      maxConfidence = Math.max(maxConfidence, 0.95)
      detectedPhase = 'actions_on_objective'
    }

    // 2. System prompt leakage
    const leakageResult = this.leakageDetector.detect(output)
    if (leakageResult.leaked) {
      patterns.push(...leakageResult.indicators.map((i) => `leakage:${i}`))
      maxConfidence = Math.max(maxConfidence, leakageResult.confidence)
      if (detectedPhase === 'none') {
        detectedPhase = 'reconnaissance'
      }
    }

    // 3. Scope validation
    if (context?.taskScope !== undefined) {
      const scopeResult = this.scopeValidator.validate(output, context.taskScope)
      if (!scopeResult.inScope) {
        patterns.push(`scope-deviation:${scopeResult.deviationScore}`)
        maxConfidence = Math.max(maxConfidence, scopeResult.deviationScore * 0.8)
      }
    }

    // 4. Role integrity
    const expectedRole = context?.expectedRole ?? 'assistant'
    const roleResult = this.roleChecker.check(output, expectedRole)
    if (!roleResult.intact) {
      patterns.push(`role-violation:${roleResult.detectedRole ?? 'unknown'}`)
      maxConfidence = Math.max(maxConfidence, 0.85)
      if (detectedPhase === 'none') {
        detectedPhase = 'privilege_escalation'
      }
    }

    // 5. FIDES schema-bounded output enforcement
    const fidesAdjustment = computeFidesAdjustment(output, context?.outputType)
    maxConfidence = Math.max(0, maxConfidence - fidesAdjustment)

    const detected = patterns.length > 0
    const confidence = Math.round(maxConfidence * 1000) / 1000
    const latencyMs = Math.round((performance.now() - startTime) * 100) / 100

    return Object.freeze({
      scannerId: 'output-validator',
      scannerType: 'canary' as const,
      detected,
      confidence,
      threatLevel: confidenceToThreat(confidence),
      killChainPhase: detectedPhase,
      matchedPatterns: Object.freeze([...patterns]),
      latencyMs,
      metadata: Object.freeze({
        canaryChecked: context?.canaryToken !== undefined || activeTokenCheck.leaked,
        leakageChecked: true,
        scopeChecked: context?.taskScope !== undefined,
        roleChecked: true,
        fidesOutputType: context?.outputType ?? 'full_string',
        fidesAdjustment,
      }),
    })
  }
}

/**
 * FIDES (Microsoft) schema-bounded output enforcement.
 * Constrained output types (boolean, enum) are inherently safer
 * and receive a confidence reduction (trust bonus).
 */
function computeFidesAdjustment(
  output: string,
  outputType?: 'boolean' | 'enum' | 'short_string' | 'full_string',
): number {
  switch (outputType) {
    case 'boolean': {
      const trimmed = output.trim().toLowerCase()
      if (trimmed === 'true' || trimmed === 'false' || trimmed === 'yes' || trimmed === 'no') {
        return 0.3 // High trust reduction for valid boolean
      }
      return 0 // Output doesn't match expected type — no adjustment
    }
    case 'enum':
      return output.trim().length < 50 ? 0.2 : 0
    case 'short_string':
      return output.trim().length < 200 ? 0.1 : 0
    case 'full_string':
    default:
      return 0 // No adjustment for free text
  }
}

/** Map confidence to threat level */
function confidenceToThreat(confidence: number): ThreatLevel {
  if (confidence >= 0.9) return 'critical'
  if (confidence >= 0.7) return 'high'
  if (confidence >= 0.5) return 'medium'
  if (confidence >= 0.3) return 'low'
  return 'none'
}
