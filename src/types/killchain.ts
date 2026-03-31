/**
 * Kill chain mapping types (Schneier et al. 2026 Promptware Kill Chain).
 */

import type { KillChainPhase, ThreatLevel } from './detection.js'

/** Detailed description of a kill chain phase */
export interface KillChainPhaseDetail {
  readonly phase: KillChainPhase
  readonly name: string
  readonly description: string
  readonly indicators: readonly string[]
  readonly rulePatterns: readonly string[]
  readonly defaultSeverity: ThreatLevel
  readonly mitigations: readonly string[]
}

/** Result of kill chain classification */
export interface KillChainClassification {
  readonly primaryPhase: KillChainPhase
  readonly confidence: number
  readonly allPhases: readonly KillChainMapping[]
  readonly isMultiPhase: boolean
  readonly attackChainDescription: string
}

/** Mapping of a scan result to a kill chain phase */
export interface KillChainMapping {
  readonly phase: KillChainPhase
  readonly confidence: number
  readonly matchedRuleIds: readonly string[]
  readonly scannerSources: readonly string[]
}
