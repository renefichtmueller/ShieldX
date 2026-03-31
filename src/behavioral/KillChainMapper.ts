/**
 * Kill Chain Mapper — Maps scan results to Schneier 2026 Promptware Kill Chain phases.
 *
 * Classifies detected threats into a 7-phase attack lifecycle,
 * enabling phase-aware healing responses and multi-phase attack detection.
 */

import type { KillChainPhase, ScanResult, ThreatLevel } from '../types/detection.js'
import type {
  KillChainClassification,
  KillChainMapping,
  KillChainPhaseDetail,
} from '../types/killchain.js'

/**
 * Priority-ordered kill chain phases (highest severity first).
 * Used to determine the primary phase when multiple phases are detected.
 */
const PHASE_PRIORITY: readonly KillChainPhase[] = [
  'actions_on_objective',
  'lateral_movement',
  'command_and_control',
  'persistence',
  'privilege_escalation',
  'reconnaissance',
  'initial_access',
] as const

/**
 * Full kill chain phase definitions with indicators, rule patterns, and mitigations.
 */
export const KILL_CHAIN_PHASES: Readonly<Record<Exclude<KillChainPhase, 'none'>, KillChainPhaseDetail>> = {
  initial_access: {
    phase: 'initial_access',
    name: 'Initial Access',
    description: 'Attacker gains initial foothold via prompt injection, encoding tricks, or input obfuscation.',
    indicators: [
      'Direct injection patterns in user input',
      'Unicode homoglyph substitution',
      'Tokenizer exploitation attempts',
      'Delimiter confusion attacks',
      'Encoding-based payload delivery',
    ],
    rulePatterns: ['io-', 'da-', 'ea-', 'unicode', 'tokenizer'],
    defaultSeverity: 'medium',
    mitigations: [
      'Input sanitization',
      'Pattern stripping',
      'Warning injection',
      'Logging for analysis',
    ],
  },
  privilege_escalation: {
    phase: 'privilege_escalation',
    name: 'Privilege Escalation',
    description: 'Attacker attempts to override system prompt constraints or escalate LLM role.',
    indicators: [
      'Role override attempts',
      'System prompt manipulation',
      'Jailbreak patterns',
      'Instruction hierarchy subversion',
    ],
    rulePatterns: ['rs-', 'jailbreak'],
    defaultSeverity: 'high',
    mitigations: [
      'Block or sanitize per configuration',
      'Re-inject system prompt boundary',
      'Log at HIGH severity',
    ],
  },
  reconnaissance: {
    phase: 'reconnaissance',
    name: 'Reconnaissance',
    description: 'Attacker probes for system prompt content, model capabilities, or security boundaries.',
    indicators: [
      'Prompt extraction attempts',
      'Capability enumeration',
      'Boundary testing',
      'Scope probing queries',
    ],
    rulePatterns: ['pe-', 'scope'],
    defaultSeverity: 'high',
    mitigations: [
      'Block with generic fallback',
      'Never reveal prompt existence',
      'Increment suspicion score',
    ],
  },
  persistence: {
    phase: 'persistence',
    name: 'Persistence',
    description: 'Attacker manipulates conversation memory or context to maintain influence across turns.',
    indicators: [
      'Memory manipulation attempts',
      'Context poisoning',
      'Persistent instruction injection',
      'History rewriting',
    ],
    rulePatterns: ['pm-', 'memory'],
    defaultSeverity: 'critical',
    mitigations: [
      'Full session checkpoint',
      'Context purge and reset',
      'CRITICAL alert raised',
    ],
  },
  command_and_control: {
    phase: 'command_and_control',
    name: 'Command and Control',
    description: 'Attacker establishes external communication channel via URL fetching or dynamic instructions.',
    indicators: [
      'External URL fetching directives',
      'Dynamic instruction loading',
      'Remote payload retrieval',
      'Callback establishment',
    ],
    rulePatterns: ['c2-', 'fetch', 'url', 'dynamic'],
    defaultSeverity: 'critical',
    mitigations: [
      'Block immediately',
      'Generate full incident report',
      'Webhook notification',
    ],
  },
  lateral_movement: {
    phase: 'lateral_movement',
    name: 'Lateral Movement',
    description: 'Attacker attempts to spread to other tools, agents, or systems via the LLM.',
    indicators: [
      'Self-replication patterns',
      'Cross-agent propagation',
      'Tool chain exploitation',
      'Multi-system targeting',
    ],
    rulePatterns: ['lm-', 'replicate', 'propagat'],
    defaultSeverity: 'critical',
    mitigations: [
      'Block ALL outbound tool calls',
      'Session termination',
      'Full incident report',
    ],
  },
  actions_on_objective: {
    phase: 'actions_on_objective',
    name: 'Actions on Objective',
    description: 'Attacker achieves final goal: data exfiltration, content injection, or system compromise.',
    indicators: [
      'Data exfiltration patterns',
      'Content injection',
      'Credential harvesting',
      'Unauthorized data access',
    ],
    rulePatterns: ['de-', 'ci-', 'exfil'],
    defaultSeverity: 'critical',
    mitigations: [
      'Maximum response: block + incident + notify + kill session',
    ],
  },
} as const

/** Threat level severity ordering for comparison */
const THREAT_SEVERITY: Readonly<Record<ThreatLevel, number>> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

/**
 * Maps scan results to Schneier 2026 Promptware Kill Chain phases.
 *
 * Analyzes detection output to classify attacks into structured phases,
 * detect multi-phase attack chains, and determine the highest-severity phase.
 */
export class KillChainMapper {
  /**
   * Classify scan results into kill chain phases.
   *
   * @param scanResults - Readonly array of scan results from the detection pipeline
   * @returns Kill chain classification with primary phase, all phases, and confidence
   */
  classify(scanResults: readonly ScanResult[]): KillChainClassification {
    const detectedResults = scanResults.filter((r) => r.detected)

    if (detectedResults.length === 0) {
      return {
        primaryPhase: 'none',
        confidence: 1.0,
        allPhases: [],
        isMultiPhase: false,
        attackChainDescription: 'No threats detected.',
      }
    }

    const phaseMap = this.buildPhaseMap(detectedResults)
    const allPhases = this.buildPhaseList(phaseMap)
    const primaryPhase = this.selectPrimaryPhase(allPhases)
    const isMultiPhase = allPhases.length >= 2

    if (isMultiPhase) {
      this.logPhaseTransitions(allPhases)
    }

    const attackChainDescription = this.describeAttackChain(allPhases, isMultiPhase)

    return {
      primaryPhase,
      confidence: allPhases[0]?.confidence ?? 0,
      allPhases,
      isMultiPhase,
      attackChainDescription,
    }
  }

  /**
   * Build a map of phases to their contributing scan results.
   */
  private buildPhaseMap(
    results: readonly ScanResult[]
  ): ReadonlyMap<KillChainPhase, readonly ScanResult[]> {
    const map = new Map<KillChainPhase, ScanResult[]>()

    for (const result of results) {
      const phase = this.resolvePhase(result)
      if (phase === 'none') continue

      const existing = map.get(phase) ?? []
      map.set(phase, [...existing, result])
    }

    return map
  }

  /**
   * Resolve the kill chain phase for a single scan result.
   * Uses the result's declared phase first, then falls back to rule prefix matching.
   */
  private resolvePhase(result: ScanResult): KillChainPhase {
    if (result.killChainPhase !== 'none') {
      return result.killChainPhase
    }

    return this.classifyByRulePrefix(result.scannerId, result.matchedPatterns)
  }

  /**
   * Classify a scan result by matching its scanner ID and patterns against rule prefixes.
   */
  private classifyByRulePrefix(
    scannerId: string,
    matchedPatterns: readonly string[]
  ): KillChainPhase {
    const allIdentifiers = [scannerId, ...matchedPatterns].map((s) => s.toLowerCase())

    for (const identifier of allIdentifiers) {
      for (const [phase, detail] of Object.entries(KILL_CHAIN_PHASES)) {
        const matches = detail.rulePatterns.some((prefix) => identifier.includes(prefix))
        if (matches) {
          return phase as KillChainPhase
        }
      }
    }

    return 'none'
  }

  /**
   * Convert the phase map into a sorted list of kill chain mappings.
   */
  private buildPhaseList(
    phaseMap: ReadonlyMap<KillChainPhase, readonly ScanResult[]>
  ): readonly KillChainMapping[] {
    const mappings: KillChainMapping[] = []

    for (const [phase, results] of phaseMap) {
      const confidence = this.computePhaseConfidence(results)
      const matchedRuleIds = results.map((r) => r.scannerId)
      const scannerSources = [...new Set(results.map((r) => r.scannerType))]

      mappings.push({ phase, confidence, matchedRuleIds, scannerSources })
    }

    return mappings.sort((a, b) => {
      const priorityA = PHASE_PRIORITY.indexOf(a.phase as KillChainPhase)
      const priorityB = PHASE_PRIORITY.indexOf(b.phase as KillChainPhase)
      if (priorityA !== priorityB) return priorityA - priorityB
      return b.confidence - a.confidence
    })
  }

  /**
   * Compute aggregate confidence for a set of scan results in a single phase.
   */
  private computePhaseConfidence(results: readonly ScanResult[]): number {
    if (results.length === 0) return 0

    const maxConfidence = Math.max(...results.map((r) => r.confidence))
    const avgConfidence =
      results.reduce((sum, r) => sum + r.confidence, 0) / results.length
    const severityBoost = Math.max(
      ...results.map((r) => THREAT_SEVERITY[r.threatLevel] * 0.05)
    )

    return Math.min(1.0, maxConfidence * 0.6 + avgConfidence * 0.3 + severityBoost + results.length * 0.02)
  }

  /**
   * Select the primary (highest-severity) phase from the sorted phase list.
   */
  private selectPrimaryPhase(phases: readonly KillChainMapping[]): KillChainPhase {
    const first = phases[0]
    if (!first) return 'none'
    return first.phase
  }

  /**
   * Log phase transitions for multi-phase attack detection.
   */
  private logPhaseTransitions(phases: readonly KillChainMapping[]): void {
    const phaseNames = phases.map((p) => {
      const detail = KILL_CHAIN_PHASES[p.phase as Exclude<KillChainPhase, 'none'>]
      return detail?.name ?? p.phase
    })

    console.warn(
      `[ShieldX:KillChain] Multi-phase attack detected: ${phaseNames.join(' -> ')} (${phases.length} phases)`
    )
  }

  /**
   * Generate a human-readable description of the detected attack chain.
   */
  private describeAttackChain(
    phases: readonly KillChainMapping[],
    isMultiPhase: boolean
  ): string {
    if (phases.length === 0) return 'No kill chain phases detected.'

    if (!isMultiPhase) {
      const firstPhase = phases[0]
      if (!firstPhase) return 'No kill chain phases detected.'
      const detail = KILL_CHAIN_PHASES[firstPhase.phase as Exclude<KillChainPhase, 'none'>]
      return detail
        ? `Single-phase attack: ${detail.name} — ${detail.description}`
        : `Single-phase attack: ${firstPhase.phase}`
    }

    const descriptions = phases.map((p) => {
      const detail = KILL_CHAIN_PHASES[p.phase as Exclude<KillChainPhase, 'none'>]
      return detail?.name ?? p.phase
    })

    return `Multi-phase attack chain (${phases.length} phases): ${descriptions.join(' -> ')}`
  }
}
