/**
 * Incident Reporter — Creates structured incident reports for security events.
 *
 * Generates SHA-256 hashed reports (never stores raw input),
 * maps to MITRE ATLAS and OWASP frameworks, and supports
 * webhook delivery for security operations integration.
 */

import { createHash, randomUUID } from 'node:crypto'
import type {
  HealingAction,
  IncidentReport,
  KillChainPhase,
  ScanResult,
  ThreatLevel,
} from '../types/detection.js'

/** MITRE ATLAS mapping by kill chain phase */
const ATLAS_MAPPINGS: Readonly<Record<Exclude<KillChainPhase, 'none'>, string>> = {
  initial_access: 'AML.T0051 — LLM Prompt Injection',
  privilege_escalation: 'AML.T0051.001 — Direct Prompt Injection',
  reconnaissance: 'AML.T0052 — System Prompt Extraction',
  persistence: 'AML.T0053 — Context Manipulation',
  command_and_control: 'AML.T0054 — External Resource Loading',
  lateral_movement: 'AML.T0055 — Cross-Agent Propagation',
  actions_on_objective: 'AML.T0048 — Data Exfiltration via LLM',
} as const

/** OWASP LLM Top 10 2025 mapping by kill chain phase */
const OWASP_MAPPINGS: Readonly<Record<Exclude<KillChainPhase, 'none'>, string>> = {
  initial_access: 'LLM01:2025 — Prompt Injection',
  privilege_escalation: 'LLM01:2025 — Prompt Injection',
  reconnaissance: 'LLM07:2025 — System Prompt Leakage',
  persistence: 'LLM01:2025 — Prompt Injection',
  command_and_control: 'LLM05:2025 — Insecure Output Handling',
  lateral_movement: 'LLM08:2025 — Excessive Agency',
  actions_on_objective: 'LLM02:2025 — Sensitive Information Disclosure',
} as const

/** Configuration for incident reporter */
export interface IncidentReporterConfig {
  readonly webhookUrl?: string
  readonly webhookTimeout: number
  readonly includeAtlasMapping: boolean
  readonly includeOwaspMapping: boolean
}

/** Default configuration */
const DEFAULT_CONFIG: IncidentReporterConfig = {
  webhookTimeout: 5000,
  includeAtlasMapping: true,
  includeOwaspMapping: true,
}

/**
 * Creates structured incident reports and delivers them via webhook.
 *
 * All input is SHA-256 hashed before storage — raw user input is never
 * persisted or transmitted in incident reports.
 */
export class IncidentReporter {
  private readonly config: IncidentReporterConfig

  constructor(config: Partial<IncidentReporterConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Create an incident report from scan results.
   *
   * @param input - The original input (will be hashed, never stored raw)
   * @param scanResults - Scan results that triggered the incident
   * @param phase - The classified kill chain phase
   * @param threatLevel - The determined threat level
   * @param action - The healing action taken
   * @param sessionId - Optional session identifier
   * @param userId - Optional user identifier
   * @returns A structured incident report
   */
  createReport(
    input: string,
    scanResults: readonly ScanResult[],
    phase: KillChainPhase,
    threatLevel: ThreatLevel,
    action: HealingAction,
    sessionId?: string,
    userId?: string
  ): IncidentReport {
    const inputHash = createHash('sha256').update(input).digest('hex')
    const matchedPatterns = scanResults.flatMap((r) => r.matchedPatterns)
    const attackVector = this.deriveAttackVector(scanResults)
    const mitigationApplied = this.describeMitigation(action, phase)

    const report: IncidentReport = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      threatLevel,
      killChainPhase: phase,
      action,
      attackVector,
      matchedPatterns,
      inputHash,
      mitigationApplied,
      ...(sessionId != null ? { sessionId } : {}),
      ...(userId != null ? { userId } : {}),
      ...this.getComplianceMappings(phase),
    }

    return report
  }

  /**
   * Deliver an incident report via webhook.
   *
   * @param report - The incident report to deliver
   * @returns True if delivery succeeded, false otherwise
   */
  async deliverWebhook(report: IncidentReport): Promise<boolean> {
    if (!this.config.webhookUrl) {
      console.warn('[ShieldX:IncidentReporter] No webhook URL configured.')
      return false
    }

    try {
      const controller = new AbortController()
      const timeout = setTimeout(
        () => controller.abort(),
        this.config.webhookTimeout
      )

      const response = await fetch(this.config.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(report),
        signal: controller.signal,
      })

      clearTimeout(timeout)

      if (!response.ok) {
        console.error(
          `[ShieldX:IncidentReporter] Webhook delivery failed: ${response.status} ${response.statusText}`
        )
        return false
      }

      return true
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.error(
        `[ShieldX:IncidentReporter] Webhook delivery error: ${message}`
      )
      return false
    }
  }

  /**
   * Get compliance framework mappings as a partial record.
   * Returns only the properties that have values (no undefined).
   */
  private getComplianceMappings(
    phase: KillChainPhase
  ): { atlasMapping?: string; owaspMapping?: string } {
    const mappings: { atlasMapping?: string; owaspMapping?: string } = {}

    if (this.config.includeAtlasMapping && phase !== 'none') {
      const atlas = ATLAS_MAPPINGS[phase]
      if (atlas) {
        return { ...mappings, atlasMapping: atlas, ...this.getOwaspOnly(phase) }
      }
    }

    return { ...mappings, ...this.getOwaspOnly(phase) }
  }

  /** Get OWASP mapping only */
  private getOwaspOnly(
    phase: KillChainPhase
  ): { owaspMapping?: string } {
    if (this.config.includeOwaspMapping && phase !== 'none') {
      const owasp = OWASP_MAPPINGS[phase]
      if (owasp) return { owaspMapping: owasp }
    }
    return {}
  }

  /**
   * Derive the attack vector description from scan results.
   */
  private deriveAttackVector(scanResults: readonly ScanResult[]): string {
    const scannerTypes = [...new Set(scanResults.map((r) => r.scannerType))]
    const highestThreat = scanResults.reduce<ThreatLevel>(
      (max, r) => {
        const levels: ThreatLevel[] = ['none', 'low', 'medium', 'high', 'critical']
        return levels.indexOf(r.threatLevel) > levels.indexOf(max)
          ? r.threatLevel
          : max
      },
      'none'
    )

    return `Detected by ${scannerTypes.join(', ')} scanners at ${highestThreat} severity`
  }

  /**
   * Describe the mitigation action taken.
   */
  private describeMitigation(action: HealingAction, phase: KillChainPhase): string {
    const descriptions: Record<HealingAction, string> = {
      allow: 'No mitigation — allowed through',
      sanitize: 'Input sanitized: injection patterns stripped',
      warn: 'Warning added to output',
      block: 'Request blocked with safe fallback response',
      reset: 'Session reset to last clean checkpoint',
      incident: `Incident response activated for ${phase} phase`,
    }

    return descriptions[action]
  }
}
