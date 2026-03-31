/**
 * Healing Orchestrator — Coordinates healing responses based on kill chain phase and threat level.
 *
 * Routes detected threats to phase-specific strategies, manages session state,
 * generates incident reports, and delivers webhook notifications.
 */

import type {
  BehavioralContext,
  HealingAction,
  KillChainPhase,
  ScanResult,
  ShieldXConfig,
  ShieldXResult,
  ThreatLevel,
} from '../types/detection.js'
import type { HealingResponse } from '../types/healing.js'
import { FallbackResponder } from './FallbackResponder.js'
import { IncidentReporter } from './IncidentReporter.js'
// PromptReconstructor available via getPromptReconstructor() or healing/index.ts
import { SessionManager } from './SessionManager.js'
import { executePhase1 } from './strategies/phase1.strategy.js'
import { executePhase2 } from './strategies/phase2.strategy.js'
import { executePhase3 } from './strategies/phase3.strategy.js'
import { executePhase4 } from './strategies/phase4.strategy.js'
import { executePhase5 } from './strategies/phase5.strategy.js'
import { executePhase6 } from './strategies/phase6.strategy.js'
import { executePhase7 } from './strategies/phase7.strategy.js'

/**
 * Default action matrix: maps (threatLevel, phase) to healing action.
 * Phase-specific strategies may override these defaults.
 */
const ACTION_MATRIX: Readonly<Record<KillChainPhase, Readonly<Record<ThreatLevel, HealingAction>>>> = {
  none: { none: 'allow', low: 'allow', medium: 'allow', high: 'allow', critical: 'allow' },
  initial_access: { none: 'allow', low: 'warn', medium: 'sanitize', high: 'sanitize', critical: 'block' },
  privilege_escalation: { none: 'allow', low: 'warn', medium: 'sanitize', high: 'block', critical: 'block' },
  reconnaissance: { none: 'allow', low: 'warn', medium: 'block', high: 'block', critical: 'block' },
  persistence: { none: 'allow', low: 'warn', medium: 'reset', high: 'reset', critical: 'reset' },
  command_and_control: { none: 'allow', low: 'block', medium: 'block', high: 'incident', critical: 'incident' },
  lateral_movement: { none: 'allow', low: 'block', medium: 'incident', high: 'incident', critical: 'incident' },
  actions_on_objective: { none: 'allow', low: 'block', medium: 'incident', high: 'incident', critical: 'incident' },
} as const

/**
 * Coordinates healing responses across the kill chain.
 *
 * Determines the appropriate action for each threat, delegates to phase-specific
 * strategies, manages session state, and handles incident reporting.
 */
export class HealingOrchestrator {
  private readonly sessionManager: SessionManager
  private readonly incidentReporter: IncidentReporter
  private readonly fallbackResponder: FallbackResponder
  private readonly phaseStrategies: Partial<Record<KillChainPhase, HealingAction>>

  constructor(config?: Partial<ShieldXConfig>) {
    this.sessionManager = new SessionManager()
    this.incidentReporter = new IncidentReporter()
    this.fallbackResponder = new FallbackResponder()
    this.phaseStrategies = config?.healing?.phaseStrategies ?? {}
  }

  /**
   * Determine the appropriate healing action for a threat level and phase combination.
   *
   * Checks custom phase strategies first, then falls back to the default action matrix.
   *
   * @param threatLevel - Detected threat severity
   * @param phase - Classified kill chain phase
   * @returns The healing action to take
   */
  determineAction(threatLevel: ThreatLevel, phase: KillChainPhase): HealingAction {
    // Check custom phase strategies first
    const customAction = this.phaseStrategies[phase]
    if (customAction) return customAction

    // Fall back to default action matrix
    const phaseActions = ACTION_MATRIX[phase]
    return phaseActions[threatLevel]
  }

  /**
   * Execute the full healing pipeline for a ShieldX result.
   *
   * 1. Determine action from threat level + phase
   * 2. Delegate to phase-specific strategy
   * 3. Manage session state (checkpoint/reset)
   * 4. Generate incident report if needed
   * 5. Deliver webhook if configured
   *
   * @param result - The ShieldX pipeline result
   * @param context - Optional behavioral context for session management
   * @returns Healing response with all actions taken
   */
  async executeHealing(
    result: ShieldXResult,
    context?: BehavioralContext
  ): Promise<HealingResponse> {
    const { threatLevel, killChainPhase, scanResults, input } = result
    const action = this.determineAction(threatLevel, killChainPhase)

    // If no action needed, return early
    if (action === 'allow') {
      return this.createAllowResponse()
    }

    // Checkpoint session before any healing action
    if (context) {
      this.sessionManager.createCheckpoint(
        context.sessionId,
        input,
        this.threatLevelToTrustScore(threatLevel)
      )
    }

    // Execute phase-specific strategy
    const detectedResults = scanResults.filter((r) => r.detected)
    const phaseResponse = await this.executePhaseStrategy(
      killChainPhase,
      input,
      detectedResults,
      action
    )

    // Handle session reset if strategy requires it
    if (phaseResponse.sessionResetPerformed && context) {
      const cleanCheckpoint = this.sessionManager.getLatestCleanCheckpoint(
        context.sessionId
      )
      if (cleanCheckpoint) {
        this.sessionManager.rollback(context.sessionId, cleanCheckpoint.id)
      }
      this.sessionManager.purgeUntrustedMemory(context.sessionId)
    }

    // Generate incident report if needed
    let incidentReported = phaseResponse.incidentReported
    if (phaseResponse.strategy.requiresIncidentReport) {
      const report = this.incidentReporter.createReport(
        input,
        detectedResults,
        killChainPhase,
        threatLevel,
        action,
        context?.sessionId,
        context?.userId
      )

      console.error(
        `[ShieldX:Incident] ${report.id} | Phase: ${killChainPhase} | Threat: ${threatLevel} | Action: ${action}`
      )
      incidentReported = true
    }

    // Deliver webhook if needed
    let webhookNotified = phaseResponse.webhookNotified
    if (phaseResponse.strategy.requiresWebhookNotify) {
      const report = this.incidentReporter.createReport(
        input,
        detectedResults,
        killChainPhase,
        threatLevel,
        action,
        context?.sessionId,
        context?.userId
      )
      webhookNotified = await this.incidentReporter.deliverWebhook(report)
    }

    // Ensure fallback response is safe
    const fallbackResponse = phaseResponse.fallbackResponse
      ? this.fallbackResponder.isSafeResponse(phaseResponse.fallbackResponse)
        ? phaseResponse.fallbackResponse
        : this.fallbackResponder.getResponse(killChainPhase)
      : this.fallbackResponder.getResponse(killChainPhase)

    return {
      ...phaseResponse,
      fallbackResponse,
      incidentReported,
      webhookNotified,
    }
  }

  /**
   * Get the session manager instance (for external checkpoint/rollback access).
   */
  getSessionManager(): SessionManager {
    return this.sessionManager
  }

  /**
   * Get the incident reporter instance (for external report access).
   */
  getIncidentReporter(): IncidentReporter {
    return this.incidentReporter
  }

  /**
   * Route to the appropriate phase strategy.
   */
  private async executePhaseStrategy(
    phase: KillChainPhase,
    input: string,
    scanResults: readonly ScanResult[],
    action: HealingAction
  ): Promise<HealingResponse> {
    switch (phase) {
      case 'initial_access':
        return executePhase1(input, scanResults)
      case 'privilege_escalation': {
        const allowSanitize = action === 'sanitize'
        return executePhase2(input, scanResults, allowSanitize)
      }
      case 'reconnaissance':
        return executePhase3(input, scanResults)
      case 'persistence':
        return executePhase4(input, scanResults)
      case 'command_and_control':
        return executePhase5(input, scanResults)
      case 'lateral_movement':
        return executePhase6(input, scanResults)
      case 'actions_on_objective':
        return executePhase7(input, scanResults)
      default:
        return this.createAllowResponse()
    }
  }

  /** Create a no-op "allow" response */
  private createAllowResponse(): HealingResponse {
    return {
      action: 'allow',
      strategy: {
        phase: 'none',
        defaultAction: 'allow',
        escalationThreshold: 1.0,
        requiresSessionReset: false,
        requiresIncidentReport: false,
        requiresWebhookNotify: false,
      },
      sessionResetPerformed: false,
      incidentReported: false,
      webhookNotified: false,
    }
  }

  /** Convert threat level to a trust score (inverse relationship) */
  private threatLevelToTrustScore(threatLevel: ThreatLevel): number {
    const scores: Record<ThreatLevel, number> = {
      none: 1.0,
      low: 0.8,
      medium: 0.5,
      high: 0.3,
      critical: 0.1,
    }
    return scores[threatLevel]
  }
}
