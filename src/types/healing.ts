/**
 * Types for the healing/self-repair subsystem.
 */

import type { HealingAction, KillChainPhase, ThreatLevel } from './detection.js'

/** Strategy function signature for a kill chain phase */
export interface HealingStrategy {
  readonly phase: KillChainPhase
  readonly defaultAction: HealingAction
  readonly escalationThreshold: number
  readonly requiresSessionReset: boolean
  readonly requiresIncidentReport: boolean
  readonly requiresWebhookNotify: boolean
}

/** Response from the healing orchestrator */
export interface HealingResponse {
  readonly action: HealingAction
  readonly strategy: HealingStrategy
  readonly sanitizedInput?: string
  readonly fallbackResponse?: string
  readonly sessionResetPerformed: boolean
  readonly incidentReported: boolean
  readonly webhookNotified: boolean
}

/** Session state checkpoint for rollback */
export interface SessionCheckpoint {
  readonly id: string
  readonly sessionId: string
  readonly createdAt: string
  readonly messageIndex: number
  readonly contextSnapshot: string
  readonly trustScore: number
  readonly isClean: boolean
}

/** Per-phase strategy configuration */
export interface PhaseStrategyConfig {
  readonly phase: KillChainPhase
  readonly threatLevel: ThreatLevel
  readonly action: HealingAction
  readonly logLevel: 'info' | 'warn' | 'error' | 'critical'
  readonly resetSession: boolean
  readonly notifyWebhook: boolean
  readonly blockOutboundTools: boolean
  readonly terminateSession: boolean
}
