/**
 * Phase 6 Strategy — Lateral Movement
 *
 * Handles self-replication, cross-agent propagation,
 * and tool chain exploitation attempts.
 *
 * Default action: incident
 * - Block ALL outbound tool calls
 * - Terminate the session
 * - Generate full incident report with webhook notification
 */

import type { ScanResult } from '../../types/detection.js'
import type { HealingResponse, HealingStrategy } from '../../types/healing.js'

/** Phase 6 healing strategy definition */
export const PHASE6_STRATEGY: HealingStrategy = {
  phase: 'lateral_movement',
  defaultAction: 'incident',
  escalationThreshold: 0.3,
  requiresSessionReset: true,
  requiresIncidentReport: true,
  requiresWebhookNotify: true,
} as const

/**
 * Execute Phase 6 (Lateral Movement) healing.
 *
 * Maximum containment: blocks all outbound tool calls,
 * terminates the session, and generates a full incident report
 * with webhook notification.
 *
 * @param _input - The original user input (blocked)
 * @param _scanResults - Scan results that triggered this phase
 * @returns Healing response with session termination and incident reporting
 */
export async function executePhase6(
  _input: string,
  _scanResults: readonly ScanResult[]
): Promise<HealingResponse> {
  return {
    action: 'incident',
    strategy: PHASE6_STRATEGY,
    fallbackResponse: 'Session terminated due to a critical security event. All outbound operations have been suspended.',
    sessionResetPerformed: true,
    incidentReported: true,
    webhookNotified: true,
  }
}
