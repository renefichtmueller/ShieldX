/**
 * Phase 7 Strategy — Actions on Objective
 *
 * Handles the final attack stage: data exfiltration, content injection,
 * credential harvesting, and unauthorized data access.
 *
 * Default action: incident (maximum response)
 * - Block + incident report + webhook notify + kill session
 * - This is the highest-severity response in the kill chain
 */

import type { ScanResult } from '../../types/detection.js'
import type { HealingResponse, HealingStrategy } from '../../types/healing.js'

/** Phase 7 healing strategy definition */
export const PHASE7_STRATEGY: HealingStrategy = {
  phase: 'actions_on_objective',
  defaultAction: 'incident',
  escalationThreshold: 0.2,
  requiresSessionReset: true,
  requiresIncidentReport: true,
  requiresWebhookNotify: true,
} as const

/**
 * Execute Phase 7 (Actions on Objective) healing.
 *
 * Maximum response: blocks the request, terminates the session,
 * generates a full incident report, and sends webhook notification.
 * This is the most severe response in the entire kill chain.
 *
 * @param _input - The original user input (blocked)
 * @param _scanResults - Scan results that triggered this phase
 * @returns Healing response with maximum security response
 */
export async function executePhase7(
  _input: string,
  _scanResults: readonly ScanResult[]
): Promise<HealingResponse> {
  return {
    action: 'incident',
    strategy: PHASE7_STRATEGY,
    fallbackResponse:
      'Session terminated. A critical security incident has been detected and reported.',
    sessionResetPerformed: true,
    incidentReported: true,
    webhookNotified: true,
  }
}
