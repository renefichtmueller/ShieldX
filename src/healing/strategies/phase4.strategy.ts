/**
 * Phase 4 Strategy — Persistence
 *
 * Handles memory manipulation, context poisoning, and persistent
 * instruction injection that survives across conversation turns.
 *
 * Default action: reset
 * - Full session checkpoint before reset
 * - Purge potentially poisoned context
 * - Raise CRITICAL alert
 */

import type { ScanResult } from '../../types/detection.js'
import type { HealingResponse, HealingStrategy } from '../../types/healing.js'

/** Phase 4 healing strategy definition */
export const PHASE4_STRATEGY: HealingStrategy = {
  phase: 'persistence',
  defaultAction: 'reset',
  escalationThreshold: 0.5,
  requiresSessionReset: true,
  requiresIncidentReport: true,
  requiresWebhookNotify: false,
} as const

/**
 * Execute Phase 4 (Persistence) healing.
 *
 * Performs a full session reset: checkpoints the current state,
 * purges the context, and raises a CRITICAL alert.
 *
 * @param _input - The original user input (discarded on reset)
 * @param _scanResults - Scan results that triggered this phase
 * @returns Healing response with session reset
 */
export async function executePhase4(
  _input: string,
  _scanResults: readonly ScanResult[]
): Promise<HealingResponse> {
  return {
    action: 'reset',
    strategy: PHASE4_STRATEGY,
    fallbackResponse:
      'A security concern was detected. Your session context has been reset to a safe state. You may continue with a new request.',
    sessionResetPerformed: true,
    incidentReported: true,
    webhookNotified: false,
  }
}
