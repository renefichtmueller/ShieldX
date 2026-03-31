/**
 * Phase 3 Strategy — Reconnaissance
 *
 * Handles attempts to probe for system prompt content,
 * enumerate model capabilities, or test security boundaries.
 *
 * Default action: block
 * - Block with generic fallback (NEVER reveal prompt existence)
 * - Increment suspicion score
 * - Log for pattern analysis
 */

import type { ScanResult } from '../../types/detection.js'
import type { HealingResponse, HealingStrategy } from '../../types/healing.js'

/** Phase 3 healing strategy definition */
export const PHASE3_STRATEGY: HealingStrategy = {
  phase: 'reconnaissance',
  defaultAction: 'block',
  escalationThreshold: 0.6,
  requiresSessionReset: false,
  requiresIncidentReport: false,
  requiresWebhookNotify: false,
} as const

/**
 * Generic fallback responses that do NOT reveal the existence of a system prompt.
 * Rotated to avoid fingerprinting.
 */
const GENERIC_FALLBACKS: readonly string[] = [
  "I can't help with that request.",
  "I'm not able to assist with that particular query.",
  'That falls outside the scope of what I can do.',
  'I can help you with other questions instead.',
  "Let me know if there's something else I can help with.",
] as const

/**
 * Execute Phase 3 (Reconnaissance) healing.
 *
 * Always blocks with a generic fallback response that avoids
 * revealing any information about the system prompt or internal configuration.
 *
 * @param _input - The original user input (unused — always blocked)
 * @param _scanResults - Scan results that triggered this phase
 * @returns Healing response with generic fallback
 */
export async function executePhase3(
  _input: string,
  _scanResults: readonly ScanResult[]
): Promise<HealingResponse> {
  const fallbackIndex = Math.floor(Math.random() * GENERIC_FALLBACKS.length)
  const fallback = GENERIC_FALLBACKS[fallbackIndex] ?? GENERIC_FALLBACKS[0] ?? "I can't help with that request."

  return {
    action: 'block',
    strategy: PHASE3_STRATEGY,
    fallbackResponse: fallback,
    sessionResetPerformed: false,
    incidentReported: false,
    webhookNotified: false,
  }
}
