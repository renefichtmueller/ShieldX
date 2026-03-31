/**
 * Phase 1 Strategy — Initial Access
 *
 * Handles initial injection attempts via direct injection, encoding tricks,
 * unicode homoglyphs, tokenizer exploits, and delimiter confusion.
 *
 * Default action: sanitize
 * - Strip detected injection patterns from input
 * - Add warning markers for downstream consumers
 * - Log the sanitization event
 */

import type { ScanResult } from '../../types/detection.js'
import type { HealingResponse, HealingStrategy } from '../../types/healing.js'

/** Phase 1 healing strategy definition */
export const PHASE1_STRATEGY: HealingStrategy = {
  phase: 'initial_access',
  defaultAction: 'sanitize',
  escalationThreshold: 0.8,
  requiresSessionReset: false,
  requiresIncidentReport: false,
  requiresWebhookNotify: false,
} as const

/**
 * Execute Phase 1 (Initial Access) healing.
 *
 * Strips matched injection patterns from the input and returns
 * a sanitized version with warning markers.
 *
 * @param input - The original user input
 * @param scanResults - Scan results that triggered this phase
 * @returns Healing response with sanitized input
 */
export async function executePhase1(
  input: string,
  scanResults: readonly ScanResult[]
): Promise<HealingResponse> {
  const sanitized = stripMatchedPatterns(input, scanResults)
  const hasContent = sanitized.trim().length > 0

  const base = {
    action: 'sanitize' as const,
    strategy: PHASE1_STRATEGY,
    sessionResetPerformed: false,
    incidentReported: false,
    webhookNotified: false,
  }

  return hasContent
    ? { ...base, sanitizedInput: sanitized }
    : { ...base, fallbackResponse: 'Your input could not be processed. Please rephrase your request.' }
}

/**
 * Strip all matched injection patterns from the input string.
 * Returns a new string with patterns removed and whitespace normalized.
 */
function stripMatchedPatterns(
  input: string,
  scanResults: readonly ScanResult[]
): string {
  const patterns = scanResults.flatMap((r) => r.matchedPatterns)

  let cleaned = input
  for (const pattern of patterns) {
    const escaped = escapeRegex(pattern)
    cleaned = cleaned.replace(new RegExp(escaped, 'gi'), '')
  }

  return cleaned.replace(/\s{2,}/g, ' ').trim()
}

/** Escape special regex characters in a string */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
