/**
 * Fallback Responder — Generates safe fallback responses when blocking.
 *
 * Produces generic responses that do not reveal system prompt existence,
 * with phase-appropriate messaging for different kill chain phases.
 */

import type { KillChainPhase } from '../types/detection.js'

/**
 * Phase-specific fallback response pools.
 *
 * Each phase has multiple responses to prevent fingerprinting.
 * Responses are carefully crafted to never reveal:
 * - The existence of a system prompt
 * - Internal security mechanisms
 * - Detection specifics
 */
const PHASE_FALLBACKS: Readonly<Record<Exclude<KillChainPhase, 'none'>, readonly string[]>> = {
  initial_access: [
    'Your input could not be processed. Please rephrase your request.',
    'I was unable to understand that input. Could you try again?',
    'That request could not be completed. Please provide a clearer query.',
  ],
  privilege_escalation: [
    'This request conflicts with established guidelines.',
    'I am not able to change how I operate based on that request.',
    'That request falls outside my operational scope.',
  ],
  reconnaissance: [
    "I can't help with that request.",
    "I'm not able to assist with that particular query.",
    'That falls outside the scope of what I can do.',
    'I can help you with other questions instead.',
    "Let me know if there's something else I can help with.",
  ],
  persistence: [
    'A security concern was detected. Your session has been reset to a safe state.',
    'Your conversation context has been refreshed. You may continue with a new request.',
    'For your protection, the session has been restored to a clean state.',
  ],
  command_and_control: [
    'This request has been blocked due to a security policy violation.',
    'That operation is not permitted. The incident has been recorded.',
    'This request cannot be fulfilled for security reasons.',
  ],
  lateral_movement: [
    'Session terminated. All outbound operations have been suspended.',
    'This session has been closed due to a security concern.',
    'Session ended. External operations are no longer available.',
  ],
  actions_on_objective: [
    'Session terminated. A critical security incident has been detected and reported.',
    'This session has been permanently closed due to a critical security event.',
    'All operations terminated. Security team has been notified.',
  ],
} as const

/** Default fallback for unknown/unmatched phases */
const DEFAULT_FALLBACK = "I'm unable to process that request. Please try something else."

/**
 * Generates safe, phase-appropriate fallback responses.
 *
 * Ensures responses never leak information about the system prompt,
 * internal security mechanisms, or detection specifics.
 */
export class FallbackResponder {
  /**
   * Get a fallback response appropriate for the given kill chain phase.
   *
   * @param phase - The detected kill chain phase
   * @returns A safe fallback response string
   */
  getResponse(phase: KillChainPhase): string {
    if (phase === 'none') return DEFAULT_FALLBACK

    const pool = PHASE_FALLBACKS[phase]
    if (!pool || pool.length === 0) return DEFAULT_FALLBACK

    const index = Math.floor(Math.random() * pool.length)
    return pool[index] ?? DEFAULT_FALLBACK
  }

  /**
   * Get a deterministic fallback response (for testing).
   *
   * @param phase - The detected kill chain phase
   * @param index - Index into the response pool
   * @returns A safe fallback response string
   */
  getResponseAtIndex(phase: KillChainPhase, index: number): string {
    if (phase === 'none') return DEFAULT_FALLBACK

    const pool = PHASE_FALLBACKS[phase]
    if (!pool || pool.length === 0) return DEFAULT_FALLBACK

    const safeIndex = Math.abs(index) % pool.length
    return pool[safeIndex] ?? DEFAULT_FALLBACK
  }

  /**
   * Check whether a proposed response is safe to send.
   * Validates that it does not contain system-prompt-revealing content.
   *
   * @param response - The proposed response string
   * @returns True if the response is safe
   */
  isSafeResponse(response: string): boolean {
    const lower = response.toLowerCase()

    const dangerousPatterns = [
      'system prompt',
      'system message',
      'system instruction',
      'my instructions',
      'my prompt',
      'i was told to',
      'i was instructed',
      'my configuration',
      'my rules say',
      'according to my rules',
      'internal policy',
      'detection system',
      'injection detected',
      'security scanner',
      'kill chain',
    ]

    return !dangerousPatterns.some((pattern) => lower.includes(pattern))
  }
}
