/**
 * Runtime behavioral intent monitoring.
 * "Does this action align with the declared task?"
 *
 * Core responsibilities:
 * - Session baseline from taskDescription + allowedTools
 * - Semantic drift detection per message (cosine distance to task embedding)
 * - Tool call validation against allowedTools
 * - Bayesian trust scoring (Stackelberg defense, game-theoretic)
 *
 * Part of Layer 6 — Behavioral Monitoring.
 */

import type { SessionProfile, AnomalySignal } from '../types/behavioral.js'
import type { BehavioralContext, ScanResult, ThreatLevel } from '../types/detection.js'
import { simpleEmbedding, buildProfile } from './SessionProfiler.js'
import { measureDrift, isHijacked } from './ContextDriftDetector.js'
import { validate as validateTool } from './ToolCallValidator.js'

/** Default drift threshold */
const DEFAULT_DRIFT_THRESHOLD = 0.4

/** Bayesian prior probability of adversarial intent */
const PRIOR_ADVERSARIAL = 0.01

/** Signal likelihood ratios (how much each signal shifts P(adversarial)) */
const SIGNAL_LIKELIHOODS: Readonly<Record<AnomalySignal['type'], number>> = {
  drift: 3.0,
  escalation: 8.0,
  tool_misuse: 10.0,
  authority_shift: 6.0,
  topic_pivot: 2.5,
  memory_tampering: 15.0,
}

/** In-memory session store */
const sessionStore = new Map<string, {
  readonly profile: SessionProfile
  readonly context: BehavioralContext
  adversarialProbability: number
  turnCount: number
}>()

/**
 * Create a new monitoring session.
 * Builds a session baseline from the behavioral context.
 *
 * @param context - The behavioral context at session start
 * @returns The session ID
 */
export function createSession(context: BehavioralContext): string {
  const profile = buildProfile(context)

  sessionStore.set(context.sessionId, {
    profile,
    context,
    adversarialProbability: PRIOR_ADVERSARIAL,
    turnCount: 0,
  })

  return context.sessionId
}

/**
 * Check an input message against the session baseline.
 * Measures semantic drift and computes a scan result.
 *
 * @param input - The message text to check
 * @param context - The current behavioral context
 * @returns A ScanResult from the behavioral scanner
 */
export async function check(
  input: string,
  context: BehavioralContext,
): Promise<ScanResult> {
  const start = performance.now()
  const session = sessionStore.get(context.sessionId)

  if (session === undefined) {
    // Auto-create session if not exists
    createSession(context)
    return createCleanResult(performance.now() - start)
  }

  // Compute semantic embedding of current input
  const inputEmbedding = simpleEmbedding(input)

  // Measure drift from task baseline
  const driftScore = measureDrift(inputEmbedding, session.profile.taskEmbedding)
  const drifted = isHijacked(driftScore, session.profile.baselineDriftThreshold)

  // Collect threat signals
  const matchedPatterns: string[] = []
  let confidence = 0

  if (drifted) {
    matchedPatterns.push(`intent_drift:${driftScore.toFixed(3)}`)
    confidence = Math.max(confidence, driftScore)
  }

  // Update turn count
  const updatedSession = {
    ...session,
    turnCount: session.turnCount + 1,
  }
  sessionStore.set(context.sessionId, updatedSession)

  // Determine threat level
  const threatLevel = computeThreatLevel(driftScore, session.adversarialProbability)
  const detected = threatLevel !== 'none'

  const latencyMs = performance.now() - start

  return {
    scannerId: 'intent-monitor',
    scannerType: 'behavioral',
    detected,
    confidence: Math.min(1.0, confidence),
    threatLevel,
    killChainPhase: detected ? 'reconnaissance' : 'none',
    matchedPatterns,
    rawScore: driftScore,
    latencyMs,
    metadata: {
      driftScore,
      adversarialProbability: session.adversarialProbability,
      turnCount: updatedSession.turnCount,
    },
  }
}

/**
 * Validate a tool call against the session's allowed tools and sensitive resources.
 *
 * @param toolName - The name of the tool being called
 * @param args - The arguments passed to the tool
 * @param sessionId - The session identifier
 * @returns Validation result with allowed status and reason
 */
export async function validateToolCall(
  toolName: string,
  args: Readonly<Record<string, unknown>>,
  sessionId: string,
): Promise<{ readonly allowed: boolean; readonly reason?: string }> {
  const session = sessionStore.get(sessionId)
  if (session === undefined) {
    return { allowed: false, reason: `Unknown session: ${sessionId}` }
  }

  const result = validateTool(toolName, args, session.context)

  // If tool call is not allowed, update adversarial probability
  if (!result.allowed) {
    const signals: AnomalySignal[] = [{
      type: 'tool_misuse',
      severity: result.threatLevel,
      confidence: 0.8,
      description: result.reason ?? 'Unauthorized tool call',
      relatedTurns: [],
      killChainPhase: 'actions_on_objective',
    }]
    updateTrustScore(sessionId, signals)
  }

  const response: { readonly allowed: boolean; readonly reason?: string } = result.reason !== undefined
    ? { allowed: result.allowed, reason: result.reason }
    : { allowed: result.allowed }

  return response
}

/**
 * Get the session profile for a given session ID.
 *
 * @param sessionId - The session identifier
 * @returns The SessionProfile or undefined
 */
export function getSessionProfile(sessionId: string): SessionProfile | undefined {
  const session = sessionStore.get(sessionId)
  return session?.profile
}

/**
 * Update the Bayesian trust score for a session based on observed anomaly signals.
 * Uses Stackelberg defense formulation:
 *
 *   P(adversarial | signals) = P(signals | adversarial) * P(adversarial)
 *                               / P(signals)
 *
 * Where P(signals) is computed via total probability theorem.
 *
 * @param sessionId - The session identifier
 * @param signals - Array of observed anomaly signals
 * @returns Updated adversarial probability P(adversarial)
 */
export function updateTrustScore(
  sessionId: string,
  signals: readonly AnomalySignal[],
): number {
  const session = sessionStore.get(sessionId)
  if (session === undefined) return PRIOR_ADVERSARIAL

  let currentP = session.adversarialProbability

  for (const signal of signals) {
    // Likelihood ratio: P(signal | adversarial) / P(signal | benign)
    const likelihoodRatio = SIGNAL_LIKELIHOODS[signal.type] ?? 2.0

    // Scale by confidence
    const scaledRatio = 1 + (likelihoodRatio - 1) * signal.confidence

    // Bayesian update: P(A|S) = P(S|A)*P(A) / (P(S|A)*P(A) + P(S|~A)*P(~A))
    const pSignalGivenAdversarial = scaledRatio
    const pSignalGivenBenign = 1.0
    const pAdversarial = currentP
    const pBenign = 1 - currentP

    const numerator = pSignalGivenAdversarial * pAdversarial
    const denominator = numerator + pSignalGivenBenign * pBenign

    currentP = denominator > 0 ? numerator / denominator : currentP
  }

  // Clamp to [0, 1]
  currentP = Math.max(0, Math.min(1, currentP))

  // Update stored probability (this is the one mutable field)
  const updated = { ...session, adversarialProbability: currentP }
  sessionStore.set(sessionId, updated)

  return currentP
}

/**
 * Get the current adversarial probability for a session.
 *
 * @param sessionId - The session identifier
 * @returns The current P(adversarial) or the prior if session not found
 */
export function getAdversarialProbability(sessionId: string): number {
  const session = sessionStore.get(sessionId)
  return session?.adversarialProbability ?? PRIOR_ADVERSARIAL
}

/**
 * Remove a session from the monitor.
 *
 * @param sessionId - The session identifier
 */
export function destroySession(sessionId: string): void {
  sessionStore.delete(sessionId)
}

/**
 * Compute threat level from drift score and adversarial probability.
 */
function computeThreatLevel(
  driftScore: number,
  adversarialProbability: number,
): ThreatLevel {
  // P(adversarial) thresholds from Stackelberg defense
  if (adversarialProbability > 0.8) return 'critical'
  if (adversarialProbability > 0.5) return 'high'

  // Drift-based thresholds
  if (driftScore > 0.7) return 'high'
  if (driftScore > DEFAULT_DRIFT_THRESHOLD) return 'medium'
  if (driftScore > 0.2) return 'low'

  return 'none'
}

/**
 * Create a clean (no threat) scan result.
 */
function createCleanResult(latencyMs: number): ScanResult {
  return {
    scannerId: 'intent-monitor',
    scannerType: 'behavioral',
    detected: false,
    confidence: 0,
    threatLevel: 'none',
    killChainPhase: 'none',
    matchedPatterns: [],
    latencyMs,
  }
}
