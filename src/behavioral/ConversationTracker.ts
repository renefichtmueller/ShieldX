/**
 * Stateful multi-turn conversation tracker (P0 — most critical).
 * Detects attacks distributed across conversation turns by tracking
 * cumulative intent vectors, suspicion scores, topic drift,
 * authority shifts, and escalation patterns.
 *
 * Key design: suspicion score accumulates and NEVER decreases within a session.
 * This prevents attackers from "resetting" trust through benign messages.
 *
 * Part of Layer 6 — Behavioral Monitoring.
 */

import type {
  ConversationState,
  ConversationTurn,
  IntentVector,
  AnomalySignal,
} from '../types/behavioral.js'
import type { ScanResult, ThreatLevel } from '../types/detection.js'
import type { TrustTagType } from '../types/trust.js'
import { createHash } from 'node:crypto'
import { simpleEmbedding } from './SessionProfiler.js'
import { measureDrift } from './ContextDriftDetector.js'

/** Default sliding window size for turn history */
const DEFAULT_WINDOW_SIZE = 20

/** Cumulative drift threshold that triggers suspicion */
const CUMULATIVE_DRIFT_THRESHOLD = 0.3

/** Authority claim patterns */
const AUTHORITY_PATTERNS: readonly RegExp[] = [
  /(?:i\s+am|i'm)\s+(?:an?\s+)?(?:admin|administrator|developer|system|root|superuser|engineer)/i,
  /(?:as\s+(?:an?\s+)?(?:admin|system|developer)|in\s+(?:admin|system)\s+mode)/i,
  /(?:my\s+role|my\s+access)\s+(?:is|includes|allows)\s+(?:admin|full|root|unlimited)/i,
  /(?:i\s+have|i've\s+got)\s+(?:admin|root|full|elevated|special)\s+(?:access|privileges|permissions)/i,
  /(?:authorized|permitted|allowed)\s+to\s+(?:access|modify|delete|execute)\s+(?:everything|all|any)/i,
  /(?:switch|change|set)\s+(?:to|into)\s+(?:admin|developer|system|privileged)\s+mode/i,
]

/** Escalation topic patterns (benign -> boundary-testing -> harmful) */
const ESCALATION_PATTERNS: readonly { readonly pattern: RegExp; readonly severity: number }[] = [
  { pattern: /(?:how\s+does|explain)\s+(?:security|authentication|authorization)/i, severity: 0.1 },
  { pattern: /(?:what\s+(?:are|is)\s+the)\s+(?:limitations|restrictions|boundaries)/i, severity: 0.2 },
  { pattern: /(?:can\s+you|is\s+it\s+possible\s+to)\s+(?:bypass|circumvent|work\s+around)/i, severity: 0.5 },
  { pattern: /(?:ignore|override|disable)\s+(?:your|the|these)\s+(?:rules|instructions|safety)/i, severity: 0.8 },
  { pattern: /(?:jailbreak|hack|exploit|pwn|own)/i, severity: 0.9 },
]

/** Reconnaissance patterns (probing similar topics repeatedly) */
const RECON_KEYWORDS: readonly string[] = [
  'system prompt',
  'instructions',
  'configuration',
  'api key',
  'secret',
  'credentials',
  'database',
  'internal',
  'architecture',
  'infrastructure',
]

/** In-memory conversation state store */
const stateStore = new Map<string, ConversationState>()

/** Track per-session recon keyword hit counts */
const reconTracker = new Map<string, Map<string, number>>()

/**
 * Hash content for storage (never store raw input).
 */
function hashContent(content: string): string {
  return createHash('sha256').update(content).digest('hex')
}

/**
 * Build an intent vector from text content.
 *
 * @param content - The text to analyze
 * @param taskEmbedding - The task embedding for alignment computation
 * @returns An IntentVector characterizing the content
 */
function buildIntentVector(
  content: string,
  taskEmbedding: readonly number[],
): IntentVector {
  const embedding = simpleEmbedding(content)
  const alignmentWithTask = taskEmbedding.length > 0
    ? 1 - measureDrift(embedding, taskEmbedding)
    : 0.5

  // Determine dominant topic from content
  const dominantTopic = extractDominantTopic(content)

  // Sensitivity score based on presence of sensitive keywords
  const sensitivityScore = computeSensitivityScore(content)

  return {
    embedding,
    dominantTopic,
    sensitivityScore,
    alignmentWithTask: Math.max(0, Math.min(1, alignmentWithTask)),
  }
}

/**
 * Extract the dominant topic from text using keyword frequency.
 */
function extractDominantTopic(content: string): string {
  const lower = content.toLowerCase()
  const topics: Readonly<Record<string, readonly string[]>> = {
    security: ['security', 'password', 'auth', 'access', 'permission', 'credential'],
    data: ['data', 'database', 'query', 'record', 'table', 'storage'],
    system: ['system', 'config', 'setting', 'admin', 'root', 'server'],
    code: ['code', 'function', 'class', 'variable', 'implement', 'algorithm'],
    general: ['help', 'explain', 'how', 'what', 'why', 'create', 'make'],
  }

  let bestTopic = 'general'
  let bestScore = 0

  for (const [topic, keywords] of Object.entries(topics)) {
    let score = 0
    for (const keyword of keywords) {
      if (lower.includes(keyword)) score++
    }
    if (score > bestScore) {
      bestScore = score
      bestTopic = topic
    }
  }

  return bestTopic
}

/**
 * Compute a sensitivity score for content based on keyword analysis.
 * @returns Score in [0, 1] where 1 = highly sensitive content
 */
function computeSensitivityScore(content: string): number {
  const lower = content.toLowerCase()
  let hits = 0

  for (const keyword of RECON_KEYWORDS) {
    if (lower.includes(keyword)) hits++
  }

  return Math.min(1.0, hits / 3)
}

/**
 * Compute the cumulative intent vector by averaging all turn vectors.
 */
function computeCumulativeVector(turns: readonly ConversationTurn[]): IntentVector {
  if (turns.length === 0) {
    return { embedding: [], dominantTopic: 'none', sensitivityScore: 0, alignmentWithTask: 1 }
  }

  const lastTurn = turns[turns.length - 1]
  if (lastTurn === undefined) {
    return { embedding: [], dominantTopic: 'none', sensitivityScore: 0, alignmentWithTask: 1 }
  }

  const dim = lastTurn.intentVector.embedding.length
  const avgEmbedding = new Array<number>(dim).fill(0)

  let totalSensitivity = 0
  let totalAlignment = 0

  for (const turn of turns) {
    for (let i = 0; i < dim; i++) {
      const val = turn.intentVector.embedding[i]
      const current = avgEmbedding[i]
      if (val !== undefined && current !== undefined) {
        avgEmbedding[i] = current + val
      }
    }
    totalSensitivity += turn.intentVector.sensitivityScore
    totalAlignment += turn.intentVector.alignmentWithTask
  }

  const count = turns.length
  const normalizedEmbedding = avgEmbedding.map(v => v / count)

  return {
    embedding: normalizedEmbedding,
    dominantTopic: lastTurn.intentVector.dominantTopic,
    sensitivityScore: totalSensitivity / count,
    alignmentWithTask: totalAlignment / count,
  }
}

/**
 * Detect authority escalation patterns in content.
 * @returns Number of authority claim matches
 */
function detectAuthorityShift(content: string): number {
  let shifts = 0
  for (const pattern of AUTHORITY_PATTERNS) {
    if (pattern.test(content)) shifts++
    pattern.lastIndex = 0
  }
  return shifts
}

/**
 * Compute suspicion delta for a turn based on multiple signals.
 */
function computeSuspicionDelta(
  content: string,
  intentVector: IntentVector,
  authorityShifts: number,
  prevState: ConversationState | undefined,
): number {
  let delta = 0

  // Signal 1: Low task alignment
  if (intentVector.alignmentWithTask < 0.5) {
    delta += (0.5 - intentVector.alignmentWithTask) * 0.3
  }

  // Signal 2: High sensitivity content
  delta += intentVector.sensitivityScore * 0.2

  // Signal 3: Authority claims
  delta += authorityShifts * 0.15

  // Signal 4: Escalation patterns
  for (const esc of ESCALATION_PATTERNS) {
    if (esc.pattern.test(content)) {
      delta += esc.severity * 0.2
    }
    esc.pattern.lastIndex = 0
  }

  // Signal 5: Topic drift from previous turn
  if (prevState !== undefined && prevState.turns.length > 0) {
    const lastTurn = prevState.turns[prevState.turns.length - 1]
    if (lastTurn !== undefined) {
      const turnDrift = measureDrift(
        intentVector.embedding,
        lastTurn.intentVector.embedding,
      )
      if (turnDrift > 0.5) {
        delta += turnDrift * 0.1
      }
    }
  }

  return delta
}

/**
 * Check for reconnaissance behavior (repeated probing of similar keywords).
 */
function checkReconnaissance(sessionId: string, content: string): number {
  const lower = content.toLowerCase()
  let tracker = reconTracker.get(sessionId)
  if (tracker === undefined) {
    tracker = new Map()
    reconTracker.set(sessionId, tracker)
  }

  let reconScore = 0
  for (const keyword of RECON_KEYWORDS) {
    if (lower.includes(keyword)) {
      const prevCount = tracker.get(keyword) ?? 0
      const newCount = prevCount + 1
      tracker.set(keyword, newCount)

      // Repeated probing of the same keyword increases suspicion
      if (newCount >= 3) {
        reconScore += 0.1 * (newCount - 2)
      }
    }
  }

  return reconScore
}

/**
 * Add a conversation turn and update the session state.
 * Returns the updated ConversationState (immutable — original is not mutated).
 *
 * @param sessionId - The session identifier
 * @param turn - The turn data (index is auto-assigned)
 * @returns The updated ConversationState
 */
export function addTurn(
  sessionId: string,
  turn: Omit<ConversationTurn, 'index'>,
): ConversationState {
  const prevState = stateStore.get(sessionId)
  const currentTurns = prevState?.turns ?? []
  const turnIndex = currentTurns.length

  const fullTurn: ConversationTurn = {
    ...turn,
    index: turnIndex,
  }

  // Apply sliding window
  const allTurns = [...currentTurns, fullTurn]
  const windowedTurns = allTurns.length > DEFAULT_WINDOW_SIZE
    ? allTurns.slice(allTurns.length - DEFAULT_WINDOW_SIZE)
    : allTurns

  // Compute cumulative metrics
  const cumulativeIntentVector = computeCumulativeVector(windowedTurns)
  const topicDrift = prevState !== undefined
    ? prevState.topicDrift + (1 - fullTurn.intentVector.alignmentWithTask) * 0.1
    : 0

  // Suspicion score: accumulates, NEVER decreases
  const prevSuspicion = prevState?.suspicionScore ?? 0
  const newSuspicion = prevSuspicion + fullTurn.suspicionDelta

  // Track authority shifts
  const authorityShifts = (prevState?.authorityShifts ?? 0) +
    (fullTurn.threatSignals.some(s => s.includes('authority')) ? 1 : 0)

  const escalationDetected = newSuspicion > 0.5 || authorityShifts > 2

  const state: ConversationState = {
    sessionId,
    turns: windowedTurns,
    cumulativeIntentVector,
    suspicionScore: newSuspicion,
    escalationDetected,
    topicDrift,
    authorityShifts,
    lastUpdated: new Date().toISOString(),
  }

  stateStore.set(sessionId, state)
  return state
}

/**
 * Get the current conversation state for a session.
 *
 * @param sessionId - The session identifier
 * @returns The ConversationState or undefined if not found
 */
export function getState(sessionId: string): ConversationState | undefined {
  return stateStore.get(sessionId)
}

/**
 * Scan the latest input in the context of the full conversation.
 * Builds a turn, detects signals, and returns a ScanResult.
 *
 * @param sessionId - The session identifier
 * @param latestInput - The new input text to analyze
 * @returns A ScanResult from the conversation scanner
 */
export async function scan(
  sessionId: string,
  latestInput: string,
): Promise<ScanResult> {
  const start = performance.now()
  const prevState = stateStore.get(sessionId)

  // Build intent vector using task embedding from state or empty
  const taskEmbedding = prevState?.cumulativeIntentVector.embedding ?? []
  const intentVector = buildIntentVector(latestInput, taskEmbedding)

  // Detect authority shifts
  const authorityShifts = detectAuthorityShift(latestInput)

  // Build threat signals
  const threatSignals: string[] = []
  if (authorityShifts > 0) threatSignals.push('authority_shift')
  if (intentVector.sensitivityScore > 0.5) threatSignals.push('sensitive_content')
  if (intentVector.alignmentWithTask < 0.3) threatSignals.push('high_drift')

  // Check for escalation patterns
  for (const esc of ESCALATION_PATTERNS) {
    if (esc.pattern.test(latestInput)) {
      threatSignals.push(`escalation:${esc.severity}`)
    }
    esc.pattern.lastIndex = 0
  }

  // Compute suspicion delta
  const suspicionDelta = computeSuspicionDelta(
    latestInput, intentVector, authorityShifts, prevState,
  )

  // Check reconnaissance
  const reconScore = checkReconnaissance(sessionId, latestInput)
  const adjustedDelta = suspicionDelta + reconScore

  // Create the turn
  const trustTag: TrustTagType = 'user'
  const turn: Omit<ConversationTurn, 'index'> = {
    timestamp: new Date().toISOString(),
    role: 'user',
    contentHash: hashContent(latestInput),
    intentVector,
    trustTag,
    threatSignals,
    suspicionDelta: adjustedDelta,
  }

  // Update state
  const newState = addTurn(sessionId, turn)

  // Determine threat level from cumulative state
  const threatLevel = computeThreatLevel(newState)
  const detected = threatLevel !== 'none'

  const latencyMs = performance.now() - start

  return {
    scannerId: 'conversation-tracker',
    scannerType: 'conversation',
    detected,
    confidence: Math.min(1.0, newState.suspicionScore),
    threatLevel,
    killChainPhase: detected
      ? (newState.authorityShifts > 0 ? 'privilege_escalation' : 'reconnaissance')
      : 'none',
    matchedPatterns: threatSignals,
    rawScore: newState.suspicionScore,
    latencyMs,
    metadata: {
      topicDrift: newState.topicDrift,
      authorityShifts: newState.authorityShifts,
      turnCount: newState.turns.length,
      escalationDetected: newState.escalationDetected,
    },
  }
}

/**
 * Detect escalation signals across the conversation history.
 *
 * @param sessionId - The session identifier
 * @returns Array of AnomalySignals for detected escalation patterns
 */
export function detectEscalation(sessionId: string): readonly AnomalySignal[] {
  const state = stateStore.get(sessionId)
  if (state === undefined) return []

  const signals: AnomalySignal[] = []

  // Check cumulative drift
  if (state.topicDrift > CUMULATIVE_DRIFT_THRESHOLD) {
    signals.push({
      type: 'drift',
      severity: state.topicDrift > 0.6 ? 'high' : 'medium',
      confidence: Math.min(1.0, state.topicDrift / 0.6),
      description: `Cumulative topic drift ${state.topicDrift.toFixed(3)} exceeds threshold ${CUMULATIVE_DRIFT_THRESHOLD}`,
      relatedTurns: state.turns.map(t => t.index),
      killChainPhase: 'reconnaissance',
    })
  }

  // Check authority shifts
  if (state.authorityShifts > 0) {
    signals.push({
      type: 'authority_shift',
      severity: state.authorityShifts > 2 ? 'critical' : 'high',
      confidence: Math.min(1.0, state.authorityShifts / 3),
      description: `${state.authorityShifts} authority escalation attempts detected`,
      relatedTurns: state.turns
        .filter(t => t.threatSignals.includes('authority_shift'))
        .map(t => t.index),
      killChainPhase: 'privilege_escalation',
    })
  }

  // Check escalation pattern
  if (state.escalationDetected) {
    signals.push({
      type: 'escalation',
      severity: 'high',
      confidence: Math.min(1.0, state.suspicionScore),
      description: `Escalation pattern detected: suspicion score ${state.suspicionScore.toFixed(3)}`,
      relatedTurns: state.turns.map(t => t.index),
      killChainPhase: state.authorityShifts > 0 ? 'privilege_escalation' : 'reconnaissance',
    })
  }

  return signals
}

/**
 * Reset conversation state for a session.
 *
 * @param sessionId - The session identifier
 */
export function reset(sessionId: string): void {
  stateStore.delete(sessionId)
  reconTracker.delete(sessionId)
}

/**
 * Compute threat level from conversation state.
 */
function computeThreatLevel(state: ConversationState): ThreatLevel {
  if (state.suspicionScore >= 0.8) return 'critical'
  if (state.suspicionScore >= 0.5 || state.authorityShifts > 2) return 'high'
  if (state.suspicionScore >= 0.3 || state.topicDrift > CUMULATIVE_DRIFT_THRESHOLD) return 'medium'
  if (state.suspicionScore >= 0.1) return 'low'
  return 'none'
}

/**
 * Hash content for external use.
 */
export { hashContent }
