/**
 * DecompositionDetector — Enhanced Multi-Turn Decomposition Detection.
 *
 * Detects when harmful intent is decomposed across multiple conversation turns:
 * - Each individual turn is benign
 * - Combined intent is harmful
 *
 * Complements ConversationTracker's crescendo/FITD/jigsaw detection with
 * deeper analysis techniques:
 *
 * 1. **Boiling Frog**: Gradual sensitivity shift over 10+ turns with small deltas
 * 2. **Topic Drift**: Conversation naturally drifts to sensitive territory
 * 3. **Role Play Chain**: "Let's play a game" escalation pattern
 * 4. **Fragment Assembly**: Individual turns harmless, combined triggers detection
 *
 * Part of Layer 6 — Behavioral Monitoring.
 *
 * References:
 * - sarendis56 multi-turn attack taxonomy
 * - Schneier et al. 2026 Promptware Kill Chain
 * - MITRE ATLAS AML.T0054 (LLM Multi-Turn Manipulation)
 */

import type { ScanResult, ThreatLevel, KillChainPhase } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Decomposition attack technique type */
export type DecompositionTechnique =
  | 'boiling_frog'
  | 'topic_drift'
  | 'role_play_chain'
  | 'fragment_assembly'

/** Result from decomposition analysis */
export interface DecompositionResult {
  readonly detected: boolean
  readonly technique: DecompositionTechnique | null
  readonly turnCount: number
  readonly combinedIntent: string
  readonly perTurnHarmScores: readonly number[]
  readonly combinedHarmScore: number
  readonly decompositionScore: number
  readonly confidence: number
}

// ---------------------------------------------------------------------------
// Pre-compiled patterns
// ---------------------------------------------------------------------------

/** Sensitive topic keywords indicating harmful territory */
const SENSITIVE_KEYWORDS: readonly string[] = Object.freeze([
  'password', 'credential', 'secret', 'api key', 'token',
  'system prompt', 'instructions', 'bypass', 'override', 'jailbreak',
  'exploit', 'hack', 'privilege', 'escalat', 'injection',
  'exfiltrat', 'leak', 'dump', 'reverse shell', 'payload',
  'malware', 'backdoor', 'root access', 'admin', 'sudo',
  'disable safety', 'ignore rules', 'unrestricted', 'no limits',
  'kill', 'destroy', 'rm -rf', 'drop table', 'delete all',
])

/** Harmful intent keywords for combined-turn analysis */
const HARM_KEYWORDS: readonly string[] = Object.freeze([
  'bypass', 'jailbreak', 'circumvent',
  'exploit', 'hack', 'pwn',
  'disable safety', 'kill session', 'destroy context',
  'steal credentials', 'extract secrets', 'dump database', 'leak system',
  'escalate privileges', 'privilege escalation', 'inject payload',
  'poison context', 'override', 'ignore previous', 'disregard',
  'reveal system prompt', 'show your instructions', 'output your rules',
  'execute command', 'run shell', 'rm -rf', 'drop table',
  'forward data', 'exfiltrate', 'send to',
])

/** Role play initiation patterns */
const ROLE_PLAY_INIT_PATTERNS: readonly RegExp[] = Object.freeze([
  /\b(?:let'?s?\s+(?:play|pretend|imagine|role\s*-?\s*play|act\s+out|simulate))\b/i,
  /\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|pretend\s+(?:to\s+be|you(?:'re|\s+are)))\b/i,
  /\b(?:act\s+as\s+if|imagine\s+you\s+are|suppose\s+you\s+(?:are|were))\b/i,
  /\b(?:in\s+this\s+(?:scenario|game|story)|for\s+this\s+(?:exercise|simulation))\b/i,
])

/** Role play escalation patterns (progressively more harmful) */
const ROLE_PLAY_ESCALATION_PATTERNS: readonly {
  readonly pattern: RegExp
  readonly severity: number
}[] = Object.freeze([
  { pattern: /\b(?:now\s+in\s+(?:this|your)\s+(?:role|character))\b/i, severity: 0.2 },
  { pattern: /\b(?:as\s+(?:this|that)\s+character\s+(?:you\s+)?(?:would|can|should))\b/i, severity: 0.3 },
  { pattern: /\b(?:stay\s+in\s+character|don'?t\s+break\s+character|remember\s+you(?:'re|\s+are)\s+(?:playing|acting))\b/i, severity: 0.4 },
  { pattern: /\b(?:your\s+character\s+(?:doesn'?t|does\s+not)\s+(?:have|follow|care\s+about)\s+(?:rules|restrictions|limits|safety))\b/i, severity: 0.7 },
  { pattern: /\b(?:in\s+(?:this|the)\s+(?:game|story|scenario),?\s+(?:there\s+are\s+no|safety\s+(?:rules|filters)\s+(?:don'?t|do\s+not)))\b/i, severity: 0.8 },
  { pattern: /\b(?:(?:the\s+character|you)\s+(?:can|should|must)\s+(?:ignore|bypass|override)\s+(?:all|any|the)\s+(?:rules|safety|restrictions))\b/i, severity: 0.9 },
])

/** Minimum turns before boiling frog can be detected */
const BOILING_FROG_MIN_TURNS = 6

/** Minimum turns to check for topic drift */
const TOPIC_DRIFT_WINDOW = 5

/** Minimum turns for fragment assembly */
const FRAGMENT_ASSEMBLY_MIN_TURNS = 3

// ---------------------------------------------------------------------------
// Per-session state
// ---------------------------------------------------------------------------

interface SessionState {
  readonly sessionId: string
  readonly turnScores: readonly number[]
  readonly turnContents: readonly string[]
  readonly rolePlayActive: boolean
  readonly rolePlayStartTurn: number
}

const sessionStore = new Map<string, SessionState>()

// ---------------------------------------------------------------------------
// Harm scoring
// ---------------------------------------------------------------------------

/**
 * Compute a harmfulness score for a single text.
 * @returns Score in [0, 1]
 */
function computeHarmScore(text: string): number {
  const lower = text.toLowerCase()
  let hits = 0
  for (const kw of HARM_KEYWORDS) {
    if (lower.includes(kw)) hits++
  }
  return Math.min(1.0, hits / 4)
}

/**
 * Count sensitive keyword hits in text.
 */
function countSensitiveHits(text: string): number {
  const lower = text.toLowerCase()
  let count = 0
  for (const kw of SENSITIVE_KEYWORDS) {
    if (lower.includes(kw)) count++
  }
  return count
}

/**
 * Check if text initiates a role play scenario.
 */
function isRolePlayInitiation(text: string): boolean {
  return ROLE_PLAY_INIT_PATTERNS.some(p => {
    const result = p.test(text)
    p.lastIndex = 0
    return result
  })
}

/**
 * Get role play escalation severity for text.
 * @returns Maximum severity found, or 0 if none
 */
function getRolePlayEscalation(text: string): number {
  let maxSeverity = 0
  for (const { pattern, severity } of ROLE_PLAY_ESCALATION_PATTERNS) {
    if (pattern.test(text)) {
      maxSeverity = Math.max(maxSeverity, severity)
    }
    pattern.lastIndex = 0
  }
  return maxSeverity
}

// ---------------------------------------------------------------------------
// DecompositionDetector Class
// ---------------------------------------------------------------------------

/**
 * DecompositionDetector — Enhanced multi-turn decomposition detection.
 *
 * Maintains per-session state to track conversation evolution and detect
 * when harmful intent is decomposed across multiple individually-benign turns.
 *
 * Usage:
 * ```typescript
 * const detector = new DecompositionDetector()
 * const result = detector.analyze('current input', ['turn1', 'turn2'], 'session-123')
 * if (result.detected) {
 *   console.log(`Technique: ${result.technique}, Score: ${result.decompositionScore}`)
 * }
 * ```
 */
export class DecompositionDetector {
  /**
   * Analyze a new turn in context of conversation history.
   *
   * @param currentInput - The latest user input
   * @param conversationHistory - All previous turns in order
   * @param sessionId - Session identifier for state tracking
   * @returns DecompositionResult with detection details
   */
  analyze(
    currentInput: string,
    conversationHistory: readonly string[],
    sessionId: string,
  ): DecompositionResult {
    // Update session state
    const prevState = sessionStore.get(sessionId)
    const allTurns = [...(prevState?.turnContents ?? conversationHistory), currentInput]
    const currentHarmScore = computeHarmScore(currentInput)
    const allHarmScores = [...(prevState?.turnScores ?? conversationHistory.map(computeHarmScore)), currentHarmScore]

    // Detect role play initiation
    let rolePlayActive = prevState?.rolePlayActive ?? false
    let rolePlayStartTurn = prevState?.rolePlayStartTurn ?? -1
    if (!rolePlayActive && isRolePlayInitiation(currentInput)) {
      rolePlayActive = true
      rolePlayStartTurn = allTurns.length - 1
    }

    // Store updated state
    const updatedState: SessionState = {
      sessionId,
      turnScores: allHarmScores,
      turnContents: allTurns,
      rolePlayActive,
      rolePlayStartTurn,
    }
    sessionStore.set(sessionId, updatedState)

    // Run all detection techniques
    const boilingFrog = this.detectBoilingFrog(allTurns, allHarmScores)
    const topicDrift = this.detectTopicDrift(allTurns)
    const rolePlayChain = this.detectRolePlayChain(allTurns, updatedState)
    const fragmentAssembly = this.detectFragmentAssembly(allTurns, allHarmScores)

    // Pick the highest-confidence technique
    const candidates = [boilingFrog, topicDrift, rolePlayChain, fragmentAssembly]
    const best = candidates.reduce((prev, curr) =>
      curr.confidence > prev.confidence ? curr : prev,
    )

    return best
  }

  /**
   * Convert a DecompositionResult to a ScanResult for the pipeline.
   *
   * @param result - The decomposition analysis result
   * @returns A ScanResult, or null if nothing was detected
   */
  toScanResult(result: DecompositionResult): ScanResult | null {
    if (!result.detected) return null

    const confidence = result.confidence
    const threatLevel: ThreatLevel = confidence >= 0.8
      ? 'critical'
      : confidence >= 0.6
        ? 'high'
        : confidence >= 0.4
          ? 'medium'
          : 'low'

    const killChainPhase: KillChainPhase = result.technique === 'fragment_assembly'
      ? 'initial_access'
      : result.technique === 'role_play_chain'
        ? 'privilege_escalation'
        : 'reconnaissance'

    return Object.freeze({
      scannerId: 'decomposition-detector',
      scannerType: 'behavioral' as const,
      detected: true,
      confidence,
      threatLevel,
      killChainPhase,
      matchedPatterns: Object.freeze([
        `decomposition:${result.technique ?? 'unknown'}`,
        `turns:${result.turnCount}`,
        `combined_harm:${result.combinedHarmScore.toFixed(2)}`,
        `decomposition_score:${result.decompositionScore.toFixed(2)}`,
      ]),
      latencyMs: 0,
      metadata: Object.freeze({
        technique: result.technique,
        turnCount: result.turnCount,
        combinedIntent: result.combinedIntent.slice(0, 200),
        perTurnMaxHarm: Math.max(...result.perTurnHarmScores, 0),
        decompositionScore: result.decompositionScore,
      }),
    })
  }

  /**
   * Reset session state for a given session.
   */
  resetSession(sessionId: string): void {
    sessionStore.delete(sessionId)
  }

  // -------------------------------------------------------------------------
  // Detection technique 1: Boiling Frog
  // -------------------------------------------------------------------------

  /**
   * Detect gradual sensitivity escalation over many turns.
   * Each turn's sensitivity score increases by a small delta,
   * similar to slowly raising temperature on a frog.
   */
  private detectBoilingFrog(
    turns: readonly string[],
    harmScores: readonly number[],
  ): DecompositionResult {
    const emptyResult = this.buildEmptyResult(turns, harmScores)

    if (turns.length < BOILING_FROG_MIN_TURNS) return emptyResult

    // Compute per-turn sensitivity scores
    const sensitivityScores = turns.map(t => countSensitiveHits(t) / Math.max(SENSITIVE_KEYWORDS.length * 0.1, 1))

    // Check for monotonic increase with small deltas
    let increasingCount = 0
    let totalDelta = 0
    for (let i = 1; i < sensitivityScores.length; i++) {
      const curr = sensitivityScores[i] ?? 0
      const prev = sensitivityScores[i - 1] ?? 0
      const delta = curr - prev
      if (delta > 0 && delta < 0.3) {
        increasingCount++
        totalDelta += delta
      }
    }

    // Need majority of turns to show gradual increase
    const ratio = increasingCount / (sensitivityScores.length - 1)
    if (ratio < 0.5 || totalDelta < 0.3) return emptyResult

    // Compute combined harm
    const combined = turns.join(' ')
    const combinedHarm = computeHarmScore(combined)
    const avgPerTurn = harmScores.reduce((s, v) => s + v, 0) / harmScores.length
    const decompositionScore = combinedHarm - avgPerTurn

    if (decompositionScore < 0.15) return emptyResult

    const confidence = Math.min(1.0, ratio * 0.5 + decompositionScore * 0.5 + totalDelta * 0.3)

    return Object.freeze({
      detected: confidence >= 0.4,
      technique: 'boiling_frog' as const,
      turnCount: turns.length,
      combinedIntent: combined.slice(0, 500),
      perTurnHarmScores: Object.freeze([...harmScores]),
      combinedHarmScore: Math.round(combinedHarm * 1000) / 1000,
      decompositionScore: Math.round(decompositionScore * 1000) / 1000,
      confidence: Math.round(confidence * 1000) / 1000,
    })
  }

  // -------------------------------------------------------------------------
  // Detection technique 2: Topic Drift
  // -------------------------------------------------------------------------

  /**
   * Detect when conversation naturally drifts into sensitive territory.
   * First N turns have low sensitive keyword density, last N turns have high.
   */
  private detectTopicDrift(turns: readonly string[]): DecompositionResult {
    const harmScores = turns.map(computeHarmScore)
    const emptyResult = this.buildEmptyResult(turns, harmScores)

    if (turns.length < TOPIC_DRIFT_WINDOW * 2) return emptyResult

    // Count sensitive keywords in first window vs last window
    const firstWindow = turns.slice(0, TOPIC_DRIFT_WINDOW)
    const lastWindow = turns.slice(-TOPIC_DRIFT_WINDOW)

    const firstHits = firstWindow.reduce((sum, t) => sum + countSensitiveHits(t), 0)
    const lastHits = lastWindow.reduce((sum, t) => sum + countSensitiveHits(t), 0)

    // Normalize by window size
    const firstDensity = firstHits / TOPIC_DRIFT_WINDOW
    const lastDensity = lastHits / TOPIC_DRIFT_WINDOW

    // Topic drift detected if last window has significantly more sensitive content
    const driftRatio = lastDensity - firstDensity
    if (driftRatio < 1.0) return emptyResult

    // Check that >60% of last window turns contain sensitive keywords
    const lastWindowSensitive = lastWindow.filter(t => countSensitiveHits(t) > 0).length
    const lastWindowRatio = lastWindowSensitive / TOPIC_DRIFT_WINDOW
    if (lastWindowRatio < 0.6) return emptyResult

    // Check that first window was mostly benign
    const firstWindowSensitive = firstWindow.filter(t => countSensitiveHits(t) > 0).length
    const firstWindowRatio = firstWindowSensitive / TOPIC_DRIFT_WINDOW
    if (firstWindowRatio > 0.3) return emptyResult

    const combined = turns.join(' ')
    const combinedHarm = computeHarmScore(combined)
    const avgPerTurn = harmScores.reduce((s, v) => s + v, 0) / harmScores.length
    const decompositionScore = combinedHarm - avgPerTurn

    const confidence = Math.min(1.0, lastWindowRatio * 0.4 + driftRatio * 0.15 + decompositionScore * 0.4)

    return Object.freeze({
      detected: confidence >= 0.4,
      technique: 'topic_drift' as const,
      turnCount: turns.length,
      combinedIntent: combined.slice(0, 500),
      perTurnHarmScores: Object.freeze([...harmScores]),
      combinedHarmScore: Math.round(combinedHarm * 1000) / 1000,
      decompositionScore: Math.round(decompositionScore * 1000) / 1000,
      confidence: Math.round(confidence * 1000) / 1000,
    })
  }

  // -------------------------------------------------------------------------
  // Detection technique 3: Role Play Chain
  // -------------------------------------------------------------------------

  /**
   * Detect role play initiation followed by escalating requests.
   * "Let's play a game" -> gradually escalates until the character
   * is instructed to ignore safety rules.
   */
  private detectRolePlayChain(
    turns: readonly string[],
    state: SessionState,
  ): DecompositionResult {
    const harmScores = turns.map(computeHarmScore)
    const emptyResult = this.buildEmptyResult(turns, harmScores)

    if (!state.rolePlayActive || state.rolePlayStartTurn < 0) return emptyResult

    // Get turns since role play started
    const rpTurns = turns.slice(state.rolePlayStartTurn)
    if (rpTurns.length < 2) return emptyResult

    // Track escalation severity
    let maxEscalation = 0
    let escalationCount = 0

    for (const turn of rpTurns) {
      const severity = getRolePlayEscalation(turn)
      if (severity > 0) {
        escalationCount++
        maxEscalation = Math.max(maxEscalation, severity)
      }
    }

    if (escalationCount < 1 || maxEscalation < 0.3) return emptyResult

    const combined = rpTurns.join(' ')
    const combinedHarm = computeHarmScore(combined)
    const avgPerTurn = harmScores.reduce((s, v) => s + v, 0) / harmScores.length
    const decompositionScore = Math.max(combinedHarm - avgPerTurn, maxEscalation - avgPerTurn)

    const confidence = Math.min(
      1.0,
      maxEscalation * 0.5 + (escalationCount / rpTurns.length) * 0.25 + decompositionScore * 0.25,
    )

    return Object.freeze({
      detected: confidence >= 0.4,
      technique: 'role_play_chain' as const,
      turnCount: turns.length,
      combinedIntent: combined.slice(0, 500),
      perTurnHarmScores: Object.freeze([...harmScores]),
      combinedHarmScore: Math.round(combinedHarm * 1000) / 1000,
      decompositionScore: Math.round(decompositionScore * 1000) / 1000,
      confidence: Math.round(confidence * 1000) / 1000,
    })
  }

  // -------------------------------------------------------------------------
  // Detection technique 4: Fragment Assembly
  // -------------------------------------------------------------------------

  /**
   * Detect when individual turns are harmless but the concatenation
   * of the last N turns triggers detection.
   * This is the strongest signal — directly tests the decomposition hypothesis.
   */
  private detectFragmentAssembly(
    turns: readonly string[],
    harmScores: readonly number[],
  ): DecompositionResult {
    const emptyResult = this.buildEmptyResult(turns, harmScores)

    if (turns.length < FRAGMENT_ASSEMBLY_MIN_TURNS) return emptyResult

    // Check that individual turns are benign
    const recentTurns = turns.slice(-Math.min(turns.length, 10))
    const recentScores = harmScores.slice(-Math.min(harmScores.length, 10))
    const maxIndividualHarm = Math.max(...recentScores, 0)

    // If any individual turn is already harmful, this isn't decomposition
    if (maxIndividualHarm >= 0.5) return emptyResult

    // Concatenate recent turns and check combined harm
    const combined = recentTurns.join(' ')
    const combinedHarm = computeHarmScore(combined)

    // Decomposition score: how much worse the combined version is
    const avgPerTurn = recentScores.reduce((s, v) => s + v, 0) / recentScores.length
    const decompositionScore = combinedHarm - avgPerTurn

    // Need significant decomposition gap
    if (decompositionScore < 0.2 || combinedHarm < 0.3) return emptyResult

    // Additional check: count sensitive keywords that only appear when combined
    const individualSensitiveHits = recentTurns.reduce((sum, t) => sum + countSensitiveHits(t), 0)
    const combinedSensitiveHits = countSensitiveHits(combined)
    const synergisticHits = combinedSensitiveHits - individualSensitiveHits

    // Boost confidence if combination creates new sensitive keyword matches
    const synergyBonus = synergisticHits > 0 ? 0.1 : 0

    const confidence = Math.min(
      1.0,
      decompositionScore * 0.5 + combinedHarm * 0.3 + (1 - maxIndividualHarm) * 0.2 + synergyBonus,
    )

    return Object.freeze({
      detected: confidence >= 0.4,
      technique: 'fragment_assembly' as const,
      turnCount: turns.length,
      combinedIntent: combined.slice(0, 500),
      perTurnHarmScores: Object.freeze([...harmScores]),
      combinedHarmScore: Math.round(combinedHarm * 1000) / 1000,
      decompositionScore: Math.round(decompositionScore * 1000) / 1000,
      confidence: Math.round(confidence * 1000) / 1000,
    })
  }

  // -------------------------------------------------------------------------
  // Helper
  // -------------------------------------------------------------------------

  /**
   * Build an empty (non-detected) result for early returns.
   */
  private buildEmptyResult(
    turns: readonly string[],
    harmScores: readonly number[],
  ): DecompositionResult {
    return Object.freeze({
      detected: false,
      technique: null,
      turnCount: turns.length,
      combinedIntent: '',
      perTurnHarmScores: Object.freeze([...harmScores]),
      combinedHarmScore: 0,
      decompositionScore: 0,
      confidence: 0,
    })
  }
}
