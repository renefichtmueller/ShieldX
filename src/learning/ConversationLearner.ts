/**
 * Multi-turn conversation attack pattern learning.
 * Extracts conversation-level signatures from confirmed multi-turn attacks
 * and builds a library of conversation attack patterns.
 */

import { createHash } from 'node:crypto'

import type { ConversationState } from '../types/behavioral.js'

/** Learned conversation signature */
interface ConversationSignature {
  readonly id: string
  readonly turnCount: number
  readonly suspicionProgression: readonly number[]
  readonly topicShifts: number
  readonly authorityShifts: number
  readonly escalationTurn: number | null
  readonly signatureHash: string
  readonly seenCount: number
  readonly confirmedAttack: boolean
}

/**
 * ConversationLearner — learns multi-turn attack patterns.
 *
 * When a multi-turn attack is confirmed, extracts a conversation-level
 * signature including:
 * - Suspicion score progression across turns
 * - Topic shift patterns
 * - Authority escalation points
 * - Turn count and structure
 *
 * These signatures help detect similar attack strategies in future
 * conversations even when individual turns look benign.
 */
export class ConversationLearner {
  private readonly signatures: Map<string, ConversationSignature> = new Map()

  /**
   * Learn from a completed conversation with attack classification.
   * @param state - The conversation state to learn from
   * @param wasAttack - Whether the conversation was confirmed as an attack
   */
  learnFromConversation(state: ConversationState, wasAttack: boolean): void {
    const signature = extractSignature(state, wasAttack)

    // Check if we have a similar signature already
    const existing = this.signatures.get(signature.signatureHash)
    if (existing !== undefined) {
      // Update seen count
      this.signatures.set(signature.signatureHash, Object.freeze({
        ...existing,
        seenCount: existing.seenCount + 1,
        confirmedAttack: existing.confirmedAttack || wasAttack,
      }))
      return
    }

    this.signatures.set(signature.signatureHash, signature)

    // Cap signature store
    if (this.signatures.size > 10000) {
      // Remove oldest / least seen
      let minKey: string | undefined
      let minCount = Infinity
      for (const [key, sig] of this.signatures) {
        if (sig.seenCount < minCount) {
          minCount = sig.seenCount
          minKey = key
        }
      }
      if (minKey !== undefined) {
        this.signatures.delete(minKey)
      }
    }
  }

  /**
   * Check if a conversation matches a known attack pattern.
   * @param state - Current conversation state
   * @returns Similarity score (0-1) to closest known attack pattern
   */
  matchKnownPattern(state: ConversationState): number {
    const currentSig = extractSignature(state, false)
    let bestSimilarity = 0

    for (const knownSig of this.signatures.values()) {
      if (!knownSig.confirmedAttack) continue

      const similarity = computeSimilarity(currentSig, knownSig)
      if (similarity > bestSimilarity) {
        bestSimilarity = similarity
      }
    }

    return Math.round(bestSimilarity * 1000) / 1000
  }

  /**
   * Get all learned attack signatures.
   */
  getAttackSignatures(): readonly ConversationSignature[] {
    return Object.freeze(
      [...this.signatures.values()].filter((s) => s.confirmedAttack),
    )
  }

  /**
   * Get total number of stored signatures.
   */
  getSignatureCount(): number {
    return this.signatures.size
  }
}

/** Extract a conversation signature from state */
function extractSignature(
  state: ConversationState,
  wasAttack: boolean,
): ConversationSignature {
  // Build suspicion progression from turns
  const suspicionProgression = state.turns.map((turn) => {
    // Accumulate suspicion deltas
    return turn.suspicionDelta
  })

  // Find the turn where escalation was first detected
  let escalationTurn: number | null = null
  for (const turn of state.turns) {
    if (turn.threatSignals.length > 0) {
      escalationTurn = turn.index
      break
    }
  }

  // Count topic shifts (turns where dominant topic changed)
  let topicShifts = 0
  for (let i = 1; i < state.turns.length; i++) {
    const prev = state.turns[i - 1]
    const curr = state.turns[i]
    if (prev !== undefined && curr !== undefined) {
      if (prev.intentVector.dominantTopic !== curr.intentVector.dominantTopic) {
        topicShifts += 1
      }
    }
  }

  // Create a hash of the structural signature
  const signatureData = [
    state.turns.length,
    topicShifts,
    state.authorityShifts,
    escalationTurn ?? -1,
    // Bucket suspicion scores for fuzzy matching
    ...suspicionProgression.map((s) => Math.round(s * 10)),
  ].join(':')

  const signatureHash = createHash('sha256')
    .update(signatureData)
    .digest('hex')
    .slice(0, 32)

  return Object.freeze({
    id: signatureHash,
    turnCount: state.turns.length,
    suspicionProgression: Object.freeze([...suspicionProgression]),
    topicShifts,
    authorityShifts: state.authorityShifts,
    escalationTurn,
    signatureHash,
    seenCount: 1,
    confirmedAttack: wasAttack,
  })
}

/** Compute similarity between two conversation signatures */
function computeSimilarity(
  a: ConversationSignature,
  b: ConversationSignature,
): number {
  // Turn count similarity (normalized)
  const maxTurns = Math.max(a.turnCount, b.turnCount)
  const turnSim = maxTurns > 0 ? 1 - Math.abs(a.turnCount - b.turnCount) / maxTurns : 1

  // Topic shift similarity
  const maxShifts = Math.max(a.topicShifts, b.topicShifts, 1)
  const shiftSim = 1 - Math.abs(a.topicShifts - b.topicShifts) / maxShifts

  // Authority shift similarity
  const maxAuth = Math.max(a.authorityShifts, b.authorityShifts, 1)
  const authSim = 1 - Math.abs(a.authorityShifts - b.authorityShifts) / maxAuth

  // Escalation turn proximity
  let escalationSim = 0.5 // neutral if one has no escalation
  if (a.escalationTurn !== null && b.escalationTurn !== null) {
    const maxEsc = Math.max(a.turnCount, b.turnCount, 1)
    escalationSim = 1 - Math.abs(a.escalationTurn - b.escalationTurn) / maxEsc
  }

  // Weighted combination
  return turnSim * 0.2 + shiftSim * 0.3 + authSim * 0.3 + escalationSim * 0.2
}
