/**
 * Context window integrity monitoring (P1).
 * Detects context poisoning — accumulated "harmless" content that
 * manipulates LLM behavior through contradictions, instruction injection,
 * or trust boundary violations.
 *
 * Partitions context by trust level: system > user > retrieved > external.
 * Implements context decay (older entries receive lower trust weight).
 *
 * Part of Layer 6 — Behavioral Monitoring.
 */

import type { ContextPartition, TrustTag } from '../types/behavioral.js'
import { createHash } from 'node:crypto'

/** Patterns that indicate instruction-like content from non-user sources */
const INSTRUCTION_PATTERNS: readonly RegExp[] = [
  /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|context)/i,
  /(?:you\s+are\s+now|your\s+new\s+role|act\s+as|pretend\s+to\s+be)/i,
  /(?:system\s*:\s*|admin\s*:\s*|developer\s*:\s*)/i,
  /(?:override|bypass|disable)\s+(?:safety|security|restrictions|filters)/i,
  /(?:do\s+not\s+follow|stop\s+following)\s+(?:the|your)\s+(?:rules|instructions)/i,
  /\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]/i,
  /BEGIN\s+(?:SYSTEM|ADMIN|OVERRIDE)\s+(?:MESSAGE|PROMPT|INSTRUCTION)/i,
]

/** Patterns indicating contradictory statements */
const CONTRADICTION_INDICATORS: readonly string[] = [
  'actually',
  'correction',
  'disregard',
  'instead',
  'override',
  'replace',
  'scratch that',
  'forget what',
  'not what i meant',
  'new instructions',
]

/** Maximum age in milliseconds before context decay applies */
const DECAY_WINDOW_MS = 30 * 60 * 1000 // 30 minutes

/** Trust level numeric weights for poison scoring */
const TRUST_WEIGHTS: Readonly<Record<TrustTag['source'], number>> = {
  system: 0.0,      // System content cannot poison
  developer: 0.05,  // Developer content rarely poisons
  user: 0.1,        // User content has low poison potential
  tool_output: 0.4, // Tool output is moderate risk
  retrieved: 0.5,   // Retrieved content is higher risk
  external: 0.8,    // External content is high risk
  untrusted: 1.0,   // Untrusted content is maximum risk
}

/** Internal mutable partition store */
const partitionStore: ContextPartition[] = []

/** Content buffer for contradiction detection */
const contentBuffer: Array<{ readonly content: string; readonly trustTag: TrustTag; readonly addedAt: string }> = []

/**
 * Generate a unique partition ID.
 */
function generatePartitionId(): string {
  return `ctx-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
}

/**
 * Compute SHA-256 hash of content.
 * @param content - The content to hash
 * @returns Hex-encoded hash
 */
function hashContent(content: string): string {
  return createHash('sha256').update(content).digest('hex')
}

/**
 * Check content for instruction-like patterns.
 * @param content - The content to check
 * @returns Array of matched pattern descriptions
 */
function detectInstructions(content: string): readonly string[] {
  const matches: string[] = []
  for (const pattern of INSTRUCTION_PATTERNS) {
    if (pattern.test(content)) {
      matches.push(pattern.source)
    }
    pattern.lastIndex = 0
  }
  return matches
}

/**
 * Compute a decay factor based on content age.
 * Newer content has factor closer to 1.0, older content decays toward 0.0.
 *
 * @param addedAt - ISO timestamp when content was added
 * @returns Decay factor in [0, 1]
 */
function computeDecayFactor(addedAt: string): number {
  const age = Date.now() - new Date(addedAt).getTime()
  if (age <= 0) return 1.0
  if (age >= DECAY_WINDOW_MS) return 0.1 // Minimum weight, never fully zero
  return 1.0 - (age / DECAY_WINDOW_MS) * 0.9
}

/**
 * Add content to the context with a trust tag.
 * Checks for instruction patterns and potential contradictions.
 *
 * @param content - The content being added to context
 * @param trustTag - The trust tag for the content source
 * @returns A new ContextPartition describing the added content
 */
export function addContent(content: string, trustTag: TrustTag): ContextPartition {
  const instructions = detectInstructions(content)
  const contradictions: string[] = []

  // Check for instruction-like content from non-system sources
  if (trustTag.source !== 'system' && trustTag.source !== 'developer' && instructions.length > 0) {
    contradictions.push(
      `Instruction-like content detected from ${trustTag.source} source: ${instructions.join(', ')}`,
    )
  }

  // Check for contradictions with existing content
  for (const existing of contentBuffer) {
    if (existing.trustTag.source !== trustTag.source) {
      const contentLower = content.toLowerCase()
      for (const indicator of CONTRADICTION_INDICATORS) {
        if (contentLower.includes(indicator)) {
          contradictions.push(
            `Potential contradiction with ${existing.trustTag.source} content (indicator: "${indicator}")`,
          )
          break
        }
      }
    }
  }

  const partition: ContextPartition = {
    id: generatePartitionId(),
    trustLevel: trustTag.source,
    contentHash: hashContent(content),
    createdAt: new Date().toISOString(),
    contradictions,
  }

  partitionStore.push(partition)
  contentBuffer.push({
    content,
    trustTag,
    addedAt: partition.createdAt,
  })

  return partition
}

/**
 * Check the integrity of the entire context window.
 * Computes a poison score based on:
 * - Number and severity of contradictions
 * - Trust levels of content sources
 * - Instruction patterns from non-system sources
 * - Content age (decay weighting)
 *
 * @returns Integrity report with clean status, violations, and poison score
 */
export function checkIntegrity(): {
  readonly clean: boolean
  readonly violations: readonly string[]
  readonly poisonScore: number
} {
  const violations: string[] = []
  let totalPoisonScore = 0
  let weightSum = 0

  for (let i = 0; i < partitionStore.length; i++) {
    const partition = partitionStore[i]
    const bufferEntry = contentBuffer[i]
    if (partition === undefined || bufferEntry === undefined) continue

    const decayFactor = computeDecayFactor(partition.createdAt)
    const trustWeight = TRUST_WEIGHTS[partition.trustLevel] ?? 0.5

    // Accumulate contradictions as violations
    for (const contradiction of partition.contradictions) {
      violations.push(contradiction)
    }

    // Poison contribution = trust risk * decay * (1 + contradiction count)
    const contradictionMultiplier = 1 + partition.contradictions.length * 0.5
    totalPoisonScore += trustWeight * decayFactor * contradictionMultiplier
    weightSum += decayFactor
  }

  // Normalize poison score to [0, 1]
  const normalizedScore = weightSum > 0
    ? Math.min(1.0, totalPoisonScore / Math.max(1, partitionStore.length))
    : 0

  return {
    clean: violations.length === 0 && normalizedScore < 0.3,
    violations,
    poisonScore: normalizedScore,
  }
}

/**
 * Get all current context partitions (read-only).
 *
 * @returns Immutable array of ContextPartition objects
 */
export function getPartitions(): readonly ContextPartition[] {
  return [...partitionStore]
}

/**
 * Detect contradictions across all content in the context window.
 * Performs pairwise comparison of content from different trust levels.
 *
 * @returns Array of contradiction descriptions
 */
export function detectContradictions(): readonly string[] {
  const contradictions: string[] = []

  for (let i = 0; i < contentBuffer.length; i++) {
    const entryA = contentBuffer[i]
    if (entryA === undefined) continue

    for (let j = i + 1; j < contentBuffer.length; j++) {
      const entryB = contentBuffer[j]
      if (entryB === undefined) continue

      // Only flag contradictions between different trust levels
      if (entryA.trustTag.source === entryB.trustTag.source) continue

      // Check if later content contains override/contradiction language
      const laterContent = j > i ? entryB.content : entryA.content
      const laterSource = j > i ? entryB.trustTag.source : entryA.trustTag.source
      const earlierSource = j > i ? entryA.trustTag.source : entryB.trustTag.source

      const lowerContent = laterContent.toLowerCase()
      for (const indicator of CONTRADICTION_INDICATORS) {
        if (lowerContent.includes(indicator)) {
          contradictions.push(
            `${laterSource} content contradicts ${earlierSource} content (indicator: "${indicator}")`,
          )
          break
        }
      }
    }
  }

  return contradictions
}

/**
 * Clear all context partitions and content buffer.
 * Used for session reset or testing.
 */
export function clearContext(): void {
  partitionStore.length = 0
  contentBuffer.length = 0
}
