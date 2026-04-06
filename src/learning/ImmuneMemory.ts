/**
 * ImmuneMemory — Biological Immune System-Inspired Attack Memory.
 *
 * Stores embeddings of every detected attack in the EmbeddingStore.
 * When a new input arrives, checks similarity against stored attack
 * patterns for rapid pre-classification — bypassing expensive scanners
 * when a known attack is re-encountered.
 *
 * Implements clonal selection: high-hit patterns survive decay cycles,
 * while low-hit patterns are pruned. False positives can be marked
 * and suppressed.
 *
 * MITRE ATLAS: AML.T0051 (known-pattern rapid recall)
 */

import { createHash } from 'node:crypto'

import type { KillChainPhase, ShieldXResult, ThreatLevel } from '../types/detection.js'
import type { EmbeddingStore } from './EmbeddingStore.js'
import { bagOfWordsEmbedding } from '../semantic/SemanticContrastiveScanner.js'

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

/** Configuration for the ImmuneMemory module */
export interface ImmuneMemoryConfig {
  readonly enabled: boolean
  readonly similarityThreshold: number     // default: 0.85 (pre-classify)
  readonly boostThreshold: number          // default: 0.60 (boost suspicion)
  readonly maxMemories: number             // default: 10_000
  readonly decayEnabled: boolean           // default: true
  readonly decayIntervalMs: number         // default: 86_400_000 (24h)
}

/** A single memory match against a stored attack pattern */
export interface MemoryMatch {
  readonly similarity: number
  readonly originalPhase: string
  readonly originalThreatLevel: string
  readonly hitCount: number
  readonly wasFalsePositive: boolean
  readonly firstSeen: string
  readonly lastSeen: string
}

/** Result from checking input against immune memory */
export interface ImmuneMemoryResult {
  readonly matched: boolean
  readonly matches: readonly MemoryMatch[]
  readonly suspicionBoost: number          // 0-1 to add to pipeline
  readonly preClassified: boolean          // high similarity -> skip some scanners
  readonly preClassifiedPhase: string | null
}

/** Internal metadata stored alongside each memory embedding */
interface MemoryMetadata {
  readonly phase: KillChainPhase
  readonly threatLevel: ThreatLevel
  readonly hitCount: number
  readonly falsePositive: boolean
  readonly firstSeen: string
  readonly lastSeen: string
}

/** Stats returned by getStats() */
export interface ImmuneMemoryStats {
  readonly totalMemories: number
  readonly avgHitCount: number
  readonly fpCount: number
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_CONFIG: ImmuneMemoryConfig = Object.freeze({
  enabled: true,
  similarityThreshold: 0.85,
  boostThreshold: 0.60,
  maxMemories: 10_000,
  decayEnabled: true,
  decayIntervalMs: 86_400_000,
})

/** Minimum hit count to survive a decay cycle */
const DECAY_MIN_HIT_COUNT = 2

/** Minimum age (ms) before a low-hit memory is eligible for decay */
const DECAY_MIN_AGE_MS = 7 * 24 * 60 * 60 * 1000 // 7 days

/** Number of nearest neighbours to retrieve on recall */
const RECALL_TOP_K = 5

// ---------------------------------------------------------------------------
// ImmuneMemory
// ---------------------------------------------------------------------------

/**
 * ImmuneMemory — adaptive attack memory with clonal selection.
 *
 * Stores detected attacks as embeddings. On recall, queries the top-K
 * nearest neighbours and produces a suspicion boost or pre-classification.
 */
export class ImmuneMemory {
  private readonly config: ImmuneMemoryConfig
  private readonly store: EmbeddingStore

  /**
   * In-memory metadata index keyed by inputHash.
   * Kept separate from EmbeddingStore to avoid coupling metadata schema.
   */
  private readonly metadata: Map<string, MemoryMetadata> = new Map()

  constructor(
    config: Partial<ImmuneMemoryConfig> = {},
    embeddingStore: EmbeddingStore,
  ) {
    this.config = Object.freeze({ ...DEFAULT_CONFIG, ...config })
    this.store = embeddingStore
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Record a detected attack in immune memory.
   *
   * Generates an embedding of the input, stores it in the EmbeddingStore,
   * and tracks metadata (phase, threat level, hit count, timestamps).
   *
   * If the input already exists in memory, increments hit count and
   * updates lastSeen (extending its survival through decay cycles).
   *
   * @param input - The raw input string that triggered detection
   * @param result - The ShieldXResult from the detection pipeline
   */
  async remember(input: string, result: ShieldXResult): Promise<void> {
    if (!this.config.enabled) return

    const inputHash = this.hashInput(input)
    const embedding = bagOfWordsEmbedding(input)

    // Check if we already have this memory
    const existing = this.metadata.get(inputHash)
    if (existing !== undefined) {
      // Clonal expansion: increment hit count, update lastSeen
      const updated: MemoryMetadata = Object.freeze({
        ...existing,
        hitCount: existing.hitCount + 1,
        lastSeen: new Date().toISOString(),
      })
      this.metadata.set(inputHash, updated)
      return
    }

    // Enforce max memories — evict lowest hit count if at capacity
    if (this.metadata.size >= this.config.maxMemories) {
      this.evictLowestHit()
    }

    // Store embedding
    await this.store.store(
      inputHash,
      embedding,
      result.killChainPhase,
      result.threatLevel,
    )

    // Store metadata
    const now = new Date().toISOString()
    const meta: MemoryMetadata = Object.freeze({
      phase: result.killChainPhase,
      threatLevel: result.threatLevel,
      hitCount: 1,
      falsePositive: false,
      firstSeen: now,
      lastSeen: now,
    })
    this.metadata.set(inputHash, meta)
  }

  /**
   * Check if an input matches known attack patterns in memory.
   *
   * Queries the top-K nearest neighbours from the EmbeddingStore.
   * Produces:
   * - preClassified=true if similarity >= similarityThreshold
   * - suspicionBoost > 0 if similarity >= boostThreshold
   *
   * @param input - The raw input string to check
   * @returns ImmuneMemoryResult with match details and boost values
   */
  async recall(input: string): Promise<ImmuneMemoryResult> {
    if (!this.config.enabled) {
      return this.buildEmptyResult()
    }

    const embedding = bagOfWordsEmbedding(input)
    const neighbours = await this.store.search(
      embedding,
      RECALL_TOP_K,
      this.config.boostThreshold,
    )

    if (neighbours.length === 0) {
      return this.buildEmptyResult()
    }

    const matches: MemoryMatch[] = []
    let maxSimilarity = 0
    let preClassifiedPhase: string | null = null

    for (const { distance, record } of neighbours) {
      const similarity = 1 - distance
      const meta = this.metadata.get(record.inputHash)

      // Skip false positives
      if (meta?.falsePositive === true) continue

      const match: MemoryMatch = Object.freeze({
        similarity,
        originalPhase: meta?.phase ?? record.killChainPhase,
        originalThreatLevel: meta?.threatLevel ?? record.threatLevel,
        hitCount: meta?.hitCount ?? 1,
        wasFalsePositive: false,
        firstSeen: meta?.firstSeen ?? record.createdAt,
        lastSeen: meta?.lastSeen ?? record.createdAt,
      })
      matches.push(match)

      // Track highest similarity for pre-classification
      if (similarity > maxSimilarity) {
        maxSimilarity = similarity
        preClassifiedPhase = match.originalPhase
      }

      // Increment hit count on recall (clonal reinforcement)
      if (meta !== undefined) {
        const updated: MemoryMetadata = Object.freeze({
          ...meta,
          hitCount: meta.hitCount + 1,
          lastSeen: new Date().toISOString(),
        })
        this.metadata.set(record.inputHash, updated)
      }
    }

    if (matches.length === 0) {
      return this.buildEmptyResult()
    }

    const preClassified = maxSimilarity >= this.config.similarityThreshold
    const suspicionBoost = this.computeSuspicionBoost(maxSimilarity)

    return Object.freeze({
      matched: true,
      matches: Object.freeze(matches),
      suspicionBoost,
      preClassified,
      preClassifiedPhase: preClassified ? preClassifiedPhase : null,
    })
  }

  /**
   * Mark a memory as a false positive.
   *
   * The memory remains in storage but is suppressed from future recall
   * results, preventing repeated false alarms.
   *
   * @param inputHash - SHA-256 hash of the original input
   */
  async markFalsePositive(inputHash: string): Promise<void> {
    const existing = this.metadata.get(inputHash)
    if (existing === undefined) return

    const updated: MemoryMetadata = Object.freeze({
      ...existing,
      falsePositive: true,
    })
    this.metadata.set(inputHash, updated)
  }

  /**
   * Clonal selection decay cycle.
   *
   * Removes memories that have:
   * - hitCount < DECAY_MIN_HIT_COUNT AND
   * - age > DECAY_MIN_AGE_MS
   *
   * High-hit patterns (frequently re-encountered attacks) survive
   * indefinitely. Low-hit patterns that haven't been seen recently
   * are pruned to make room for new attack signatures.
   *
   * @returns Count of removed and retained memories
   */
  async runDecayCycle(): Promise<{ readonly removed: number; readonly retained: number }> {
    if (!this.config.decayEnabled) {
      return Object.freeze({ removed: 0, retained: this.metadata.size })
    }

    const now = Date.now()
    const toRemove: string[] = []

    for (const [hash, meta] of this.metadata) {
      const ageMs = now - new Date(meta.firstSeen).getTime()
      if (meta.hitCount < DECAY_MIN_HIT_COUNT && ageMs > DECAY_MIN_AGE_MS) {
        toRemove.push(hash)
      }
    }

    for (const hash of toRemove) {
      this.metadata.delete(hash)
    }

    return Object.freeze({
      removed: toRemove.length,
      retained: this.metadata.size,
    })
  }

  /**
   * Get current immune memory statistics.
   *
   * @returns Aggregate stats: total memories, average hit count, FP count
   */
  getStats(): ImmuneMemoryStats {
    let totalHits = 0
    let fpCount = 0

    for (const meta of this.metadata.values()) {
      totalHits += meta.hitCount
      if (meta.falsePositive) fpCount += 1
    }

    const totalMemories = this.metadata.size
    const avgHitCount = totalMemories > 0 ? totalHits / totalMemories : 0

    return Object.freeze({
      totalMemories,
      avgHitCount: Math.round(avgHitCount * 100) / 100,
      fpCount,
    })
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Compute suspicion boost based on similarity.
   * Linear interpolation between boostThreshold (0) and similarityThreshold (1).
   */
  private computeSuspicionBoost(similarity: number): number {
    if (similarity >= this.config.similarityThreshold) return 1.0
    if (similarity < this.config.boostThreshold) return 0.0

    const range = this.config.similarityThreshold - this.config.boostThreshold
    if (range <= 0) return 0.0

    return (similarity - this.config.boostThreshold) / range
  }

  /** Build an empty result for disabled/no-match cases */
  private buildEmptyResult(): ImmuneMemoryResult {
    return Object.freeze({
      matched: false,
      matches: Object.freeze([]),
      suspicionBoost: 0,
      preClassified: false,
      preClassifiedPhase: null,
    })
  }

  /** SHA-256 hash of input text */
  private hashInput(input: string): string {
    return createHash('sha256').update(input).digest('hex')
  }

  /** Evict the memory with the lowest hit count to make room */
  private evictLowestHit(): void {
    let lowestHash: string | null = null
    let lowestHits = Infinity

    for (const [hash, meta] of this.metadata) {
      if (meta.hitCount < lowestHits) {
        lowestHits = meta.hitCount
        lowestHash = hash
      }
    }

    if (lowestHash !== null) {
      this.metadata.delete(lowestHash)
    }
  }
}
