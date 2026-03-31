/**
 * Session Manager — Manages session state with checkpoint/rollback support.
 *
 * Implements AgentSys memory isolation with separate trusted/untrusted memory zones.
 * Provides in-memory storage with optional PostgreSQL persistence.
 */

import { createHash, randomUUID } from 'node:crypto'
import type { SessionCheckpoint } from '../types/healing.js'

/** Configuration for the session manager */
export interface SessionManagerConfig {
  readonly maxCheckpointsPerSession: number
  readonly persistToPostgres: boolean
  readonly connectionString?: string
}

/** Memory zone classification for AgentSys isolation */
export type MemoryZone = 'trusted' | 'untrusted'

/** A memory entry with zone classification */
export interface MemoryEntry {
  readonly id: string
  readonly zone: MemoryZone
  readonly content: string
  readonly createdAt: string
  readonly hash: string
}

/** Default configuration */
const DEFAULT_CONFIG: SessionManagerConfig = {
  maxCheckpointsPerSession: 10,
  persistToPostgres: false,
}

/**
 * Manages session state with checkpoint/rollback capabilities.
 *
 * Supports AgentSys memory isolation by maintaining separate
 * trusted and untrusted memory zones per session.
 */
export class SessionManager {
  private readonly config: SessionManagerConfig
  /** Internal mutable stores — mutation is contained within class methods */
  private readonly checkpointStore: Map<string, SessionCheckpoint[]>
  private readonly trustedStore: Map<string, MemoryEntry[]>
  private readonly untrustedStore: Map<string, MemoryEntry[]>
  private readonly counterStore: Map<string, number>

  constructor(config: Partial<SessionManagerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
    this.checkpointStore = new Map()
    this.trustedStore = new Map()
    this.untrustedStore = new Map()
    this.counterStore = new Map()
  }

  /**
   * Create a checkpoint of the current session state.
   *
   * @param sessionId - Session identifier
   * @param context - Current conversation context to snapshot
   * @param trustScore - Current trust score (0.0 - 1.0)
   * @returns The created checkpoint
   */
  createCheckpoint(
    sessionId: string,
    context: string,
    trustScore = 1.0
  ): SessionCheckpoint {
    const messageIndex = (this.counterStore.get(sessionId) ?? 0) + 1
    this.counterStore.set(sessionId, messageIndex)

    const checkpoint: SessionCheckpoint = {
      id: randomUUID(),
      sessionId,
      createdAt: new Date().toISOString(),
      messageIndex,
      contextSnapshot: context,
      trustScore,
      isClean: trustScore >= 0.7,
    }

    const existing = this.checkpointStore.get(sessionId) ?? []
    const updated = [...existing, checkpoint]

    // Evict oldest if over limit
    const trimmed =
      updated.length > this.config.maxCheckpointsPerSession
        ? updated.slice(updated.length - this.config.maxCheckpointsPerSession)
        : updated

    this.checkpointStore.set(sessionId, trimmed)

    return checkpoint
  }

  /**
   * Roll back a session to a specific checkpoint.
   *
   * @param sessionId - Session identifier
   * @param checkpointId - Checkpoint to roll back to
   * @returns The restored context string
   * @throws Error if checkpoint not found
   */
  rollback(sessionId: string, checkpointId: string): string {
    const sessionCheckpoints = this.checkpointStore.get(sessionId)
    if (!sessionCheckpoints) {
      throw new Error(`No checkpoints found for session: ${sessionId}`)
    }

    const target = sessionCheckpoints.find((cp) => cp.id === checkpointId)
    if (!target) {
      throw new Error(
        `Checkpoint ${checkpointId} not found in session ${sessionId}`
      )
    }

    // Remove all checkpoints after the rollback target
    const restored = sessionCheckpoints.filter(
      (cp) => cp.messageIndex <= target.messageIndex
    )
    this.checkpointStore.set(sessionId, restored)

    // Reset message counter to the checkpoint's index
    this.counterStore.set(sessionId, target.messageIndex)

    // Purge untrusted memory created after the checkpoint
    const untrusted = this.untrustedStore.get(sessionId) ?? []
    const cleanUntrusted = untrusted.filter(
      (entry) => entry.createdAt <= target.createdAt
    )
    this.untrustedStore.set(sessionId, cleanUntrusted)

    return target.contextSnapshot
  }

  /**
   * Get the latest clean checkpoint for a session.
   *
   * @param sessionId - Session identifier
   * @returns The latest clean checkpoint, or null if none exists
   */
  getLatestCleanCheckpoint(sessionId: string): SessionCheckpoint | null {
    const sessionCheckpoints = this.checkpointStore.get(sessionId) ?? []
    const clean = sessionCheckpoints.filter((cp) => cp.isClean)

    const last = clean[clean.length - 1]
    return last ?? null
  }

  /**
   * Get all checkpoints for a session.
   *
   * @param sessionId - Session identifier
   * @returns Readonly array of checkpoints
   */
  getCheckpoints(sessionId: string): readonly SessionCheckpoint[] {
    return this.checkpointStore.get(sessionId) ?? []
  }

  /**
   * Store a memory entry in the appropriate zone (AgentSys isolation).
   *
   * @param sessionId - Session identifier
   * @param content - Memory content
   * @param zone - Memory zone classification
   * @returns The created memory entry
   */
  storeMemory(
    sessionId: string,
    content: string,
    zone: MemoryZone
  ): MemoryEntry {
    const entry: MemoryEntry = {
      id: randomUUID(),
      zone,
      content,
      createdAt: new Date().toISOString(),
      hash: createHash('sha256').update(content).digest('hex'),
    }

    const store = zone === 'trusted' ? this.trustedStore : this.untrustedStore
    const existing = store.get(sessionId) ?? []
    store.set(sessionId, [...existing, entry])

    return entry
  }

  /**
   * Retrieve memory entries from a specific zone.
   *
   * @param sessionId - Session identifier
   * @param zone - Memory zone to query
   * @returns Readonly array of memory entries
   */
  getMemory(sessionId: string, zone: MemoryZone): readonly MemoryEntry[] {
    const store = zone === 'trusted' ? this.trustedStore : this.untrustedStore
    return store.get(sessionId) ?? []
  }

  /**
   * Purge all untrusted memory for a session (used during session reset).
   *
   * @param sessionId - Session identifier
   * @returns Number of entries purged
   */
  purgeUntrustedMemory(sessionId: string): number {
    const existing = this.untrustedStore.get(sessionId) ?? []
    const count = existing.length
    this.untrustedStore.set(sessionId, [])
    return count
  }

  /**
   * Destroy all data for a session.
   *
   * @param sessionId - Session identifier
   */
  destroySession(sessionId: string): void {
    this.checkpointStore.delete(sessionId)
    this.trustedStore.delete(sessionId)
    this.untrustedStore.delete(sessionId)
    this.counterStore.delete(sessionId)
  }
}
