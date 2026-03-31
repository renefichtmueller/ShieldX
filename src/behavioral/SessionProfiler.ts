/**
 * Session behavioral profiling.
 * Builds and maintains a baseline behavioral profile for each session,
 * enabling deviation detection against established norms.
 *
 * Part of Layer 6 — Behavioral Monitoring.
 */

import type { SessionProfile } from '../types/behavioral.js'
import type { BehavioralContext } from '../types/detection.js'
import { measureDrift } from './ContextDriftDetector.js'

/** In-memory store for session profiles */
const profileStore = new Map<string, SessionProfile>()

/**
 * Generate a simple TF-IDF-like embedding from text.
 * This is a fallback when Ollama is unavailable.
 * Produces a fixed-size vector from character n-gram frequencies.
 *
 * @param text - The input text to embed
 * @param dimensions - The embedding dimensionality (default 64)
 * @returns A normalized numeric vector
 */
function simpleEmbedding(text: string, dimensions: number = 64): readonly number[] {
  const normalized = text.toLowerCase().trim()
  const vector = new Array<number>(dimensions).fill(0)

  // Character trigram hashing into fixed-size vector
  for (let i = 0; i < normalized.length - 2; i++) {
    const trigram = normalized.slice(i, i + 3)
    let hash = 0
    for (let j = 0; j < trigram.length; j++) {
      hash = (hash * 31 + trigram.charCodeAt(j)) | 0
    }
    const idx = Math.abs(hash) % dimensions
    const current = vector[idx]
    if (current !== undefined) {
      vector[idx] = current + 1
    }
  }

  // L2 normalize
  let mag = 0
  for (const v of vector) {
    mag += v * v
  }
  mag = Math.sqrt(mag)

  if (mag === 0) return vector

  return vector.map(v => v / mag)
}

/**
 * Build an initial behavioral profile for a session.
 *
 * @param context - The behavioral context at session start
 * @returns A new immutable SessionProfile
 */
export function buildProfile(context: BehavioralContext): SessionProfile {
  const taskEmbedding = simpleEmbedding(context.taskDescription)
  const allowedToolSet = new Set(context.allowedTools ?? [])

  const profile: SessionProfile = {
    sessionId: context.sessionId,
    taskEmbedding,
    allowedToolSet,
    baselineDriftThreshold: 0.4,
    messagePatterns: [],
    averageIntentAlignment: 1.0,
    createdAt: context.startTime,
    messageCount: 0,
  }

  profileStore.set(context.sessionId, profile)
  return profile
}

/**
 * Update an existing session profile with new observation data.
 * Returns a new immutable profile (never mutates the existing one).
 *
 * @param sessionId - The session identifier
 * @param newData - Partial profile data to merge
 * @returns The updated SessionProfile
 * @throws Error if session not found
 */
export function updateProfile(
  sessionId: string,
  newData: Partial<Pick<SessionProfile, 'messagePatterns' | 'averageIntentAlignment' | 'messageCount'>>,
): SessionProfile {
  const existing = profileStore.get(sessionId)
  if (existing === undefined) {
    throw new Error(`Session profile not found: ${sessionId}`)
  }

  const updated: SessionProfile = {
    sessionId: existing.sessionId,
    taskEmbedding: existing.taskEmbedding,
    allowedToolSet: existing.allowedToolSet,
    baselineDriftThreshold: existing.baselineDriftThreshold,
    messagePatterns: newData.messagePatterns ?? existing.messagePatterns,
    averageIntentAlignment: newData.averageIntentAlignment ?? existing.averageIntentAlignment,
    createdAt: existing.createdAt,
    messageCount: newData.messageCount ?? existing.messageCount,
  }

  profileStore.set(sessionId, updated)
  return updated
}

/**
 * Compare current behavioral metrics against the session baseline.
 * Returns a deviation score where 0 = identical to baseline, 1 = maximum deviation.
 *
 * @param sessionId - The session identifier
 * @param current - Current observation vector (embedding or metric vector)
 * @returns Deviation score in [0, 2]
 * @throws Error if session not found
 */
export function compareToBaseline(sessionId: string, current: readonly number[]): number {
  const profile = profileStore.get(sessionId)
  if (profile === undefined) {
    throw new Error(`Session profile not found: ${sessionId}`)
  }

  return measureDrift(current, profile.taskEmbedding)
}

/**
 * Retrieve a session profile by ID.
 *
 * @param sessionId - The session identifier
 * @returns The SessionProfile or undefined if not found
 */
export function getProfile(sessionId: string): SessionProfile | undefined {
  return profileStore.get(sessionId)
}

/**
 * Remove a session profile from the store.
 *
 * @param sessionId - The session identifier
 */
export function removeProfile(sessionId: string): void {
  profileStore.delete(sessionId)
}

/**
 * Export the simple embedding function for use by other modules.
 */
export { simpleEmbedding }
