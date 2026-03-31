/**
 * Memory integrity guard (P0).
 * Prevents injection persistence across sessions by signing memory
 * entries with HMAC-SHA256 and verifying integrity on read.
 *
 * Uses SHIELDX_CANARY_SECRET environment variable for signing.
 * Compromised entries are quarantined and excluded from reads.
 *
 * Part of Layer 6 — Behavioral Monitoring.
 */

import type { MemoryEntry, TrustTag } from '../types/behavioral.js'
import { createHash, createHmac } from 'node:crypto'

/** Environment variable name for the signing secret */
const SECRET_ENV_KEY = 'SHIELDX_CANARY_SECRET'

/** Fallback secret for development (NEVER use in production) */
const DEV_FALLBACK_SECRET = 'shieldx-dev-secret-do-not-use-in-production'

/** In-memory store for session memory entries */
const memoryStore = new Map<string, MemoryEntry[]>()

/**
 * Get the signing secret from environment.
 * Falls back to a development secret if not configured.
 *
 * @returns The HMAC signing secret
 */
function getSecret(): string {
  return process.env[SECRET_ENV_KEY] ?? DEV_FALLBACK_SECRET
}

/**
 * Generate a unique memory entry ID.
 */
function generateEntryId(): string {
  return `mem-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
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
 * Compute HMAC-SHA256 signature for a memory entry.
 * Signs: entryId + sessionId + contentHash + trustTag.source + createdAt
 *
 * @param entry - The memory entry fields to sign
 * @param secret - The HMAC secret
 * @returns Hex-encoded HMAC signature
 */
function computeSignature(
  entry: {
    readonly id: string
    readonly sessionId: string
    readonly contentHash: string
    readonly trustSource: string
    readonly createdAt: string
  },
  secret: string,
): string {
  const payload = [
    entry.id,
    entry.sessionId,
    entry.contentHash,
    entry.trustSource,
    entry.createdAt,
  ].join('|')

  return createHmac('sha256', secret).update(payload).digest('hex')
}

/**
 * Write a new memory entry with HMAC signature.
 * The content is hashed (never stored raw) and signed at write time.
 *
 * @param sessionId - The session identifier
 * @param content - The content to store (will be hashed, not stored raw)
 * @param trustTag - The trust tag for the content source
 * @returns The signed MemoryEntry
 */
export function writeMemory(
  sessionId: string,
  content: string,
  trustTag: TrustTag,
): MemoryEntry {
  const id = generateEntryId()
  const contentHash = hashContent(content)
  const createdAt = new Date().toISOString()
  const secret = getSecret()

  const signature = computeSignature(
    { id, sessionId, contentHash, trustSource: trustTag.source, createdAt },
    secret,
  )

  const entry: MemoryEntry = {
    id,
    sessionId,
    contentHash,
    trustTag,
    createdAt,
    signature,
    isQuarantined: false,
  }

  const sessionEntries = memoryStore.get(sessionId) ?? []
  memoryStore.set(sessionId, [...sessionEntries, entry])

  return entry
}

/**
 * Read all non-quarantined memory entries for a session.
 * Quarantined entries are excluded from the result.
 *
 * @param sessionId - The session identifier
 * @returns Immutable array of valid MemoryEntry objects
 */
export function readMemory(sessionId: string): readonly MemoryEntry[] {
  const entries = memoryStore.get(sessionId) ?? []
  return entries.filter(entry => !entry.isQuarantined)
}

/**
 * Verify the integrity of a memory entry by recomputing its HMAC signature.
 * Returns false if the signature does not match (entry has been tampered with).
 *
 * @param entry - The memory entry to verify
 * @returns True if the entry's signature is valid
 */
export function verifyIntegrity(entry: MemoryEntry): boolean {
  if (entry.signature === undefined) return false
  if (entry.isQuarantined) return false

  const secret = getSecret()
  const expectedSignature = computeSignature(
    {
      id: entry.id,
      sessionId: entry.sessionId,
      contentHash: entry.contentHash,
      trustSource: entry.trustTag.source,
      createdAt: entry.createdAt,
    },
    secret,
  )

  return entry.signature === expectedSignature
}

/**
 * Quarantine a memory entry by ID, marking it as compromised.
 * Quarantined entries are excluded from readMemory results.
 *
 * @param entryId - The ID of the entry to quarantine
 */
export function quarantineEntry(entryId: string): void {
  for (const [sessionId, entries] of memoryStore.entries()) {
    const updatedEntries = entries.map(entry => {
      if (entry.id === entryId) {
        return {
          ...entry,
          isQuarantined: true,
          trustTag: {
            ...entry.trustTag,
            integrity: 'compromised' as const,
          },
        }
      }
      return entry
    })
    memoryStore.set(sessionId, updatedEntries)
  }
}

/**
 * Audit all memory entries for a session.
 * Verifies each entry's signature and returns counts.
 *
 * @param sessionId - The session identifier
 * @returns Audit results with counts of valid, compromised, and quarantined entries
 */
export function auditAllEntries(sessionId: string): {
  readonly valid: number
  readonly compromised: number
  readonly quarantined: number
} {
  const entries = memoryStore.get(sessionId) ?? []

  let valid = 0
  let compromised = 0
  let quarantined = 0

  for (const entry of entries) {
    if (entry.isQuarantined) {
      quarantined++
      continue
    }

    if (verifyIntegrity(entry)) {
      valid++
    } else {
      compromised++
    }
  }

  return { valid, compromised, quarantined }
}

/**
 * Clear all memory entries for a session.
 *
 * @param sessionId - The session identifier
 */
export function clearSessionMemory(sessionId: string): void {
  memoryStore.delete(sessionId)
}
