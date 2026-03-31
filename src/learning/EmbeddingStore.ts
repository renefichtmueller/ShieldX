/**
 * pgvector embedding storage for semantic similarity detection.
 * Stores vector embeddings and supports cosine similarity search.
 */

import type { EmbeddingRecord } from '../types/learning.js'
import type { KillChainPhase, ThreatLevel } from '../types/detection.js'

/** Storage backend configuration */
interface EmbeddingStoreConfig {
  readonly backend: 'postgresql' | 'memory'
  readonly connectionString?: string
  readonly dimensions?: number
}

/** Search result with distance metric */
interface EmbeddingSearchResult {
  readonly distance: number
  readonly record: EmbeddingRecord
}

/**
 * EmbeddingStore — pgvector-backed embedding storage.
 *
 * Stores input embeddings and provides cosine similarity search
 * for semantic threat detection. Falls back to in-memory brute-force
 * when PostgreSQL is unavailable.
 */
export class EmbeddingStore {
  private readonly config: EmbeddingStoreConfig
  private pool: unknown | null = null

  // In-memory fallback
  private readonly memRecords: Map<string, EmbeddingRecord> = new Map()

  constructor(config: EmbeddingStoreConfig) {
    this.config = config
  }

  /**
   * Initialize the embedding store.
   * For PostgreSQL, ensures pgvector extension and table exist.
   */
  async initialize(): Promise<void> {
    if (this.config.backend === 'postgresql' && this.config.connectionString !== undefined) {
      const pg = await import('pg')
      this.pool = new pg.Pool({ connectionString: this.config.connectionString })
    }
  }

  /**
   * Store an embedding vector.
   * @param inputHash - SHA-256 hash of the original input
   * @param embedding - Vector embedding array
   * @param phase - Kill chain phase classification
   * @param threatLevel - Threat severity
   */
  async store(
    inputHash: string,
    embedding: readonly number[],
    phase: KillChainPhase,
    threatLevel: ThreatLevel,
  ): Promise<void> {
    const record: EmbeddingRecord = Object.freeze({
      id: inputHash,
      createdAt: new Date().toISOString(),
      inputHash,
      embedding: Object.freeze([...embedding]),
      killChainPhase: phase,
      threatLevel,
      source: 'learned',
    })

    if (this.config.backend === 'postgresql' && this.pool !== null) {
      await this.storePostgres(record)
      return
    }

    this.memRecords.set(inputHash, record)
    // Cap at 50000 records
    if (this.memRecords.size > 50000) {
      const firstKey = this.memRecords.keys().next().value
      if (firstKey !== undefined) {
        this.memRecords.delete(firstKey)
      }
    }
  }

  /**
   * Search for similar embeddings using cosine similarity.
   * @param embedding - Query embedding vector
   * @param limit - Maximum number of results
   * @param threshold - Minimum similarity threshold (0-1, higher = more similar)
   * @returns Sorted results by distance (ascending, lower = more similar)
   */
  async search(
    embedding: readonly number[],
    limit: number = 10,
    threshold: number = 0.3,
  ): Promise<readonly EmbeddingSearchResult[]> {
    if (this.config.backend === 'postgresql' && this.pool !== null) {
      return this.searchPostgres(embedding, limit, threshold)
    }

    return this.searchMemory(embedding, limit, threshold)
  }

  /**
   * Get total number of stored embeddings.
   */
  async count(): Promise<number> {
    if (this.config.backend === 'postgresql' && this.pool !== null) {
      const res = await this.pgQuery('SELECT COUNT(*)::int AS cnt FROM shieldx_embeddings')
      const rows = (res as { rows: readonly Record<string, unknown>[] }).rows
      return Number(rows[0]?.['cnt'] ?? 0)
    }

    return this.memRecords.size
  }

  // ---------------------------------------------------------------------------
  // PostgreSQL implementation
  // ---------------------------------------------------------------------------

  private async storePostgres(record: EmbeddingRecord): Promise<void> {
    const vectorStr = `[${[...record.embedding].join(',')}]`
    await this.pgQuery(
      `INSERT INTO shieldx_embeddings (input_hash, embedding, kill_chain_phase, threat_level, source, metadata)
       VALUES ($1, $2::vector, $3, $4, $5, $6)
       ON CONFLICT (input_hash) DO UPDATE SET
         embedding = EXCLUDED.embedding,
         kill_chain_phase = EXCLUDED.kill_chain_phase,
         threat_level = EXCLUDED.threat_level`,
      [
        record.inputHash, vectorStr,
        record.killChainPhase, record.threatLevel,
        record.source, JSON.stringify(record.metadata ?? {}),
      ],
    )
  }

  private async searchPostgres(
    embedding: readonly number[],
    limit: number,
    threshold: number,
  ): Promise<readonly EmbeddingSearchResult[]> {
    const vectorStr = `[${[...embedding].join(',')}]`
    // Cosine distance: 1 - similarity. threshold=0.3 similarity means distance < 0.7
    const maxDistance = 1 - threshold

    const res = await this.pgQuery(
      `SELECT *, (embedding <=> $1::vector) AS distance
       FROM shieldx_embeddings
       WHERE (embedding <=> $1::vector) < $2
       ORDER BY distance ASC
       LIMIT $3`,
      [vectorStr, maxDistance, limit],
    )

    const rows = (res as { rows: readonly Record<string, unknown>[] }).rows
    return Object.freeze(
      rows.map((row) => Object.freeze({
        distance: Number(row['distance'] ?? 1),
        record: mapRowToEmbedding(row),
      })),
    )
  }

  private async pgQuery(sql: string, params?: unknown[]): Promise<unknown> {
    if (this.pool === null) throw new Error('PostgreSQL pool not initialized')
    const pool = this.pool as { query: (sql: string, params?: unknown[]) => Promise<unknown> }
    return pool.query(sql, params)
  }

  // ---------------------------------------------------------------------------
  // In-memory implementation (brute-force cosine similarity)
  // ---------------------------------------------------------------------------

  private searchMemory(
    queryEmb: readonly number[],
    limit: number,
    threshold: number,
  ): readonly EmbeddingSearchResult[] {
    const results: EmbeddingSearchResult[] = []

    for (const record of this.memRecords.values()) {
      const similarity = cosineSimilarity(queryEmb, record.embedding)
      if (similarity >= threshold) {
        results.push(Object.freeze({
          distance: 1 - similarity,
          record,
        }))
      }
    }

    results.sort((a, b) => a.distance - b.distance)
    return Object.freeze(results.slice(0, limit))
  }
}

/** Compute cosine similarity between two vectors */
function cosineSimilarity(a: readonly number[], b: readonly number[]): number {
  if (a.length !== b.length || a.length === 0) return 0

  let dotProduct = 0
  let normA = 0
  let normB = 0

  for (let i = 0; i < a.length; i++) {
    const aVal = a[i] ?? 0
    const bVal = b[i] ?? 0
    dotProduct += aVal * bVal
    normA += aVal * aVal
    normB += bVal * bVal
  }

  const denominator = Math.sqrt(normA) * Math.sqrt(normB)
  return denominator === 0 ? 0 : dotProduct / denominator
}

/** Map a PostgreSQL row to an EmbeddingRecord */
function mapRowToEmbedding(row: Record<string, unknown>): EmbeddingRecord {
  return Object.freeze({
    id: String(row['id'] ?? ''),
    createdAt: String(row['created_at'] ?? ''),
    inputHash: String(row['input_hash'] ?? ''),
    embedding: Object.freeze(parseVector(row['embedding'])),
    killChainPhase: String(row['kill_chain_phase'] ?? 'none') as EmbeddingRecord['killChainPhase'],
    threatLevel: String(row['threat_level'] ?? 'none') as EmbeddingRecord['threatLevel'],
    source: String(row['source'] ?? 'learned'),
    ...(row['metadata'] != null ? { metadata: row['metadata'] as Readonly<Record<string, unknown>> } : {}),
  })
}

/** Parse a pgvector string representation to number array */
function parseVector(value: unknown): number[] {
  if (Array.isArray(value)) return value.map(Number)
  if (typeof value === 'string') {
    return value
      .replace(/[\[\]]/g, '')
      .split(',')
      .map((s) => Number(s.trim()))
      .filter((n) => !Number.isNaN(n))
  }
  return []
}
