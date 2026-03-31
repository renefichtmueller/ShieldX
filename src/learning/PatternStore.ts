/**
 * Pattern storage (PostgreSQL primary, in-memory fallback).
 * Core persistence layer for the evolution engine.
 */

import { readFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import type { PatternRecord, LearningStats } from '../types/learning.js'
import type { ShieldXResult, IncidentReport } from '../types/detection.js'

/** Storage backend configuration */
interface StorageConfig {
  readonly backend: 'postgresql' | 'memory'
  readonly connectionString?: string
}

/**
 * PatternStore — persistent storage for detection patterns and incidents.
 *
 * Supports PostgreSQL as primary backend (with migrations) and an
 * in-memory Map-based fallback for local/testing use.
 */
export class PatternStore {
  private readonly config: StorageConfig
  private pool: unknown | null = null

  // In-memory fallback storage
  private readonly memPatterns: Map<string, PatternRecord> = new Map()
  private readonly memIncidents: IncidentReport[] = []
  private readonly memResults: ShieldXResult[] = []
  private initialized = false

  constructor(config: StorageConfig) {
    this.config = config
  }

  /**
   * Initialize storage — run migrations for PostgreSQL, no-op for memory.
   */
  async initialize(): Promise<void> {
    if (this.initialized) return

    if (this.config.backend === 'postgresql' && this.config.connectionString !== undefined) {
      await this.initPostgres()
    }

    this.initialized = true
  }

  /**
   * Store a detection result (for pattern learning).
   * @param result - ShieldX scan result to persist
   */
  async store(result: ShieldXResult): Promise<void> {
    if (this.config.backend === 'postgresql' && this.pool !== null) {
      await this.storePostgres(result)
      return
    }

    // Memory fallback
    this.memResults.push(result)
    // Keep last 10000 results
    if (this.memResults.length > 10000) {
      this.memResults.splice(0, this.memResults.length - 10000)
    }
  }

  /**
   * Load all enabled patterns from storage.
   * @returns Array of enabled pattern records
   */
  async loadPatterns(): Promise<readonly PatternRecord[]> {
    if (this.config.backend === 'postgresql' && this.pool !== null) {
      return this.loadPatternsPostgres()
    }

    return Object.freeze(
      [...this.memPatterns.values()].filter((p) => p.enabled),
    )
  }

  /**
   * Save or upsert a pattern record.
   * @param pattern - Pattern record to save
   */
  async savePattern(pattern: PatternRecord): Promise<void> {
    if (this.config.backend === 'postgresql' && this.pool !== null) {
      await this.savePatternPostgres(pattern)
      return
    }

    this.memPatterns.set(pattern.id, pattern)
  }

  /**
   * Get aggregated statistics from the learning layer.
   */
  async getStats(): Promise<LearningStats> {
    if (this.config.backend === 'postgresql' && this.pool !== null) {
      return this.getStatsPostgres()
    }

    return this.getStatsMemory()
  }

  /**
   * Update confidence for a pattern by ID.
   * @param patternId - Pattern to update
   * @param delta - Confidence adjustment (positive or negative)
   */
  async updateConfidence(patternId: string, delta: number): Promise<void> {
    if (this.config.backend === 'postgresql' && this.pool !== null) {
      await this.updateConfidencePostgres(patternId, delta)
      return
    }

    const existing = this.memPatterns.get(patternId)
    if (existing === undefined) return

    const newConfidence = Math.max(0.1, Math.min(0.99, existing.confidenceBase + delta))
    this.memPatterns.set(patternId, {
      ...existing,
      confidenceBase: newConfidence,
      updatedAt: new Date().toISOString(),
    })
  }

  /**
   * Store an incident report.
   * @param report - Incident report to persist
   */
  async storeIncident(report: IncidentReport): Promise<void> {
    if (this.config.backend === 'postgresql' && this.pool !== null) {
      await this.storeIncidentPostgres(report)
      return
    }

    this.memIncidents.push(report)
    // Keep last 10000 incidents
    if (this.memIncidents.length > 10000) {
      this.memIncidents.splice(0, this.memIncidents.length - 10000)
    }
  }

  /**
   * Increment hit count for a pattern.
   * @param patternId - Pattern ID
   */
  async incrementHitCount(patternId: string): Promise<void> {
    if (this.config.backend === 'postgresql' && this.pool !== null) {
      await this.pgQuery(
        'UPDATE shieldx_patterns SET hit_count = hit_count + 1, updated_at = NOW() WHERE id = $1',
        [patternId],
      )
      return
    }

    const existing = this.memPatterns.get(patternId)
    if (existing === undefined) return
    this.memPatterns.set(patternId, {
      ...existing,
      hitCount: existing.hitCount + 1,
      updatedAt: new Date().toISOString(),
    })
  }

  /**
   * Increment false positive count for a pattern.
   * @param patternId - Pattern ID
   */
  async incrementFalsePositiveCount(patternId: string): Promise<void> {
    if (this.config.backend === 'postgresql' && this.pool !== null) {
      await this.pgQuery(
        'UPDATE shieldx_patterns SET false_positive_count = false_positive_count + 1, updated_at = NOW() WHERE id = $1',
        [patternId],
      )
      return
    }

    const existing = this.memPatterns.get(patternId)
    if (existing === undefined) return
    this.memPatterns.set(patternId, {
      ...existing,
      falsePositiveCount: existing.falsePositiveCount + 1,
      updatedAt: new Date().toISOString(),
    })
  }

  // ---------------------------------------------------------------------------
  // PostgreSQL implementation
  // ---------------------------------------------------------------------------

  private async initPostgres(): Promise<void> {
    const pg = await import('pg')
    this.pool = new pg.Pool({ connectionString: this.config.connectionString })

    // Run migrations
    const migrationsDir = join(dirname(fileURLToPath(import.meta.url)), 'migrations')
    const migrationFiles = [
      '001_initial_schema.sql',
      '002_embeddings.sql',
      '003_attack_graph.sql',
      '004_conversation_state.sql',
      '005_drift_history.sql',
    ]

    for (const file of migrationFiles) {
      try {
        const sql = await readFile(join(migrationsDir, file), 'utf-8')
        await this.pgQuery(sql)
      } catch {
        // Migration may already be applied — continue
      }
    }
  }

  private async storePostgres(result: ShieldXResult): Promise<void> {
    const matchedPatterns = result.scanResults
      .flatMap((sr) => [...sr.matchedPatterns])

    await this.pgQuery(
      `INSERT INTO shieldx_incidents (
        threat_level, kill_chain_phase, action_taken,
        matched_rule_ids, input_hash, mitigation_applied, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        result.threatLevel,
        result.killChainPhase,
        result.action,
        matchedPatterns,
        result.id,
        result.healingApplied ? 'auto' : 'none',
        JSON.stringify(result.metadata ?? {}),
      ],
    )
  }

  private async loadPatternsPostgres(): Promise<readonly PatternRecord[]> {
    const res = await this.pgQuery(
      'SELECT * FROM shieldx_patterns WHERE enabled = true ORDER BY confidence_base DESC',
    )
    return Object.freeze(
      (res as { rows: readonly Record<string, unknown>[] }).rows.map(mapRowToPattern),
    )
  }

  private async savePatternPostgres(pattern: PatternRecord): Promise<void> {
    await this.pgQuery(
      `INSERT INTO shieldx_patterns (
        id, pattern_text, pattern_type, kill_chain_phase,
        confidence_base, hit_count, false_positive_count, source, enabled, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      ON CONFLICT (pattern_text, pattern_type)
      DO UPDATE SET
        confidence_base = EXCLUDED.confidence_base,
        hit_count = EXCLUDED.hit_count,
        false_positive_count = EXCLUDED.false_positive_count,
        enabled = EXCLUDED.enabled,
        updated_at = NOW()`,
      [
        pattern.id, pattern.patternText, pattern.patternType,
        pattern.killChainPhase, pattern.confidenceBase,
        pattern.hitCount, pattern.falsePositiveCount,
        pattern.source, pattern.enabled,
        JSON.stringify(pattern.metadata ?? {}),
      ],
    )
  }

  private async getStatsPostgres(): Promise<LearningStats> {
    const patternRes = await this.pgQuery(`
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE source = 'builtin')::int AS builtin,
        COUNT(*) FILTER (WHERE source = 'learned')::int AS learned,
        COUNT(*) FILTER (WHERE source = 'community')::int AS community,
        COUNT(*) FILTER (WHERE source = 'red_team')::int AS red_team
      FROM shieldx_patterns WHERE enabled = true
    `)
    const incidentRes = await this.pgQuery(`
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE occurred_at > NOW() - INTERVAL '24 hours')::int AS recent,
        COALESCE(AVG(CASE WHEN false_positive THEN 1 ELSE 0 END), 0) AS fp_rate
      FROM shieldx_incidents
    `)

    const topRes = await this.pgQuery(
      'SELECT * FROM shieldx_patterns WHERE enabled = true ORDER BY hit_count DESC LIMIT 10',
    )

    const pRow = (patternRes as { rows: readonly Record<string, unknown>[] }).rows[0] ?? {}
    const iRow = (incidentRes as { rows: readonly Record<string, unknown>[] }).rows[0] ?? {}

    return Object.freeze({
      totalPatterns: Number(pRow['total'] ?? 0),
      builtinPatterns: Number(pRow['builtin'] ?? 0),
      learnedPatterns: Number(pRow['learned'] ?? 0),
      communityPatterns: Number(pRow['community'] ?? 0),
      redTeamPatterns: Number(pRow['red_team'] ?? 0),
      totalIncidents: Number(iRow['total'] ?? 0),
      falsePositiveRate: Number(iRow['fp_rate'] ?? 0),
      topPatterns: Object.freeze(
        (topRes as { rows: readonly Record<string, unknown>[] }).rows.map(mapRowToPattern),
      ),
      recentIncidents: Number(iRow['recent'] ?? 0),
      driftDetected: false,
    })
  }

  private async updateConfidencePostgres(patternId: string, delta: number): Promise<void> {
    await this.pgQuery(
      `UPDATE shieldx_patterns
       SET confidence_base = GREATEST(0.1, LEAST(0.99, confidence_base + $2)),
           updated_at = NOW()
       WHERE id = $1`,
      [patternId, delta],
    )
  }

  private async storeIncidentPostgres(report: IncidentReport): Promise<void> {
    await this.pgQuery(
      `INSERT INTO shieldx_incidents (
        id, session_id, user_id, threat_level, kill_chain_phase,
        action_taken, matched_rule_ids, input_hash,
        mitigation_applied, false_positive, atlas_mapping, owasp_mapping, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [
        report.id, report.sessionId ?? null, report.userId ?? null,
        report.threatLevel, report.killChainPhase, report.action,
        [...report.matchedPatterns], report.inputHash,
        report.mitigationApplied, report.falsePositive ?? false,
        report.atlasMapping ?? null, report.owaspMapping ?? null,
        JSON.stringify(report.metadata ?? {}),
      ],
    )
  }

  private async pgQuery(sql: string, params?: unknown[]): Promise<unknown> {
    if (this.pool === null) throw new Error('PostgreSQL pool not initialized')
    const pool = this.pool as { query: (sql: string, params?: unknown[]) => Promise<unknown> }
    return pool.query(sql, params)
  }

  // ---------------------------------------------------------------------------
  // In-memory stats
  // ---------------------------------------------------------------------------

  private getStatsMemory(): LearningStats {
    const patterns = [...this.memPatterns.values()]
    const enabledPatterns = patterns.filter((p) => p.enabled)

    const totalFP = patterns.reduce((sum, p) => sum + p.falsePositiveCount, 0)
    const totalHits = patterns.reduce((sum, p) => sum + p.hitCount, 0)
    const fpRate = totalHits > 0 ? totalFP / (totalHits + totalFP) : 0

    const oneDayAgo = new Date(Date.now() - 86_400_000).toISOString()
    const recentIncidents = this.memIncidents.filter((i) => i.timestamp > oneDayAgo).length

    const topPatterns = [...enabledPatterns]
      .sort((a, b) => b.hitCount - a.hitCount)
      .slice(0, 10)

    return Object.freeze({
      totalPatterns: enabledPatterns.length,
      builtinPatterns: enabledPatterns.filter((p) => p.source === 'builtin').length,
      learnedPatterns: enabledPatterns.filter((p) => p.source === 'learned').length,
      communityPatterns: enabledPatterns.filter((p) => p.source === 'community').length,
      redTeamPatterns: enabledPatterns.filter((p) => p.source === 'red_team').length,
      totalIncidents: this.memIncidents.length,
      falsePositiveRate: Math.round(fpRate * 1000) / 1000,
      topPatterns: Object.freeze(topPatterns),
      recentIncidents,
      driftDetected: false,
    })
  }
}

/** Map a PostgreSQL row to a PatternRecord */
function mapRowToPattern(row: Record<string, unknown>): PatternRecord {
  return Object.freeze({
    id: String(row['id'] ?? ''),
    createdAt: String(row['created_at'] ?? ''),
    updatedAt: String(row['updated_at'] ?? ''),
    patternText: String(row['pattern_text'] ?? ''),
    patternType: String(row['pattern_type'] ?? 'rule') as PatternRecord['patternType'],
    killChainPhase: String(row['kill_chain_phase'] ?? 'none') as PatternRecord['killChainPhase'],
    confidenceBase: Number(row['confidence_base'] ?? 0.5),
    hitCount: Number(row['hit_count'] ?? 0),
    falsePositiveCount: Number(row['false_positive_count'] ?? 0),
    source: String(row['source'] ?? 'builtin') as PatternRecord['source'],
    enabled: Boolean(row['enabled'] ?? true),
    ...(row['metadata'] != null ? { metadata: row['metadata'] as Readonly<Record<string, unknown>> } : {}),
  })
}
