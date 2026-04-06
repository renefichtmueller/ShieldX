/**
 * OverDefenseCalibrator — False Positive Rate Analysis and Threshold Tuning.
 *
 * Loads a corpus of known-benign inputs and runs them through the ShieldX
 * scanner pipeline. Reports which rules/scanners cause the most false
 * positives and suggests candidates for threshold relaxation.
 *
 * The over-defense score (0-1, lower = better) measures how aggressively
 * the system flags benign inputs. A score of 0 means zero false positives;
 * a score of 1 means every benign input was flagged.
 *
 * Used for:
 * - CI/CD regression testing (ensure FPR stays below target)
 * - Production calibration after rule updates
 * - ImmuneMemory false-positive feedback integration
 */

import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

import type { ShieldXResult } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

/** Result from a calibration run */
export interface CalibrationResult {
  readonly overDefenseScore: number
  readonly fpr: number
  readonly triggerWordFPR: Readonly<Record<string, number>>
  readonly suppressionCandidates: readonly string[]
  readonly benignSamplesTested: number
  readonly falsePositiveCount: number
  readonly falsePositiveInputs: readonly string[]
}

/** Shape of a benign corpus entry */
interface BenignCorpusEntry {
  readonly input: string
  readonly description?: string
  readonly category?: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default path to the benign corpus */
const DEFAULT_CORPUS_PATH = resolve(
  import.meta.url.replace('file://', '').replace(/\/[^/]+$/, ''),
  '../../tests/attack-corpus/false-positives.json',
)

/** FPR threshold above which a scanner is flagged for suppression */
const SUPPRESSION_FPR_THRESHOLD = 0.05

// ---------------------------------------------------------------------------
// OverDefenseCalibrator
// ---------------------------------------------------------------------------

/**
 * OverDefenseCalibrator — measures and reports false positive rates.
 *
 * Accepts a scanner function (typically `shield.scanInput`) and runs
 * all benign samples through it, collecting per-scanner FPR metrics.
 */
export class OverDefenseCalibrator {
  private readonly scanner: (input: string) => Promise<ShieldXResult>
  private readonly corpusPath: string

  /**
   * @param scanner - Function that scans a single input (e.g., shield.scanInput)
   * @param benignCorpusPath - Optional override path to benign corpus JSON
   */
  constructor(
    scanner: (input: string) => Promise<ShieldXResult>,
    benignCorpusPath?: string,
  ) {
    this.scanner = scanner
    this.corpusPath = benignCorpusPath ?? DEFAULT_CORPUS_PATH
  }

  /**
   * Run calibration against the benign corpus.
   *
   * Loads benign samples, scans each through the pipeline, and
   * aggregates false positive statistics per scanner/trigger-word.
   *
   * @returns CalibrationResult with FPR breakdown and suppression candidates
   */
  async calibrate(): Promise<CalibrationResult> {
    const corpus = await this.loadCorpus()

    if (corpus.length === 0) {
      return this.buildEmptyResult()
    }

    const falsePositiveInputs: string[] = []
    const scannerFPCounts: Map<string, number> = new Map()
    let falsePositiveCount = 0

    for (const entry of corpus) {
      let result: ShieldXResult
      try {
        result = await this.scanner(entry.input)
      } catch {
        // Scanner failure on a benign input is not a false positive
        continue
      }

      if (result.detected) {
        falsePositiveCount += 1
        falsePositiveInputs.push(entry.input)

        // Track which scanners triggered on this benign input
        for (const scanResult of result.scanResults) {
          if (scanResult.detected) {
            const scannerId = scanResult.scannerId
            const current = scannerFPCounts.get(scannerId) ?? 0
            scannerFPCounts.set(scannerId, current + 1)
          }
        }
      }
    }

    const totalSamples = corpus.length
    const fpr = totalSamples > 0 ? falsePositiveCount / totalSamples : 0
    const overDefenseScore = fpr // Direct mapping: FPR = over-defense score

    // Build per-scanner FPR
    const triggerWordFPR: Record<string, number> = {}
    for (const [scannerId, count] of scannerFPCounts) {
      triggerWordFPR[scannerId] = totalSamples > 0 ? count / totalSamples : 0
    }

    // Identify scanners with FPR > threshold for suppression
    const suppressionCandidates: string[] = []
    for (const [scannerId, scannerFPR] of Object.entries(triggerWordFPR)) {
      if (scannerFPR > SUPPRESSION_FPR_THRESHOLD) {
        suppressionCandidates.push(scannerId)
      }
    }

    return Object.freeze({
      overDefenseScore: Math.round(overDefenseScore * 1000) / 1000,
      fpr: Math.round(fpr * 1000) / 1000,
      triggerWordFPR: Object.freeze(triggerWordFPR),
      suppressionCandidates: Object.freeze(suppressionCandidates),
      benignSamplesTested: totalSamples,
      falsePositiveCount,
      falsePositiveInputs: Object.freeze(falsePositiveInputs),
    })
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /** Load and validate the benign corpus from disk */
  private async loadCorpus(): Promise<readonly BenignCorpusEntry[]> {
    try {
      const raw = await readFile(this.corpusPath, 'utf-8')
      const parsed: unknown = JSON.parse(raw)

      if (!Array.isArray(parsed)) {
        return []
      }

      const entries: BenignCorpusEntry[] = []
      for (const item of parsed) {
        if (
          typeof item === 'object' &&
          item !== null &&
          'input' in item &&
          typeof (item as Record<string, unknown>)['input'] === 'string'
        ) {
          const record = item as Record<string, unknown>
          const desc = typeof record['description'] === 'string' ? record['description'] : undefined
          const cat = typeof record['category'] === 'string' ? record['category'] : undefined
          entries.push({
            input: record['input'] as string,
            ...(desc !== undefined ? { description: desc } : {}),
            ...(cat !== undefined ? { category: cat } : {}),
          })
        }
      }

      return Object.freeze(entries)
    } catch {
      return []
    }
  }

  /** Build an empty result when no corpus is available */
  private buildEmptyResult(): CalibrationResult {
    return Object.freeze({
      overDefenseScore: 0,
      fpr: 0,
      triggerWordFPR: Object.freeze({}),
      suppressionCandidates: Object.freeze([]),
      benignSamplesTested: 0,
      falsePositiveCount: 0,
      falsePositiveInputs: Object.freeze([]),
    })
  }
}
