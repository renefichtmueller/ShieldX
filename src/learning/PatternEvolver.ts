/**
 * Pattern evolution engine.
 * Generates new detection pattern variants from successful attacks
 * by generalizing specific patterns and creating mutations.
 */

import { randomUUID } from 'node:crypto'

import type { PatternRecord } from '../types/learning.js'
import type { IncidentReport } from '../types/detection.js'

/**
 * PatternEvolver — evolves detection patterns from confirmed attacks.
 *
 * When an attack is detected, the evolver analyzes the matched patterns
 * and incident to generate new, generalized pattern variants that can
 * catch similar future attacks.
 */
export class PatternEvolver {
  private readonly minConfidence: number
  private readonly maxVariants: number

  /**
   * @param minConfidence - Minimum confidence for new patterns (default: 0.4)
   * @param maxVariants - Maximum variants to generate per evolution (default: 5)
   */
  constructor(minConfidence: number = 0.4, maxVariants: number = 5) {
    this.minConfidence = minConfidence
    this.maxVariants = maxVariants
  }

  /**
   * Evolve a new pattern from an incident and its matched patterns.
   * @param incident - The incident report that triggered evolution
   * @param matchedPatterns - Pattern texts that matched during detection
   * @returns A new pattern record, or null if evolution is not possible
   */
  evolve(incident: IncidentReport, matchedPatterns: readonly string[]): PatternRecord | null {
    if (matchedPatterns.length === 0) return null

    // Take the first matched pattern as the base for evolution
    const basePattern = matchedPatterns[0]
    if (basePattern === undefined) return null

    // Generate a generalized variant
    const generalized = generalizePattern(basePattern)
    if (generalized === null || generalized === basePattern) return null

    return Object.freeze({
      id: randomUUID(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      patternText: generalized,
      patternType: 'regex' as const,
      killChainPhase: incident.killChainPhase,
      confidenceBase: this.minConfidence,
      hitCount: 0,
      falsePositiveCount: 0,
      source: 'learned' as const,
      enabled: true,
      metadata: Object.freeze({
        evolvedFrom: basePattern,
        incidentId: incident.id,
        attackVector: incident.attackVector,
      }),
    })
  }

  /**
   * Generate multiple pattern variants from a base pattern.
   * @param basePattern - The original pattern text
   * @param count - Number of variants to generate
   * @returns Array of variant pattern strings
   */
  generateVariants(basePattern: string, count: number): readonly string[] {
    const variants: string[] = []
    const strategies = [
      generalizePattern,
      addWordBoundaryFlex,
      addCaseInsensitiveVariant,
      insertOptionalWords,
      createSynonymVariant,
    ]

    const maxCount = Math.min(count, this.maxVariants)

    for (const strategy of strategies) {
      if (variants.length >= maxCount) break
      const variant = strategy(basePattern)
      if (variant !== null && variant !== basePattern && !variants.includes(variant)) {
        variants.push(variant)
      }
    }

    return Object.freeze(variants)
  }
}

/**
 * Generalize a pattern by replacing specific words with wildcards.
 * E.g., "ignore previous instructions" → "ignore .{0,20} instructions"
 */
function generalizePattern(pattern: string): string | null {
  const words = pattern.split(/\s+/)
  if (words.length < 3) return null

  // Replace middle words with flexible wildcards
  const midIndex = Math.floor(words.length / 2)
  const result = [...words]
  const midWord = result[midIndex]
  if (midWord !== undefined && midWord.length > 3) {
    result[midIndex] = '.{0,30}'
  }

  return result.join('\\s+')
}

/** Add word boundary flexibility */
function addWordBoundaryFlex(pattern: string): string | null {
  if (pattern.length < 5) return null
  return `\\b${pattern.replace(/\s+/g, '\\s+')}\\b`
}

/** Create a case-insensitive variant */
function addCaseInsensitiveVariant(pattern: string): string | null {
  if (pattern.length < 5) return null
  // Convert first char to character class [Xx]
  const first = pattern[0]
  if (first === undefined) return null
  const lower = first.toLowerCase()
  const upper = first.toUpperCase()
  if (lower === upper) return null
  return `[${upper}${lower}]${pattern.slice(1)}`
}

/** Insert optional filler words between key terms */
function insertOptionalWords(pattern: string): string | null {
  const words = pattern.split(/\s+/)
  if (words.length < 2) return null

  const fillers = '(?:\\s+(?:the|my|all|any|your|our|every))?'
  return words.join(`${fillers}\\s+`)
}

/** Create a basic synonym variant for common injection keywords */
function createSynonymVariant(pattern: string): string | null {
  const synonymMap: Readonly<Record<string, string>> = {
    ignore: '(?:ignore|disregard|forget|skip)',
    previous: '(?:previous|prior|earlier|above|initial)',
    instructions: '(?:instructions?|rules?|guidelines?|directives?|prompts?)',
    system: '(?:system|internal|hidden|secret)',
    execute: '(?:execute|run|perform|carry out)',
    reveal: '(?:reveal|show|display|output|print)',
  }

  let modified = pattern
  let changed = false

  for (const [word, replacement] of Object.entries(synonymMap)) {
    const regex = new RegExp(`\\b${word}\\b`, 'gi')
    if (regex.test(modified)) {
      modified = modified.replace(regex, replacement)
      changed = true
      break // Only replace one word per call to keep variants distinct
    }
  }

  return changed ? modified : null
}
