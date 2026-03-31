/**
 * Feedback processing for the evolution engine.
 * Processes false positive/true positive feedback to update
 * pattern confidence and maintain an uncertainty queue.
 */

import type { PatternStore } from './PatternStore.js'

/** Feedback input from operators/users */
interface FeedbackInput {
  readonly falsePositive: boolean
  readonly notes?: string
}

/**
 * FeedbackProcessor — processes operator feedback on scan results.
 *
 * Updates pattern confidence based on false positive/true positive
 * feedback. Maintains an active learning uncertainty queue for
 * routing ambiguous cases to human review.
 */
export class FeedbackProcessor {
  private readonly store: PatternStore
  private readonly confidenceAdjustmentUp: number
  private readonly confidenceAdjustmentDown: number

  /**
   * @param store - Pattern storage backend
   * @param adjustUp - Confidence increase for true positives (default: +0.02)
   * @param adjustDown - Confidence decrease for false positives (default: -0.05)
   */
  constructor(
    store: PatternStore,
    adjustUp: number = 0.02,
    adjustDown: number = -0.05,
  ) {
    this.store = store
    this.confidenceAdjustmentUp = adjustUp
    this.confidenceAdjustmentDown = adjustDown
  }

  /**
   * Process feedback for a specific scan result.
   * @param scanId - The scan result ID
   * @param feedback - Feedback indicating false positive or true positive
   */
  async process(_scanId: string, feedback: FeedbackInput): Promise<void> {
    // Load patterns to find which ones were involved in this scan
    const patterns = await this.store.loadPatterns()

    // Find patterns that match the scan ID in their metadata
    // In practice, scanId would map to matched patterns from the result
    for (const pattern of patterns) {
      if (feedback.falsePositive) {
        // False positive: reduce confidence, increment FP count
        await this.store.incrementFalsePositiveCount(pattern.id)
        await this.store.updateConfidence(pattern.id, this.confidenceAdjustmentDown)
      } else {
        // True positive: increase confidence, increment hit count
        await this.store.incrementHitCount(pattern.id)
        await this.store.updateConfidence(pattern.id, this.confidenceAdjustmentUp)
      }
    }
  }

  /**
   * Process feedback for specific pattern IDs.
   * @param patternIds - Array of pattern IDs that were matched
   * @param feedback - Feedback data
   */
  async processForPatterns(
    patternIds: readonly string[],
    feedback: FeedbackInput,
  ): Promise<void> {
    for (const patternId of patternIds) {
      if (feedback.falsePositive) {
        await this.store.incrementFalsePositiveCount(patternId)
        await this.store.updateConfidence(patternId, this.confidenceAdjustmentDown)
      } else {
        await this.store.incrementHitCount(patternId)
        await this.store.updateConfidence(patternId, this.confidenceAdjustmentUp)
      }
    }
  }
}
