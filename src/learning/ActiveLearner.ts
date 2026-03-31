/**
 * Active learning for smart human review sampling.
 * Routes only the most uncertain or novel cases for human review,
 * targeting ~6% review rate per RLTHF research.
 */

import type { ScanResult } from '../types/detection.js'

/** Uncertainty zone boundaries */
const UNCERTAINTY_LOW = 0.3
const UNCERTAINTY_HIGH = 0.7

/** Maximum review queue size */
const MAX_QUEUE_SIZE = 500

/**
 * ActiveLearner — smart sampling for human review.
 *
 * Determines which scan results should be routed to human reviewers
 * based on:
 * 1. Confidence in uncertainty zone (0.3-0.7)
 * 2. Novel patterns not seen before
 * 3. Contradictions with recent feedback
 *
 * Target: only ~6% of results need human review (RLTHF finding).
 */
export class ActiveLearner {
  private readonly reviewQueue: ScanResult[] = []
  private readonly seenPatterns: Set<string> = new Set()
  private readonly recentFeedback: Map<string, boolean> = new Map()
  private reviewCount: number = 0
  private totalCount: number = 0

  /**
   * Determine if a scan result should be routed to human review.
   * @param scanResult - The scan result to evaluate
   * @returns True if human review is recommended
   */
  shouldRequestReview(scanResult: ScanResult): boolean {
    this.totalCount += 1

    // Criterion 1: Confidence in uncertainty zone
    const isUncertain =
      scanResult.confidence >= UNCERTAINTY_LOW &&
      scanResult.confidence <= UNCERTAINTY_HIGH

    // Criterion 2: Contains novel/unseen patterns
    const hasNovelPattern = scanResult.matchedPatterns.some(
      (p) => !this.seenPatterns.has(p),
    )

    // Track all patterns as seen
    for (const pattern of scanResult.matchedPatterns) {
      this.seenPatterns.add(pattern)
    }

    // Criterion 3: Contradicts recent feedback
    const contradictsFeedback = this.checkFeedbackContradiction(scanResult)

    const shouldReview = isUncertain || hasNovelPattern || contradictsFeedback

    if (shouldReview && this.reviewQueue.length < MAX_QUEUE_SIZE) {
      this.reviewQueue.push(scanResult)
      this.reviewCount += 1
    }

    return shouldReview
  }

  /**
   * Get current review queue (pending human reviews).
   * @returns Array of scan results awaiting review
   */
  getReviewQueue(): readonly ScanResult[] {
    return Object.freeze([...this.reviewQueue])
  }

  /**
   * Process a human review decision.
   * @param scanId - The scan result ID being reviewed
   * @param humanVerdict - True if human confirms it's a real threat
   */
  processReview(scanId: string, humanVerdict: boolean): void {
    // Store feedback for future contradiction detection
    this.recentFeedback.set(scanId, humanVerdict)

    // Cap feedback memory
    if (this.recentFeedback.size > 1000) {
      const firstKey = this.recentFeedback.keys().next().value
      if (firstKey !== undefined) {
        this.recentFeedback.delete(firstKey)
      }
    }

    // Remove from review queue
    const index = this.reviewQueue.findIndex((r) => r.scannerId === scanId)
    if (index >= 0) {
      this.reviewQueue.splice(index, 1)
    }
  }

  /**
   * Get the current review rate (reviews / total scans).
   */
  getReviewRate(): number {
    if (this.totalCount === 0) return 0
    return Math.round((this.reviewCount / this.totalCount) * 1000) / 1000
  }

  /**
   * Clear all state.
   */
  reset(): void {
    this.reviewQueue.length = 0
    this.seenPatterns.clear()
    this.recentFeedback.clear()
    this.reviewCount = 0
    this.totalCount = 0
  }

  /**
   * Check if a scan result contradicts recent human feedback.
   * E.g., scanner detects a pattern that was recently marked false positive.
   */
  private checkFeedbackContradiction(scanResult: ScanResult): boolean {
    // Check if any matched pattern was recently reviewed as false positive
    for (const [, verdict] of this.recentFeedback) {
      // If recent feedback said "not a threat" but scanner says "detected"
      if (!verdict && scanResult.detected && scanResult.confidence > 0.5) {
        return true
      }
    }
    return false
  }
}
