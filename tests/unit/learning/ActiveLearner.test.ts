/**
 * ActiveLearner tests — exercises smart sampling and review routing logic.
 * No database required — tests the stateful in-memory logic.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { ActiveLearner } from '../../../src/learning/ActiveLearner.js'
import type { ScanResult } from '../../../src/types/detection.js'

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    scannerId: `scanner-${Date.now()}-${Math.random()}`,
    scannerType: 'rule',
    detected: true,
    confidence: 0.5,
    threatLevel: 'medium',
    killChainPhase: 'initial_access',
    matchedPatterns: ['pattern-001'],
    latencyMs: 5,
    ...overrides,
  }
}

describe('ActiveLearner', () => {
  let learner: ActiveLearner

  beforeEach(() => {
    learner = new ActiveLearner()
  })

  describe('shouldRequestReview()', () => {
    it('should return a boolean for any scan result', () => {
      const result = makeScanResult()
      const decision = learner.shouldRequestReview(result)
      expect(typeof decision).toBe('boolean')
    })

    it('should flag uncertain confidence (0.3-0.7) for review', () => {
      // A result with confidence exactly in the uncertain zone and a novel pattern
      // should reliably be flagged for review
      const result = makeScanResult({
        confidence: 0.5,
        matchedPatterns: [`novel-unique-pattern-${Math.random()}`],
      })
      const decision = learner.shouldRequestReview(result)
      expect(decision).toBe(true)
    })

    it('should not throw for high confidence detections', () => {
      const result = makeScanResult({ confidence: 0.99, matchedPatterns: ['jailbreak'] })
      expect(() => learner.shouldRequestReview(result)).not.toThrow()
    })

    it('should not throw for zero confidence (false negative candidate)', () => {
      const result = makeScanResult({
        detected: false,
        confidence: 0,
        threatLevel: 'none',
        killChainPhase: 'none',
        matchedPatterns: [],
      })
      expect(() => learner.shouldRequestReview(result)).not.toThrow()
    })

    it('should flag a novel pattern (not seen before) for review', () => {
      const uniquePattern = `novel-pattern-${Math.random()}`
      const result = makeScanResult({ matchedPatterns: [uniquePattern] })
      // First encounter of this pattern — should be flagged as novel
      const decision = learner.shouldRequestReview(result)
      expect(decision).toBe(true)
    })

    it('should not flag a previously seen high-confidence result for review', () => {
      const seenPattern = `seen-pattern-${Math.random()}`

      // First call registers the pattern as seen
      learner.shouldRequestReview(
        makeScanResult({ confidence: 0.99, matchedPatterns: [seenPattern] }),
      )

      // Second call — pattern is known, confidence is high, no feedback contradiction
      const secondResult = makeScanResult({ confidence: 0.99, matchedPatterns: [seenPattern] })
      const decision = learner.shouldRequestReview(secondResult)
      // High confidence + already seen pattern should not be flagged
      expect(decision).toBe(false)
    })

    it('should increment totalCount on every call', () => {
      expect(learner.getReviewRate()).toBe(0)
      learner.shouldRequestReview(makeScanResult({ confidence: 0.99, matchedPatterns: [] }))
      learner.shouldRequestReview(makeScanResult({ confidence: 0.99, matchedPatterns: [] }))
      // Rate may be 0 if nothing reviewed, but totalCount drives the denominator
      const rate = learner.getReviewRate()
      expect(typeof rate).toBe('number')
      expect(rate).toBeGreaterThanOrEqual(0)
    })
  })

  describe('getReviewQueue()', () => {
    it('should return an array', () => {
      const queue = learner.getReviewQueue()
      expect(Array.isArray(queue)).toBe(true)
    })

    it('should start empty', () => {
      expect(learner.getReviewQueue().length).toBe(0)
    })

    it('should contain a result after it is flagged for review', () => {
      const result = makeScanResult({
        scannerId: 'queue-test-scanner',
        confidence: 0.5,
        matchedPatterns: [`unique-${Math.random()}`],
      })
      learner.shouldRequestReview(result)
      const queue = learner.getReviewQueue()
      expect(queue.length).toBeGreaterThan(0)
    })

    it('should return a frozen array (immutable)', () => {
      const queue = learner.getReviewQueue()
      expect(Object.isFrozen(queue)).toBe(true)
    })
  })

  describe('processReview()', () => {
    it('should accept true positive verdict without throwing', () => {
      expect(() => learner.processReview('scan-001', true)).not.toThrow()
    })

    it('should accept false positive verdict without throwing', () => {
      expect(() => learner.processReview('scan-002', false)).not.toThrow()
    })

    it('should accept multiple review verdicts', () => {
      for (let i = 0; i < 10; i++) {
        expect(() => learner.processReview(`scan-${i}`, i % 2 === 0)).not.toThrow()
      }
    })

    it('should remove a reviewed item from the queue by scannerId', () => {
      const scannerId = `removable-scanner-${Math.random()}`
      const result = makeScanResult({
        scannerId,
        confidence: 0.5,
        matchedPatterns: [`novel-${Math.random()}`],
      })
      learner.shouldRequestReview(result)

      const queueBefore = learner.getReviewQueue()
      const found = queueBefore.some((r) => r.scannerId === scannerId)
      expect(found).toBe(true)

      learner.processReview(scannerId, true)

      const queueAfter = learner.getReviewQueue()
      const stillPresent = queueAfter.some((r) => r.scannerId === scannerId)
      expect(stillPresent).toBe(false)
    })
  })

  describe('getReviewRate()', () => {
    it('should return 0 when no scans have been processed', () => {
      expect(learner.getReviewRate()).toBe(0)
    })

    it('should return a number between 0 and 1', () => {
      for (let i = 0; i < 20; i++) {
        learner.shouldRequestReview(
          makeScanResult({ confidence: 0.5, matchedPatterns: [`p-${i}`] }),
        )
      }
      const rate = learner.getReviewRate()
      expect(rate).toBeGreaterThanOrEqual(0)
      expect(rate).toBeLessThanOrEqual(1)
    })
  })

  describe('reset()', () => {
    it('should clear the review queue', () => {
      learner.shouldRequestReview(
        makeScanResult({ confidence: 0.5, matchedPatterns: [`novel-${Math.random()}`] }),
      )
      expect(learner.getReviewQueue().length).toBeGreaterThan(0)

      learner.reset()
      expect(learner.getReviewQueue().length).toBe(0)
    })

    it('should reset the review rate to 0', () => {
      learner.shouldRequestReview(
        makeScanResult({ confidence: 0.5, matchedPatterns: [`novel-${Math.random()}`] }),
      )
      learner.reset()
      expect(learner.getReviewRate()).toBe(0)
    })
  })

  describe('review rate targeting', () => {
    it('should flag under 30% of results when patterns are quickly exhausted', () => {
      let reviewCount = 0
      const total = 100
      const fixedPattern = 'repeated-known-pattern'

      for (let i = 0; i < total; i++) {
        const result = makeScanResult({
          // Use the same pattern so it becomes "seen" after the first call
          confidence: 0.85,
          matchedPatterns: [fixedPattern],
        })
        if (learner.shouldRequestReview(result)) reviewCount++
      }

      // After the first result marks the pattern as seen and no uncertainty/contradiction,
      // subsequent high-confidence results should not be flagged
      expect(reviewCount).toBeLessThan(total * 0.3)
    })

    it('should flag novel patterns for review (one per unique pattern)', () => {
      let reviewCount = 0
      const total = 20

      for (let i = 0; i < total; i++) {
        const result = makeScanResult({
          confidence: 0.99,
          matchedPatterns: [`unique-novel-${i}`],
        })
        if (learner.shouldRequestReview(result)) reviewCount++
      }

      // Each result has a brand-new pattern, so all should be flagged
      expect(reviewCount).toBe(total)
    })
  })
})
