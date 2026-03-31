import { describe, it, expect, beforeEach } from 'vitest'
import {
  checkBudget,
  recordUsage,
  getUsage,
  setLimits,
  clearSession,
  setPricing,
} from '../../../src/mcp-guard/ResourceGovernor.js'

describe('ResourceGovernor', () => {
  const sessionId = `test-rg-${Date.now()}-${Math.random()}`

  beforeEach(() => {
    clearSession(sessionId)
  })

  describe('checkBudget()', () => {
    it('should allow requests within budget', () => {
      const result = checkBudget(sessionId, 1000)
      expect(result.allowed).toBe(true)
      expect(result.remaining).toBeGreaterThan(0)
    })

    it('should deny requests exceeding per-request token limit', () => {
      setLimits(sessionId, { maxTokensPerRequest: 500 })
      const result = checkBudget(sessionId, 1000)
      expect(result.allowed).toBe(false)
      expect(result.reason).toContain('per-request token limit')
    })

    it('should deny requests when session budget is exhausted', () => {
      setLimits(sessionId, { maxTokensPerSession: 100 })
      recordUsage(sessionId, 50, 40, 10)
      const result = checkBudget(sessionId, 20)
      expect(result.allowed).toBe(false)
      expect(result.reason).toContain('Session token budget exhausted')
    })

    it('should deny requests when cost budget is exceeded', () => {
      setLimits(sessionId, { maxCostPerSession: 0.001 })
      recordUsage(sessionId, 1000, 1000, 10)
      const result = checkBudget(sessionId, 10000)
      expect(result.allowed).toBe(false)
      expect(result.reason).toContain('Cost budget exceeded')
    })
  })

  describe('rate limiting', () => {
    it('should deny requests when rate limit is exceeded', () => {
      setLimits(sessionId, { maxRequestsPerMinute: 3 })

      // Record 3 requests
      recordUsage(sessionId, 10, 10, 1)
      recordUsage(sessionId, 10, 10, 1)
      recordUsage(sessionId, 10, 10, 1)

      const result = checkBudget(sessionId, 10)
      expect(result.allowed).toBe(false)
      expect(result.reason).toContain('Rate limit exceeded')
    })

    it('should allow requests within rate limit', () => {
      setLimits(sessionId, { maxRequestsPerMinute: 10 })
      recordUsage(sessionId, 10, 10, 1)
      const result = checkBudget(sessionId, 10)
      expect(result.allowed).toBe(true)
    })
  })

  describe('recordUsage()', () => {
    it('should track token usage', () => {
      recordUsage(sessionId, 100, 200, 50)
      const usage = getUsage(sessionId)
      expect(usage.totalInputTokens).toBe(100)
      expect(usage.totalOutputTokens).toBe(200)
      expect(usage.requestCount).toBe(1)
    })

    it('should accumulate usage across requests', () => {
      recordUsage(sessionId, 100, 200, 10)
      recordUsage(sessionId, 150, 300, 20)
      const usage = getUsage(sessionId)
      expect(usage.totalInputTokens).toBe(250)
      expect(usage.totalOutputTokens).toBe(500)
      expect(usage.requestCount).toBe(2)
    })

    it('should calculate cost', () => {
      recordUsage(sessionId, 1000, 1000, 10)
      const usage = getUsage(sessionId)
      expect(usage.totalCost).toBeGreaterThan(0)
    })
  })

  describe('ThinkTrap detection', () => {
    it('should detect high output/input ratio', () => {
      const warnings = recordUsage(sessionId, 10, 10000, 5000)
      expect(warnings.some(w => w.includes('think_trap_detected'))).toBe(true)
    })

    it('should not trigger ThinkTrap for normal ratios', () => {
      const warnings = recordUsage(sessionId, 1000, 2000, 100)
      expect(warnings.some(w => w.includes('think_trap_detected'))).toBe(false)
    })

    it('should not trigger ThinkTrap for small output', () => {
      // Even with high ratio, output below threshold should not trigger
      const warnings = recordUsage(sessionId, 1, 100, 10)
      expect(warnings.some(w => w.includes('think_trap_detected'))).toBe(false)
    })

    it('should include ratio in ThinkTrap warning', () => {
      const warnings = recordUsage(sessionId, 100, 50000, 5000)
      const thinkTrapWarning = warnings.find(w => w.includes('think_trap_detected'))
      expect(thinkTrapWarning).toBeDefined()
      expect(thinkTrapWarning).toContain('output/input ratio')
    })
  })

  describe('cost estimation', () => {
    it('should track cost based on token pricing', () => {
      recordUsage(sessionId, 1000, 500, 10)
      const usage = getUsage(sessionId)
      expect(usage.totalCost).toBeGreaterThan(0)
    })

    it('should respect custom pricing', () => {
      const customSession = `custom-pricing-${Date.now()}`
      setPricing(0.00001, 0.00005)
      recordUsage(customSession, 1000, 1000, 10)
      const usage = getUsage(customSession)
      const expectedCost = (1000 * 0.00001) + (1000 * 0.00005)
      expect(usage.totalCost).toBeCloseTo(expectedCost, 4)
      // Reset to defaults
      setPricing(0.000003, 0.000015)
      clearSession(customSession)
    })
  })

  describe('getUsage()', () => {
    it('should return zero usage for unknown session', () => {
      const usage = getUsage('nonexistent-session-id')
      expect(usage.totalInputTokens).toBe(0)
      expect(usage.totalOutputTokens).toBe(0)
      expect(usage.totalCost).toBe(0)
      expect(usage.requestCount).toBe(0)
    })
  })

  describe('budget warnings', () => {
    it('should warn when approaching session token limit', () => {
      setLimits(sessionId, { maxTokensPerSession: 1000 })
      const warnings = recordUsage(sessionId, 450, 460, 10)
      expect(warnings.some(w => w.includes('session_budget_warning'))).toBe(true)
    })

    it('should warn when approaching cost limit', () => {
      setLimits(sessionId, { maxCostPerSession: 0.01 })
      // Record enough usage to approach the limit
      setPricing(0.001, 0.001)
      const warnings = recordUsage(sessionId, 5, 5, 10)
      expect(warnings.some(w => w.includes('cost_budget_warning'))).toBe(true)
      setPricing(0.000003, 0.000015)
    })
  })

  describe('clearSession()', () => {
    it('should clear all usage data for a session', () => {
      recordUsage(sessionId, 100, 200, 10)
      clearSession(sessionId)
      const usage = getUsage(sessionId)
      expect(usage.totalInputTokens).toBe(0)
      expect(usage.requestCount).toBe(0)
    })
  })
})
