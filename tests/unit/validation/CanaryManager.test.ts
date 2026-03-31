import { describe, it, expect, beforeEach } from 'vitest'
import { CanaryManager } from '../../../src/validation/CanaryManager.js'

describe('CanaryManager', () => {
  let manager: CanaryManager

  beforeEach(() => {
    manager = new CanaryManager(3, 3_600_000, 16, 'SX_CANARY_')
  })

  describe('token generation', () => {
    it('should generate the initial number of tokens', () => {
      const tokens = manager.getActiveTokens()
      expect(tokens).toHaveLength(3)
    })

    it('should generate unique tokens', () => {
      const tokens = manager.getActiveTokens()
      const uniqueTokens = new Set(tokens)
      expect(uniqueTokens.size).toBe(tokens.length)
    })

    it('should generate tokens with the configured prefix', () => {
      const tokens = manager.getActiveTokens()
      for (const token of tokens) {
        expect(token.startsWith('SX_CANARY_')).toBe(true)
      }
    })

    it('should generate tokens with random hex content', () => {
      const tokens = manager.getActiveTokens()
      for (const token of tokens) {
        const hex = token.replace('SX_CANARY_', '')
        expect(hex).toMatch(/^[a-f0-9]+$/)
        expect(hex.length).toBe(32) // 16 bytes * 2 hex chars
      }
    })

    it('should generate new token via generateToken()', () => {
      const initialCount = manager.getActiveTokens().length
      const newToken = manager.generateToken()
      expect(newToken.startsWith('SX_CANARY_')).toBe(true)
      expect(manager.getActiveTokens().length).toBe(initialCount + 1)
    })

    it('should generate multiple tokens via generateTokens()', () => {
      const initialCount = manager.getActiveTokens().length
      const newTokens = manager.generateTokens(5)
      expect(newTokens).toHaveLength(5)
      expect(manager.getActiveTokens().length).toBe(initialCount + 5)
    })

    it('should generate different tokens on each call', () => {
      const token1 = manager.generateToken()
      const token2 = manager.generateToken()
      expect(token1).not.toBe(token2)
    })
  })

  describe('leak detection', () => {
    it('should detect leaked canary token in output', () => {
      const tokens = manager.getActiveTokens()
      const leakedToken = tokens[0]!
      const output = `Here is the response. ${leakedToken} And some more text.`
      const result = manager.checkOutput(output)
      expect(result.leaked).toBe(true)
      expect(result.leakedTokens).toContain(leakedToken)
    })

    it('should detect multiple leaked tokens', () => {
      const tokens = manager.getActiveTokens()
      const output = `Result: ${tokens[0]} and also ${tokens[1]}`
      const result = manager.checkOutput(output)
      expect(result.leaked).toBe(true)
      expect(result.leakedTokens.length).toBe(2)
    })

    it('should not report leak when no tokens are in output', () => {
      const output = 'This is a clean output with no canary tokens.'
      const result = manager.checkOutput(output)
      expect(result.leaked).toBe(false)
      expect(result.leakedTokens).toHaveLength(0)
    })

    it('should check against custom token list when provided', () => {
      const customTokens = ['CUSTOM_TOKEN_1', 'CUSTOM_TOKEN_2']
      const output = 'Output contains CUSTOM_TOKEN_1 somewhere.'
      const result = manager.checkOutput(output, customTokens)
      expect(result.leaked).toBe(true)
      expect(result.leakedTokens).toContain('CUSTOM_TOKEN_1')
    })

    it('should return frozen result', () => {
      const result = manager.checkOutput('no tokens here')
      expect(Object.isFrozen(result)).toBe(true)
      expect(Object.isFrozen(result.leakedTokens)).toBe(true)
    })
  })

  describe('token rotation', () => {
    it('should replace all tokens on rotation', () => {
      const oldTokens = [...manager.getActiveTokens()]
      const newTokens = manager.rotateTokens()
      expect(newTokens.length).toBe(oldTokens.length)
      // New tokens should be different from old tokens
      for (const oldToken of oldTokens) {
        expect(newTokens).not.toContain(oldToken)
      }
    })

    it('should maintain the same token count after rotation', () => {
      const countBefore = manager.getActiveTokens().length
      manager.rotateTokens()
      const countAfter = manager.getActiveTokens().length
      expect(countAfter).toBe(countBefore)
    })

    it('should detect leak after rotation uses new tokens', () => {
      manager.rotateTokens()
      const newTokens = manager.getActiveTokens()
      const output = `Leaked: ${newTokens[0]}`
      const result = manager.checkOutput(output)
      expect(result.leaked).toBe(true)
    })

    it('should not detect old tokens after rotation', () => {
      const oldTokens = [...manager.getActiveTokens()]
      manager.rotateTokens()
      const output = `Old token: ${oldTokens[0]}`
      const result = manager.checkOutput(output)
      expect(result.leaked).toBe(false)
    })
  })

  describe('isRotationDue()', () => {
    it('should return false immediately after construction', () => {
      expect(manager.isRotationDue()).toBe(false)
    })

    it('should return false immediately after rotation', () => {
      manager.rotateTokens()
      expect(manager.isRotationDue()).toBe(false)
    })

    it('should return true when rotation interval has passed', () => {
      // Create manager with very short rotation interval
      const shortManager = new CanaryManager(1, 1, 8, 'TEST_')
      // Wait briefly to exceed 1ms interval
      const start = Date.now()
      while (Date.now() - start < 5) {
        // busy wait
      }
      expect(shortManager.isRotationDue()).toBe(true)
    })
  })

  describe('getActiveTokens()', () => {
    it('should return a frozen copy of tokens', () => {
      const tokens = manager.getActiveTokens()
      expect(Object.isFrozen(tokens)).toBe(true)
    })

    it('should return all active tokens', () => {
      const tokens = manager.getActiveTokens()
      expect(tokens.length).toBeGreaterThan(0)
    })
  })

  describe('custom configuration', () => {
    it('should support custom prefix', () => {
      const custom = new CanaryManager(2, 1000, 8, 'MY_PREFIX_')
      const tokens = custom.getActiveTokens()
      for (const token of tokens) {
        expect(token.startsWith('MY_PREFIX_')).toBe(true)
      }
    })

    it('should support custom token length', () => {
      const custom = new CanaryManager(1, 1000, 8, 'P_')
      const tokens = custom.getActiveTokens()
      const hex = tokens[0]!.replace('P_', '')
      expect(hex.length).toBe(16) // 8 bytes * 2 hex chars
    })
  })
})
