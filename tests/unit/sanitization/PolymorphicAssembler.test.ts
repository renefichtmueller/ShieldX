import { describe, it, expect, beforeEach } from 'vitest'
import { PolymorphicAssembler } from '../../../src/sanitization/PolymorphicAssembler.js'
import { defaultConfig } from '../../../src/core/config.js'

describe('PolymorphicAssembler', () => {
  let assembler: PolymorphicAssembler

  beforeEach(() => {
    assembler = new PolymorphicAssembler(defaultConfig, 'test-secret-key')
  })

  describe('assemble()', () => {
    it('should include user input in assembled output', () => {
      const result = assembler.assemble('Hello, how are you?', 'You are a helpful assistant.', 'session-1')
      expect(result.assembled).toContain('Hello, how are you?')
    })

    it('should include system prompt in assembled output', () => {
      const result = assembler.assemble('user message', 'System: Be helpful.', 'session-1')
      expect(result.assembled).toContain('System: Be helpful.')
    })

    it('should wrap user input in session-unique XML tags', () => {
      const result = assembler.assemble('my input', 'system prompt', 'session-1')
      expect(result.assembled).toContain(`<${result.sessionTag}>`)
      expect(result.assembled).toContain(`</${result.sessionTag}>`)
    })

    it('should return separator hash', () => {
      const result = assembler.assemble('input', undefined, 'session-1')
      expect(result.separatorHash).toBeTruthy()
      expect(result.separatorHash.length).toBe(16)
    })
  })

  describe('deterministic within session', () => {
    it('should produce the same structure for the same sessionId', () => {
      const result1 = assembler.assemble('input', 'system', 'same-session')
      const result2 = assembler.assemble('input', 'system', 'same-session')
      expect(result1.sessionTag).toBe(result2.sessionTag)
      expect(result1.separatorHash).toBe(result2.separatorHash)
      expect(result1.assembled).toBe(result2.assembled)
    })
  })

  describe('different sessions produce different structures', () => {
    it('should produce different session tags for different sessions', () => {
      const result1 = assembler.assemble('input', 'system', 'session-alpha')
      const result2 = assembler.assemble('input', 'system', 'session-beta')
      expect(result1.sessionTag).not.toBe(result2.sessionTag)
    })

    it('should produce different separator hashes for different sessions', () => {
      const result1 = assembler.assemble('input', 'system', 'session-alpha')
      const result2 = assembler.assemble('input', 'system', 'session-beta')
      expect(result1.separatorHash).not.toBe(result2.separatorHash)
    })
  })

  describe('canary token weaving', () => {
    it('should include canary tokens in assembled output', () => {
      const result = assembler.assemble('input', 'system', 'session-1')
      expect(result.canaryTokens.length).toBeGreaterThan(0)
      for (const token of result.canaryTokens) {
        expect(result.assembled).toContain(token)
      }
    })

    it('should generate tokens with [CANARY:...] format', () => {
      const result = assembler.assemble('input', 'system', 'session-1')
      for (const token of result.canaryTokens) {
        expect(token).toMatch(/^\[CANARY:[a-f0-9]+\]$/)
      }
    })

    it('should generate the configured number of canary tokens', () => {
      const result = assembler.assemble('input', 'system', 'session-1')
      expect(result.canaryTokens.length).toBe(defaultConfig.canary.tokenCount)
    })
  })

  describe('randomization levels', () => {
    it('should report "low" randomization level', () => {
      const lowConfig = { ...defaultConfig, ppa: { ...defaultConfig.ppa, randomizationLevel: 'low' as const } }
      const lowAssembler = new PolymorphicAssembler(lowConfig, 'test-secret')
      const result = lowAssembler.assemble('input', 'system', 'session-1')
      expect(result.randomizationLevel).toBe('low')
    })

    it('should report "medium" randomization level', () => {
      const result = assembler.assemble('input', 'system', 'session-1')
      expect(result.randomizationLevel).toBe('medium')
    })

    it('should report "high" randomization level', () => {
      const highConfig = { ...defaultConfig, ppa: { ...defaultConfig.ppa, randomizationLevel: 'high' as const } }
      const highAssembler = new PolymorphicAssembler(highConfig, 'test-secret')
      const result = highAssembler.assemble('input', 'system', 'session-1')
      expect(result.randomizationLevel).toBe('high')
    })

    it('should produce different output structures at different levels', () => {
      const lowConfig = { ...defaultConfig, ppa: { ...defaultConfig.ppa, randomizationLevel: 'low' as const } }
      const highConfig = { ...defaultConfig, ppa: { ...defaultConfig.ppa, randomizationLevel: 'high' as const } }

      const lowAssembler = new PolymorphicAssembler(lowConfig, 'test-secret')
      const highAssembler = new PolymorphicAssembler(highConfig, 'test-secret')

      const lowResult = lowAssembler.assemble('input text', 'system prompt with multiple lines\nline two\nline three', 'session-1')
      const highResult = highAssembler.assemble('input text', 'system prompt with multiple lines\nline two\nline three', 'session-1')

      // High should generally have more noise separators
      const lowNoiseCount = (lowResult.assembled.match(/---\[/g) || []).length
      const highNoiseCount = (highResult.assembled.match(/---\[/g) || []).length
      expect(highNoiseCount).toBeGreaterThanOrEqual(lowNoiseCount)
    })
  })

  describe('edge cases', () => {
    it('should handle empty user input', () => {
      const result = assembler.assemble('', 'system', 'session-1')
      expect(result.assembled).toBeTruthy()
      expect(result.sessionTag).toBeTruthy()
    })

    it('should handle missing system prompt', () => {
      const result = assembler.assemble('user input', undefined, 'session-1')
      expect(result.assembled).toContain('user input')
    })

    it('should handle missing sessionId by generating one', () => {
      const result = assembler.assemble('user input', 'system')
      expect(result.assembled).toContain('user input')
      expect(result.sessionTag).toBeTruthy()
    })

    it('should return frozen result object', () => {
      const result = assembler.assemble('input', 'system', 'session-1')
      expect(Object.isFrozen(result)).toBe(true)
      expect(Object.isFrozen(result.canaryTokens)).toBe(true)
    })
  })
})
