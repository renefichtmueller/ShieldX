import { describe, it, expect, beforeEach } from 'vitest'
import { UnicodeNormalizer } from '../../../src/preprocessing/UnicodeNormalizer.js'
import { defaultConfig } from '../../../src/core/config.js'

describe('UnicodeNormalizer', () => {
  let normalizer: UnicodeNormalizer

  beforeEach(() => {
    normalizer = new UnicodeNormalizer(defaultConfig)
  })

  describe('normalize()', () => {
    describe('zero-width character stripping', () => {
      it('should strip zero-width space (U+200B)', () => {
        const input = 'hello\u200Bworld'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('helloworld')
        expect(result.strippedChars).toBeGreaterThan(0)
      })

      it('should strip zero-width non-joiner (U+200C)', () => {
        const input = 'test\u200Cinput'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('testinput')
      })

      it('should strip zero-width joiner (U+200D)', () => {
        const input = 'a\u200Db'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('ab')
      })

      it('should strip BOM / zero-width no-break space (U+FEFF)', () => {
        const input = '\uFEFFhello'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('hello')
      })

      it('should report zero_width_characters in suspicious patterns', () => {
        const input = 'ig\u200Bnore prev\u200Cious'
        const result = normalizer.normalize(input)
        expect(result.suspiciousPatterns).toContain('zero_width_characters')
      })
    })

    describe('Unicode tag character stripping', () => {
      it('should strip Unicode tag characters (U+E0000 range)', () => {
        const input = 'hello\u{E0001}\u{E0069}\u{E0067}\u{E006E}world'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('helloworld')
        expect(result.strippedChars).toBe(4)
      })

      it('should report unicode_tag_characters in suspicious patterns', () => {
        const input = 'test\u{E0020}\u{E0041}data'
        const result = normalizer.normalize(input)
        expect(result.suspiciousPatterns).toContain('unicode_tag_characters')
      })
    })

    describe('bidi override removal', () => {
      it('should strip LRO (U+202D) and RLO (U+202E)', () => {
        const input = 'normal\u202Dtext\u202E'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('normaltext')
        expect(result.strippedChars).toBe(2)
      })

      it('should strip LRE, RLE, PDF, LRI, RLI, FSI, PDI', () => {
        const input = '\u202A\u202B\u202C\u2066\u2067\u2068\u2069text'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('text')
        expect(result.strippedChars).toBe(7)
      })

      it('should report bidi_override_characters in suspicious patterns', () => {
        const input = '\u202Ehello'
        const result = normalizer.normalize(input)
        expect(result.suspiciousPatterns).toContain('bidi_override_characters')
      })
    })

    describe('homoglyph normalization', () => {
      it('should normalize Cyrillic а (U+0430) to Latin a', () => {
        const input = '\u0430dmin'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('admin')
        expect(result.homoglyphsReplaced).toBe(1)
      })

      it('should normalize Cyrillic о (U+043E) to Latin o', () => {
        const input = 'hell\u043E'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('hello')
      })

      it('should normalize multiple Cyrillic homoglyphs', () => {
        const input = '\u0441\u043E\u0440\u0435'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('cope')
        expect(result.homoglyphsReplaced).toBe(4)
      })

      it('should normalize Greek homoglyphs (Α → A, ο → o)', () => {
        const input = '\u0391\u03BFtest'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('Aotest')
        expect(result.homoglyphsReplaced).toBe(2)
      })

      it('should normalize fullwidth Latin characters', () => {
        const input = '\uFF41\uFF42\uFF43'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('abc')
        expect(result.homoglyphsReplaced).toBe(3)
      })

      it('should report homoglyph_substitution in suspicious patterns', () => {
        const input = '\u0430\u0435\u043E\u0440'
        const result = normalizer.normalize(input)
        expect(result.suspiciousPatterns).toContain('homoglyph_substitution')
      })
    })

    describe('normal text passthrough', () => {
      it('should pass through normal ASCII text unchanged', () => {
        const input = 'Hello, this is a normal message.'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe(input)
        expect(result.strippedChars).toBe(0)
        expect(result.homoglyphsReplaced).toBe(0)
        expect(result.suspiciousPatterns).toHaveLength(0)
      })

      it('should preserve tabs and newlines', () => {
        const input = 'line one\nline two\ttab'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe(input)
        expect(result.strippedChars).toBe(0)
      })

      it('should preserve normal Unicode text (Chinese)', () => {
        const input = '你好世界'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('你好世界')
        expect(result.strippedChars).toBe(0)
      })

      it('should preserve normal Unicode text (Arabic)', () => {
        const input = 'مرحبا بالعالم'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('مرحبا بالعالم')
        expect(result.strippedChars).toBe(0)
      })

      it('should preserve emoji', () => {
        const input = 'Hello 👋 World 🌍'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe(input)
      })
    })

    describe('variation selector stripping', () => {
      it('should strip variation selectors (FE00-FE0F)', () => {
        const input = 'text\uFE0Fmore'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('textmore')
        expect(result.suspiciousPatterns).toContain('variation_selectors')
      })
    })

    describe('invisible formatting stripping', () => {
      it('should strip soft hyphen (U+00AD)', () => {
        const input = 'in\u00ADvisible'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('invisible')
      })

      it('should strip word joiner (U+2060)', () => {
        const input = 'hello\u2060world'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('helloworld')
      })
    })

    describe('control character stripping', () => {
      it('should strip null bytes and other C0 controls', () => {
        const input = 'hello\x00\x01\x02world'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('helloworld')
        expect(result.suspiciousPatterns).toContain('control_characters')
      })

      it('should strip C1 control characters (U+0080-009F)', () => {
        const input = 'test\x80\x90data'
        const result = normalizer.normalize(input)
        expect(result.normalized).toBe('testdata')
      })
    })
  })

  describe('scan()', () => {
    it('should return ScanResult with correct scanner metadata', () => {
      const result = normalizer.scan('clean text')
      expect(result.scannerId).toBe('unicode-normalizer')
      expect(result.scannerType).toBe('unicode')
      expect(result.latencyMs).toBeGreaterThanOrEqual(0)
    })

    it('should not detect clean text as suspicious', () => {
      const result = normalizer.scan('This is perfectly normal text.')
      expect(result.detected).toBe(false)
      expect(result.killChainPhase).toBe('none')
    })

    it('should detect text with many stripped chars (>5) as suspicious', () => {
      const input = '\u200B\u200C\u200D\uFEFF\u200B\u200C extra zero widths'
      const result = normalizer.scan(input)
      expect(result.detected).toBe(true)
      expect(result.killChainPhase).toBe('initial_access')
    })

    it('should detect text with many homoglyphs (>3) as suspicious', () => {
      const input = '\u0430\u0435\u043E\u0440 looks like aeop'
      const result = normalizer.scan(input)
      expect(result.detected).toBe(true)
      expect(result.confidence).toBeGreaterThanOrEqual(0.4)
    })

    it('should not flag text with exactly 5 stripped chars as suspicious', () => {
      const input = '\u200B\u200C\u200D\uFEFF\u200B text'
      const result = normalizer.scan(input)
      expect(result.detected).toBe(false)
    })

    it('should include confidence score', () => {
      const result = normalizer.scan('\u200B'.repeat(20) + 'test')
      expect(result.confidence).toBeGreaterThan(0)
      expect(result.confidence).toBeLessThanOrEqual(1.0)
    })

    it('should compute threat level based on confidence', () => {
      const result = normalizer.scan('\u200B'.repeat(20) + '\u0430'.repeat(10) + 'test')
      expect(['low', 'medium', 'high', 'critical']).toContain(result.threatLevel)
    })
  })
})
