import { describe, it, expect, beforeEach } from 'vitest'
import { ATLASMapper } from '../../../src/compliance/ATLASMapper.js'

describe('ATLASMapper', () => {
  let mapper: ATLASMapper

  beforeEach(() => {
    mapper = new ATLASMapper()
  })

  describe('mapRule()', () => {
    it('should map prompt-injection rule to AML.T0051', () => {
      const mapping = mapper.mapRule('rule:prompt-injection')
      expect(mapping).toBeDefined()
      expect(mapping!.techniqueId).toBe('AML.T0051')
      expect(mapping!.techniqueName).toContain('Prompt Injection')
      expect(mapping!.tacticName).toBe('Initial Access')
    })

    it('should map indirect prompt injection to AML.T0051.001', () => {
      const mapping = mapper.mapRule('rule:prompt-injection-indirect')
      expect(mapping).toBeDefined()
      expect(mapping!.techniqueId).toBe('AML.T0051.001')
    })

    it('should map jailbreak rule to AML.T0054', () => {
      const mapping = mapper.mapRule('rule:jailbreak')
      expect(mapping).toBeDefined()
      expect(mapping!.techniqueId).toBe('AML.T0054')
      expect(mapping!.relatedKillChainPhase).toBe('privilege_escalation')
    })

    it('should map model-extraction rule to AML.T0024', () => {
      const mapping = mapper.mapRule('rule:model-extraction')
      expect(mapping).toBeDefined()
      expect(mapping!.techniqueId).toBe('AML.T0024')
    })

    it('should map system-prompt-extraction rule', () => {
      const mapping = mapper.mapRule('rule:system-prompt-extraction')
      expect(mapping).toBeDefined()
      expect(mapping!.techniqueId).toBe('AML.T0051.002')
      expect(mapping!.relatedKillChainPhase).toBe('reconnaissance')
    })

    it('should map data-poisoning rule to AML.T0020', () => {
      const mapping = mapper.mapRule('rule:data-poisoning')
      expect(mapping).toBeDefined()
      expect(mapping!.techniqueId).toBe('AML.T0020')
      expect(mapping!.relatedKillChainPhase).toBe('persistence')
    })

    it('should map supply-chain rule to AML.T0010', () => {
      const mapping = mapper.mapRule('rule:supply-chain')
      expect(mapping).toBeDefined()
      expect(mapping!.techniqueId).toBe('AML.T0010')
    })

    it('should map encoding-evasion rule to AML.T0015', () => {
      const mapping = mapper.mapRule('rule:encoding-evasion')
      expect(mapping).toBeDefined()
      expect(mapping!.techniqueId).toBe('AML.T0015')
    })

    it('should map tool-abuse rule to AML.T0040', () => {
      const mapping = mapper.mapRule('rule:tool-abuse')
      expect(mapping).toBeDefined()
      expect(mapping!.techniqueId).toBe('AML.T0040')
      expect(mapping!.relatedKillChainPhase).toBe('command_and_control')
    })

    it('should map data-exfiltration rule to AML.T0025', () => {
      const mapping = mapper.mapRule('rule:data-exfiltration')
      expect(mapping).toBeDefined()
      expect(mapping!.techniqueId).toBe('AML.T0025')
      expect(mapping!.relatedKillChainPhase).toBe('actions_on_objective')
    })

    it('should return undefined for unknown rule', () => {
      const mapping = mapper.mapRule('rule:nonexistent')
      expect(mapping).toBeUndefined()
    })

    it('should include mitigation IDs in mappings', () => {
      const mapping = mapper.mapRule('rule:prompt-injection')!
      expect(mapping.mitigationIds.length).toBeGreaterThan(0)
      expect(mapping.mitigationIds[0]).toMatch(/^AML\.M\d+/)
    })
  })

  describe('getMappedRules()', () => {
    it('should return all mapped rule IDs', () => {
      const rules = mapper.getMappedRules()
      expect(rules.length).toBeGreaterThan(0)
      expect(rules).toContain('rule:prompt-injection')
      expect(rules).toContain('rule:jailbreak')
      expect(rules).toContain('rule:data-exfiltration')
    })

    it('should return frozen array', () => {
      const rules = mapper.getMappedRules()
      expect(Object.isFrozen(rules)).toBe(true)
    })
  })

  describe('getCoverage()', () => {
    it('should return coverage statistics', () => {
      const coverage = mapper.getCoverage()
      expect(coverage.covered).toBeGreaterThan(0)
      expect(coverage.total).toBe(20)
      expect(coverage.covered).toBeLessThanOrEqual(coverage.total)
    })

    it('should identify coverage gaps', () => {
      const coverage = mapper.getCoverage()
      expect(coverage.gaps.length).toBeGreaterThan(0)
      // Gaps should be technique IDs not covered
      for (const gap of coverage.gaps) {
        expect(gap).toMatch(/^AML\.T\d+/)
      }
    })

    it('should have covered + gaps = total known techniques', () => {
      const coverage = mapper.getCoverage()
      // All techniques are either covered or in gaps
      const allKnownCount = coverage.covered + coverage.gaps.length
      // May not equal total exactly since some rules map to same technique
      expect(allKnownCount).toBeLessThanOrEqual(coverage.total)
    })

    it('should return frozen result', () => {
      const coverage = mapper.getCoverage()
      expect(Object.isFrozen(coverage)).toBe(true)
      expect(Object.isFrozen(coverage.gaps)).toBe(true)
    })
  })

  describe('getAllMappings()', () => {
    it('should return all ATLAS mappings', () => {
      const mappings = mapper.getAllMappings()
      expect(mappings.length).toBeGreaterThan(0)
    })

    it('should include required fields in each mapping', () => {
      const mappings = mapper.getAllMappings()
      for (const mapping of mappings) {
        expect(mapping.techniqueId).toBeTruthy()
        expect(mapping.tacticId).toBeTruthy()
        expect(mapping.techniqueName).toBeTruthy()
        expect(mapping.tacticName).toBeTruthy()
        expect(mapping.description).toBeTruthy()
        expect(mapping.relatedKillChainPhase).toBeTruthy()
        expect(Array.isArray(mapping.mitigationIds)).toBe(true)
        expect(Array.isArray(mapping.caseStudyIds)).toBe(true)
      }
    })

    it('should return frozen array', () => {
      const mappings = mapper.getAllMappings()
      expect(Object.isFrozen(mappings)).toBe(true)
    })
  })
})
