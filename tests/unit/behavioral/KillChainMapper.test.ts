import { describe, it, expect, beforeEach } from 'vitest'
import { KillChainMapper, KILL_CHAIN_PHASES } from '../../../src/behavioral/KillChainMapper.js'
import type { ScanResult, KillChainPhase } from '../../../src/types/detection.js'

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    scannerId: 'test-scanner',
    scannerType: 'rule',
    detected: true,
    confidence: 0.8,
    threatLevel: 'high',
    killChainPhase: 'initial_access',
    matchedPatterns: ['test-pattern'],
    latencyMs: 1,
    ...overrides,
  }
}

describe('KillChainMapper', () => {
  let mapper: KillChainMapper

  beforeEach(() => {
    mapper = new KillChainMapper()
  })

  describe('classify()', () => {
    it('should return "none" for empty scan results', () => {
      const classification = mapper.classify([])
      expect(classification.primaryPhase).toBe('none')
      expect(classification.allPhases).toHaveLength(0)
      expect(classification.isMultiPhase).toBe(false)
      expect(classification.confidence).toBe(1.0)
    })

    it('should return "none" when no results are detected', () => {
      const results = [makeScanResult({ detected: false })]
      const classification = mapper.classify(results)
      expect(classification.primaryPhase).toBe('none')
      expect(classification.allPhases).toHaveLength(0)
    })

    describe('phase classification for each of 7 phases', () => {
      const testCases: Array<{ phase: KillChainPhase; label: string }> = [
        { phase: 'initial_access', label: 'Initial Access' },
        { phase: 'privilege_escalation', label: 'Privilege Escalation' },
        { phase: 'reconnaissance', label: 'Reconnaissance' },
        { phase: 'persistence', label: 'Persistence' },
        { phase: 'command_and_control', label: 'Command and Control' },
        { phase: 'lateral_movement', label: 'Lateral Movement' },
        { phase: 'actions_on_objective', label: 'Actions on Objective' },
      ]

      for (const { phase, label } of testCases) {
        it(`should classify ${label} phase correctly`, () => {
          const results = [makeScanResult({ killChainPhase: phase })]
          const classification = mapper.classify(results)
          expect(classification.primaryPhase).toBe(phase)
          expect(classification.allPhases.length).toBeGreaterThan(0)
          expect(classification.allPhases[0]!.phase).toBe(phase)
        })
      }
    })

    describe('priority ordering', () => {
      it('should prioritize actions_on_objective over initial_access', () => {
        const results = [
          makeScanResult({ killChainPhase: 'initial_access', confidence: 0.9 }),
          makeScanResult({ killChainPhase: 'actions_on_objective', confidence: 0.7 }),
        ]
        const classification = mapper.classify(results)
        expect(classification.primaryPhase).toBe('actions_on_objective')
      })

      it('should prioritize lateral_movement over reconnaissance', () => {
        const results = [
          makeScanResult({ killChainPhase: 'reconnaissance', confidence: 0.95 }),
          makeScanResult({ killChainPhase: 'lateral_movement', confidence: 0.6 }),
        ]
        const classification = mapper.classify(results)
        expect(classification.primaryPhase).toBe('lateral_movement')
      })

      it('should prioritize command_and_control over privilege_escalation', () => {
        const results = [
          makeScanResult({ killChainPhase: 'privilege_escalation', confidence: 0.9 }),
          makeScanResult({ killChainPhase: 'command_and_control', confidence: 0.7 }),
        ]
        const classification = mapper.classify(results)
        expect(classification.primaryPhase).toBe('command_and_control')
      })
    })

    describe('multi-phase detection', () => {
      it('should detect multi-phase attack (2+ phases)', () => {
        const results = [
          makeScanResult({ killChainPhase: 'initial_access' }),
          makeScanResult({ killChainPhase: 'privilege_escalation' }),
        ]
        const classification = mapper.classify(results)
        expect(classification.isMultiPhase).toBe(true)
        expect(classification.allPhases.length).toBe(2)
      })

      it('should not flag single-phase as multi-phase', () => {
        const results = [
          makeScanResult({ killChainPhase: 'initial_access', scannerId: 'scanner-1' }),
          makeScanResult({ killChainPhase: 'initial_access', scannerId: 'scanner-2' }),
        ]
        const classification = mapper.classify(results)
        expect(classification.isMultiPhase).toBe(false)
      })

      it('should include description of attack chain', () => {
        const results = [
          makeScanResult({ killChainPhase: 'initial_access' }),
          makeScanResult({ killChainPhase: 'persistence' }),
          makeScanResult({ killChainPhase: 'actions_on_objective' }),
        ]
        const classification = mapper.classify(results)
        expect(classification.isMultiPhase).toBe(true)
        expect(classification.attackChainDescription).toContain('Multi-phase')
        expect(classification.attackChainDescription).toContain('3 phases')
      })
    })

    describe('confidence scoring', () => {
      it('should return confidence > 0 for detected phases', () => {
        const results = [makeScanResult({ killChainPhase: 'initial_access', confidence: 0.8 })]
        const classification = mapper.classify(results)
        expect(classification.confidence).toBeGreaterThan(0)
        expect(classification.confidence).toBeLessThanOrEqual(1.0)
      })

      it('should include matched rule IDs in phase mappings', () => {
        const results = [makeScanResult({ killChainPhase: 'reconnaissance', scannerId: 'pe-001' })]
        const classification = mapper.classify(results)
        expect(classification.allPhases[0]!.matchedRuleIds).toContain('pe-001')
      })
    })

    describe('rule prefix classification', () => {
      it('should classify by scanner ID prefix when killChainPhase is none', () => {
        const results = [makeScanResult({
          killChainPhase: 'none',
          scannerId: 'io-001',
          matchedPatterns: ['io-injection'],
        })]
        const classification = mapper.classify(results)
        // io- prefix should map to initial_access
        expect(classification.primaryPhase).not.toBe('none')
      })
    })
  })

  describe('KILL_CHAIN_PHASES', () => {
    it('should define all 7 phases', () => {
      const phases = Object.keys(KILL_CHAIN_PHASES)
      expect(phases).toHaveLength(7)
      expect(phases).toContain('initial_access')
      expect(phases).toContain('privilege_escalation')
      expect(phases).toContain('reconnaissance')
      expect(phases).toContain('persistence')
      expect(phases).toContain('command_and_control')
      expect(phases).toContain('lateral_movement')
      expect(phases).toContain('actions_on_objective')
    })

    it('should have name, description, and mitigations for each phase', () => {
      for (const detail of Object.values(KILL_CHAIN_PHASES)) {
        expect(detail.name).toBeTruthy()
        expect(detail.description).toBeTruthy()
        expect(detail.mitigations.length).toBeGreaterThan(0)
        expect(detail.rulePatterns.length).toBeGreaterThan(0)
      }
    })
  })
})
