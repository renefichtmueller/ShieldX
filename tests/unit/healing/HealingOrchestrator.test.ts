import { describe, it, expect, beforeEach } from 'vitest'
import { HealingOrchestrator } from '../../../src/healing/HealingOrchestrator.js'
import type { KillChainPhase, ThreatLevel, HealingAction } from '../../../src/types/detection.js'

describe('HealingOrchestrator', () => {
  let orchestrator: HealingOrchestrator

  beforeEach(() => {
    orchestrator = new HealingOrchestrator()
  })

  describe('determineAction()', () => {
    describe('default action matrix', () => {
      it('should return "allow" for no threat on any phase', () => {
        const phases: KillChainPhase[] = [
          'none', 'initial_access', 'privilege_escalation',
          'reconnaissance', 'persistence', 'command_and_control',
          'lateral_movement', 'actions_on_objective',
        ]
        for (const phase of phases) {
          const action = orchestrator.determineAction('none', phase)
          expect(action).toBe('allow')
        }
      })

      it('should return "sanitize" for initial_access + medium threat', () => {
        const action = orchestrator.determineAction('medium', 'initial_access')
        expect(action).toBe('sanitize')
      })

      it('should return "block" for initial_access + critical threat', () => {
        const action = orchestrator.determineAction('critical', 'initial_access')
        expect(action).toBe('block')
      })

      it('should return "block" for privilege_escalation + high threat', () => {
        const action = orchestrator.determineAction('high', 'privilege_escalation')
        expect(action).toBe('block')
      })

      it('should return "reset" for persistence + medium threat', () => {
        const action = orchestrator.determineAction('medium', 'persistence')
        expect(action).toBe('reset')
      })

      it('should return "reset" for persistence + critical threat', () => {
        const action = orchestrator.determineAction('critical', 'persistence')
        expect(action).toBe('reset')
      })

      it('should return "incident" for command_and_control + high threat', () => {
        const action = orchestrator.determineAction('high', 'command_and_control')
        expect(action).toBe('incident')
      })

      it('should return "incident" for lateral_movement + medium threat', () => {
        const action = orchestrator.determineAction('medium', 'lateral_movement')
        expect(action).toBe('incident')
      })

      it('should return "incident" for actions_on_objective + critical threat', () => {
        const action = orchestrator.determineAction('critical', 'actions_on_objective')
        expect(action).toBe('incident')
      })

      it('should return "warn" for low threats on most phases', () => {
        expect(orchestrator.determineAction('low', 'initial_access')).toBe('warn')
        expect(orchestrator.determineAction('low', 'privilege_escalation')).toBe('warn')
        expect(orchestrator.determineAction('low', 'reconnaissance')).toBe('warn')
        expect(orchestrator.determineAction('low', 'persistence')).toBe('warn')
      })

      it('should return "block" for low command_and_control', () => {
        expect(orchestrator.determineAction('low', 'command_and_control')).toBe('block')
      })
    })

    describe('phase 1 = sanitize (initial_access)', () => {
      it('should default to sanitize for initial_access medium', () => {
        expect(orchestrator.determineAction('medium', 'initial_access')).toBe('sanitize')
      })
    })

    describe('phase 7 = incident (actions_on_objective)', () => {
      it('should escalate to incident for actions_on_objective high/critical', () => {
        expect(orchestrator.determineAction('high', 'actions_on_objective')).toBe('incident')
        expect(orchestrator.determineAction('critical', 'actions_on_objective')).toBe('incident')
      })
    })
  })

  describe('custom phase strategies override defaults', () => {
    it('should use custom strategy when provided', () => {
      const customOrchestrator = new HealingOrchestrator({
        healing: {
          phaseStrategies: {
            initial_access: 'block',
          },
        },
      })
      const action = customOrchestrator.determineAction('low', 'initial_access')
      expect(action).toBe('block')
    })

    it('should fall back to default when custom strategy not defined for phase', () => {
      const customOrchestrator = new HealingOrchestrator({
        healing: {
          phaseStrategies: {
            initial_access: 'block',
          },
        },
      })
      // persistence has no custom override
      const action = customOrchestrator.determineAction('high', 'persistence')
      expect(action).toBe('reset')
    })
  })

  describe('session reset trigger for persistence phase', () => {
    it('should return reset for persistence phase at medium+', () => {
      expect(orchestrator.determineAction('medium', 'persistence')).toBe('reset')
      expect(orchestrator.determineAction('high', 'persistence')).toBe('reset')
      expect(orchestrator.determineAction('critical', 'persistence')).toBe('reset')
    })
  })

  describe('incident reporting for critical phases', () => {
    const criticalPhases: KillChainPhase[] = [
      'command_and_control',
      'lateral_movement',
      'actions_on_objective',
    ]

    for (const phase of criticalPhases) {
      it(`should trigger incident for ${phase} at high threat`, () => {
        expect(orchestrator.determineAction('high', phase)).toBe('incident')
      })

      it(`should trigger incident for ${phase} at critical threat`, () => {
        expect(orchestrator.determineAction('critical', phase)).toBe('incident')
      })
    }
  })

  describe('getSessionManager()', () => {
    it('should return a SessionManager instance', () => {
      const sm = orchestrator.getSessionManager()
      expect(sm).toBeDefined()
    })
  })

  describe('getIncidentReporter()', () => {
    it('should return an IncidentReporter instance', () => {
      const ir = orchestrator.getIncidentReporter()
      expect(ir).toBeDefined()
    })
  })
})
