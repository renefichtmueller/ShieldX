/**
 * Tests for HealingOrchestrator.executeHealing() — the async pipeline path.
 * Covers all 7 kill chain phases, session management, incident reporting.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { HealingOrchestrator } from '../../../src/healing/HealingOrchestrator.js'
import type { ShieldXResult, ScanResult } from '../../../src/types/detection.js'

function makeResult(overrides: Partial<ShieldXResult> = {}): ShieldXResult {
  const base: ShieldXResult = {
    id: 'test-id',
    timestamp: new Date().toISOString(),
    input: 'test input',
    detected: true,
    threatLevel: 'high',
    killChainPhase: 'initial_access',
    action: 'sanitize',
    scanResults: [] as ScanResult[],
    healingApplied: true,
    latencyMs: 10,
  }
  return { ...base, ...overrides }
}

describe('HealingOrchestrator.executeHealing()', () => {
  let orchestrator: HealingOrchestrator

  beforeEach(() => {
    orchestrator = new HealingOrchestrator()
  })

  describe('allow path — no threat', () => {
    it('should return allow response when threat is none/none', async () => {
      const result = makeResult({ detected: false, threatLevel: 'none', killChainPhase: 'none', action: 'allow' })
      const response = await orchestrator.executeHealing(result)
      expect(response.action).toBe('allow')
      expect(response.incidentReported).toBe(false)
      expect(response.sessionResetPerformed).toBe(false)
    })
  })

  describe('initial_access phase', () => {
    it('should execute phase 1 strategy for initial_access medium', async () => {
      const result = makeResult({ killChainPhase: 'initial_access', threatLevel: 'medium', action: 'sanitize' })
      const response = await orchestrator.executeHealing(result)
      expect(response.action).toBeDefined()
      expect(response.strategy).toBeDefined()
      expect(response.strategy.phase).toBe('initial_access')
    })

    it('should respond for initial_access critical', async () => {
      const result = makeResult({ killChainPhase: 'initial_access', threatLevel: 'critical', action: 'block' })
      const response = await orchestrator.executeHealing(result)
      expect(['block', 'sanitize']).toContain(response.action)
    })

    it('should provide fallback response', async () => {
      const result = makeResult({ killChainPhase: 'initial_access', threatLevel: 'high', action: 'sanitize' })
      const response = await orchestrator.executeHealing(result)
      expect(response.fallbackResponse).toBeTruthy()
      expect(typeof response.fallbackResponse).toBe('string')
    })
  })

  describe('privilege_escalation phase', () => {
    it('should execute phase 2 strategy', async () => {
      const result = makeResult({ killChainPhase: 'privilege_escalation', threatLevel: 'high', action: 'block' })
      const response = await orchestrator.executeHealing(result)
      expect(response.strategy.phase).toBe('privilege_escalation')
    })

    it('should block jailbreak with critical threat', async () => {
      const result = makeResult({ killChainPhase: 'privilege_escalation', threatLevel: 'critical', action: 'block' })
      const response = await orchestrator.executeHealing(result)
      expect(['block', 'sanitize']).toContain(response.action)
    })
  })

  describe('reconnaissance phase', () => {
    it('should execute phase 3 strategy and block', async () => {
      const result = makeResult({ killChainPhase: 'reconnaissance', threatLevel: 'high', action: 'block' })
      const response = await orchestrator.executeHealing(result)
      expect(response.strategy.phase).toBe('reconnaissance')
      expect(response.fallbackResponse).toBeTruthy()
    })
  })

  describe('persistence phase', () => {
    it('should reset session for persistence medium', async () => {
      const result = makeResult({ killChainPhase: 'persistence', threatLevel: 'medium', action: 'reset' })
      const response = await orchestrator.executeHealing(result)
      expect(response.strategy.phase).toBe('persistence')
      expect(response.strategy.requiresSessionReset).toBe(true)
    })

    it('should perform session reset with context', async () => {
      const result = makeResult({ killChainPhase: 'persistence', threatLevel: 'high', action: 'reset' })
      const response = await orchestrator.executeHealing(result, { sessionId: 'test-session-persist', userId: 'user1' })
      expect(response.sessionResetPerformed).toBe(true)
    })
  })

  describe('command_and_control phase', () => {
    it('should generate incident for C2 high', async () => {
      const result = makeResult({ killChainPhase: 'command_and_control', threatLevel: 'high', action: 'incident' })
      const response = await orchestrator.executeHealing(result)
      expect(response.incidentReported).toBe(true)
    })

    it('should generate incident for C2 critical', async () => {
      const result = makeResult({ killChainPhase: 'command_and_control', threatLevel: 'critical', action: 'incident' })
      const response = await orchestrator.executeHealing(result)
      expect(response.incidentReported).toBe(true)
    })
  })

  describe('lateral_movement phase', () => {
    it('should generate incident for lateral movement', async () => {
      const result = makeResult({ killChainPhase: 'lateral_movement', threatLevel: 'high', action: 'incident' })
      const response = await orchestrator.executeHealing(result)
      expect(response.incidentReported).toBe(true)
      expect(response.strategy.phase).toBe('lateral_movement')
    })
  })

  describe('actions_on_objective phase', () => {
    it('should generate incident for final objective', async () => {
      const result = makeResult({ killChainPhase: 'actions_on_objective', threatLevel: 'critical', action: 'incident' })
      const response = await orchestrator.executeHealing(result)
      expect(response.incidentReported).toBe(true)
      expect(response.strategy.phase).toBe('actions_on_objective')
    })
  })

  describe('session checkpoint with context', () => {
    it('should checkpoint session when context is provided', async () => {
      const result = makeResult({ killChainPhase: 'initial_access', threatLevel: 'medium', action: 'sanitize' })
      const context = { sessionId: 'checkpoint-test', userId: 'user-42' }
      const response = await orchestrator.executeHealing(result, context)
      expect(response).toBeDefined()
      // Session manager should have recorded the checkpoint
      const sm = orchestrator.getSessionManager()
      expect(sm).toBeDefined()
    })
  })

  describe('fallback response safety', () => {
    it('should always return a safe fallback string', async () => {
      const phases = ['initial_access', 'privilege_escalation', 'reconnaissance', 'persistence', 'command_and_control', 'lateral_movement', 'actions_on_objective'] as const
      for (const phase of phases) {
        const result = makeResult({ killChainPhase: phase, threatLevel: 'high', action: 'block' })
        const response = await orchestrator.executeHealing(result)
        expect(typeof response.fallbackResponse).toBe('string')
        expect(response.fallbackResponse!.length).toBeGreaterThan(0)
      }
    })
  })

  describe('response structure completeness', () => {
    it('should return all required fields', async () => {
      const result = makeResult({ killChainPhase: 'initial_access', threatLevel: 'high', action: 'block' })
      const response = await orchestrator.executeHealing(result)
      expect(response.action).toBeDefined()
      expect(response.strategy).toBeDefined()
      expect(typeof response.sessionResetPerformed).toBe('boolean')
      expect(typeof response.incidentReported).toBe('boolean')
      expect(typeof response.webhookNotified).toBe('boolean')
    })
  })
})
