'use client'

import { useContext, useMemo } from 'react'

import { ShieldXContext } from '../provider'
import type { ShieldXContextValue } from '../provider'
import type { KillChainPhase, ThreatLevel } from '../types'
import type { IncidentFeedItem } from '../types'

// ---------------------------------------------------------------------------
// useShieldX — raw context
// ---------------------------------------------------------------------------
export function useShieldX(): ShieldXContextValue {
  const ctx = useContext(ShieldXContext)
  if (ctx === null) {
    throw new Error('useShieldX must be used within a <ShieldXProvider>')
  }
  return ctx
}

// ---------------------------------------------------------------------------
// useStats
// ---------------------------------------------------------------------------
export function useStats() {
  const { stats, loading } = useShieldX()
  return { stats, loading }
}

// ---------------------------------------------------------------------------
// useIncidents — with filtering
// ---------------------------------------------------------------------------
export interface IncidentFilters {
  readonly threatLevel?: ThreatLevel
  readonly killChainPhase?: KillChainPhase
  readonly search?: string
}

export function useIncidents(filters?: IncidentFilters) {
  const { incidents, loading } = useShieldX()

  const filtered = useMemo(() => {
    let result: readonly IncidentFeedItem[] = incidents
    if (filters?.threatLevel) {
      result = result.filter((i) => i.threatLevel === filters.threatLevel)
    }
    if (filters?.killChainPhase) {
      result = result.filter((i) => i.killChainPhase === filters.killChainPhase)
    }
    if (filters?.search) {
      const q = filters.search.toLowerCase()
      result = result.filter(
        (i) =>
          i.attackVector.toLowerCase().includes(q) ||
          i.matchedPatterns.some((p) => p.toLowerCase().includes(q))
      )
    }
    return result
  }, [incidents, filters?.threatLevel, filters?.killChainPhase, filters?.search])

  return { incidents: filtered, loading }
}

// ---------------------------------------------------------------------------
// useKillChain — phase distribution
// ---------------------------------------------------------------------------
const KILL_CHAIN_PHASES: readonly KillChainPhase[] = [
  'initial_access',
  'privilege_escalation',
  'reconnaissance',
  'persistence',
  'command_and_control',
  'lateral_movement',
  'actions_on_objective',
]

export interface KillChainDistribution {
  readonly phase: KillChainPhase
  readonly label: string
  readonly count: number
}

const PHASE_LABELS: Record<string, string> = {
  initial_access: 'Initial Access',
  privilege_escalation: 'Privilege Escalation',
  reconnaissance: 'Reconnaissance',
  persistence: 'Persistence',
  command_and_control: 'Command & Control',
  lateral_movement: 'Lateral Movement',
  actions_on_objective: 'Actions on Objective',
}

export function useKillChain() {
  const { incidents, loading } = useShieldX()

  const distribution = useMemo<readonly KillChainDistribution[]>(() => {
    const counts = new Map<KillChainPhase, number>()
    for (const phase of KILL_CHAIN_PHASES) {
      counts.set(phase, 0)
    }
    for (const incident of incidents) {
      if (incident.killChainPhase !== 'none') {
        const current = counts.get(incident.killChainPhase) ?? 0
        counts.set(incident.killChainPhase, current + 1)
      }
    }
    return KILL_CHAIN_PHASES.map((phase) => ({
      phase,
      label: PHASE_LABELS[phase] ?? phase,
      count: counts.get(phase) ?? 0,
    }))
  }, [incidents])

  return { distribution, loading }
}

// ---------------------------------------------------------------------------
// useAttackGraph
// ---------------------------------------------------------------------------
export function useAttackGraph() {
  const { attackGraph, loading } = useShieldX()
  return { ...attackGraph, loading }
}

// ---------------------------------------------------------------------------
// useReviewQueue
// ---------------------------------------------------------------------------
export function useReviewQueue() {
  const { reviewQueue, loading, api } = useShieldX()
  return { reviewQueue, loading, api }
}

// ---------------------------------------------------------------------------
// useDrift
// ---------------------------------------------------------------------------
export function useDrift() {
  const { drift, loading } = useShieldX()
  return { drift, loading }
}

// ---------------------------------------------------------------------------
// useCompliance
// ---------------------------------------------------------------------------
export function useCompliance() {
  const { compliance, loading } = useShieldX()
  return { compliance, loading }
}

// ---------------------------------------------------------------------------
// useConfig
// ---------------------------------------------------------------------------
export function useConfig() {
  const { config, loading } = useShieldX()
  return { config, loading }
}

// ---------------------------------------------------------------------------
// useSessions
// ---------------------------------------------------------------------------
export function useSessions() {
  const { sessions, loading } = useShieldX()
  return { sessions, loading }
}

// ---------------------------------------------------------------------------
// useHealingLog
// ---------------------------------------------------------------------------
export function useHealingLog() {
  const { healingLog, loading } = useShieldX()
  return { healingLog, loading }
}

// ---------------------------------------------------------------------------
// useProtectedEndpoints
// ---------------------------------------------------------------------------
export function useProtectedEndpoints() {
  const { protectedEndpoints, loading } = useShieldX()
  return { protectedEndpoints, loading }
}

// ---------------------------------------------------------------------------
// useTimeRange
// ---------------------------------------------------------------------------
export function useTimeRange() {
  const { timeRange, setTimeRange } = useShieldX()
  return { timeRange, setTimeRange }
}
