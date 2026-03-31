'use client'

import React, { createContext, useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type {
  ShieldXDashboardAPI,
  IncidentFeedItem,
  ProtectedEndpoint,
  HealingLogEntry,
  TimeRange,
  ShieldXConfig,
  ScanResult,
  LearningStats,
  DriftReport,
  AttackGraphNode,
  AttackGraphEdge,
  ConversationState,
  ComplianceReport,
} from './types'

/** Shape of the data exposed via context */
export interface ShieldXContextValue {
  readonly config: ShieldXConfig | null
  readonly stats: LearningStats | null
  readonly incidents: readonly IncidentFeedItem[]
  readonly attackGraph: { readonly nodes: readonly AttackGraphNode[]; readonly edges: readonly AttackGraphEdge[] }
  readonly reviewQueue: readonly ScanResult[]
  readonly drift: DriftReport | null
  readonly compliance: ComplianceReport | null
  readonly sessions: readonly ConversationState[]
  readonly healingLog: readonly HealingLogEntry[]
  readonly protectedEndpoints: readonly ProtectedEndpoint[]
  readonly loading: boolean
  readonly error: string | null
  readonly timeRange: TimeRange
  readonly setTimeRange: (range: TimeRange) => void
  readonly api: ShieldXDashboardAPI | null
}

export const ShieldXContext = createContext<ShieldXContextValue | null>(null)

export interface ShieldXProviderProps {
  readonly shieldx: ShieldXDashboardAPI
  readonly pollInterval?: number
  readonly children: React.ReactNode
}

export function ShieldXProvider({ shieldx, pollInterval = 5000, children }: ShieldXProviderProps) {
  const [config, setConfig] = useState<ShieldXConfig | null>(null)
  const [stats, setStats] = useState<LearningStats | null>(null)
  const [incidents, setIncidents] = useState<readonly IncidentFeedItem[]>([])
  const [attackGraph, setAttackGraph] = useState<{ nodes: readonly AttackGraphNode[]; edges: readonly AttackGraphEdge[] }>({ nodes: [], edges: [] })
  const [reviewQueue, setReviewQueue] = useState<readonly ScanResult[]>([])
  const [drift, setDrift] = useState<DriftReport | null>(null)
  const [compliance, setCompliance] = useState<ComplianceReport | null>(null)
  const [sessions, setSessions] = useState<readonly ConversationState[]>([])
  const [healingLog, setHealingLog] = useState<readonly HealingLogEntry[]>([])
  const [protectedEndpoints, setProtectedEndpoints] = useState<readonly ProtectedEndpoint[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [timeRange, setTimeRange] = useState<TimeRange>('24h')
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const fetchData = useCallback(async () => {
    try {
      const [statsData, incidentsData] = await Promise.all([
        shieldx.getStats(),
        shieldx.getIncidents(timeRange),
      ])

      setConfig(shieldx.getConfig())
      setStats(statsData)
      setIncidents(incidentsData)
      setAttackGraph(shieldx.getAttackGraph())
      setReviewQueue(shieldx.getReviewQueue())
      setDrift(shieldx.getDriftStatus())
      setCompliance(shieldx.generateComplianceReport('combined'))
      setSessions(shieldx.getActiveSessions())
      setHealingLog(shieldx.getHealingLog(timeRange))
      setProtectedEndpoints(shieldx.getProtectedEndpoints())
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch dashboard data')
    } finally {
      setLoading(false)
    }
  }, [shieldx, timeRange])

  useEffect(() => {
    fetchData()

    intervalRef.current = setInterval(fetchData, pollInterval)

    return () => {
      if (intervalRef.current !== null) {
        clearInterval(intervalRef.current)
      }
    }
  }, [fetchData, pollInterval])

  const value = useMemo<ShieldXContextValue>(
    () => ({
      config,
      stats,
      incidents,
      attackGraph,
      reviewQueue,
      drift,
      compliance,
      sessions,
      healingLog,
      protectedEndpoints,
      loading,
      error,
      timeRange,
      setTimeRange,
      api: shieldx,
    }),
    [config, stats, incidents, attackGraph, reviewQueue, drift, compliance, sessions, healingLog, protectedEndpoints, loading, error, timeRange, shieldx]
  )

  return <ShieldXContext.Provider value={value}>{children}</ShieldXContext.Provider>
}
