'use client'

import React, { useState } from 'react'
import * as s from './styles'
import { theme } from '../theme'
import { useIncidents, useTimeRange } from '../hooks'
import { DataTable } from '../components/DataTable'
import type { DataTableColumn } from '../components/DataTable'
import { ThreatBadge } from '../components/ThreatBadge'
import { PhaseBadge } from '../components/PhaseBadge'
import { ActionBadge } from '../components/ActionBadge'
import { TimeRangeSelector } from '../components/TimeRangeSelector'
import { LoadingSpinner } from '../components/LoadingSpinner'
import type { IncidentFeedItem } from '../types'
import type { ThreatLevel, KillChainPhase } from '../types'

const selectStyle: React.CSSProperties = {
  background: theme.colors.bg,
  border: `1px solid ${theme.colors.cardBorder}`,
  borderRadius: 4,
  color: theme.colors.text,
  padding: '6px 10px',
  fontSize: 12,
  fontFamily: theme.font,
}

export function IncidentFeed() {
  const { timeRange, setTimeRange } = useTimeRange()
  const [threatFilter, setThreatFilter] = useState<ThreatLevel | ''>('')
  const [phaseFilter, setPhaseFilter] = useState<KillChainPhase | ''>('')
  const { incidents, loading } = useIncidents({
    threatLevel: threatFilter || undefined,
    killChainPhase: phaseFilter || undefined,
  })

  if (loading) return <LoadingSpinner />

  const columns: DataTableColumn<IncidentFeedItem>[] = [
    { key: 'timestamp', header: 'Time', render: (r) => new Date(r.timestamp).toLocaleString(), accessor: (r) => r.timestamp },
    { key: 'threatLevel', header: 'Threat', render: (r) => <ThreatBadge level={r.threatLevel} />, accessor: (r) => r.threatLevel },
    { key: 'killChainPhase', header: 'Phase', render: (r) => <PhaseBadge phase={r.killChainPhase} />, accessor: (r) => r.killChainPhase },
    { key: 'action', header: 'Action', render: (r) => <ActionBadge action={r.action} />, accessor: (r) => r.action },
    { key: 'attackVector', header: 'Attack Vector', accessor: (r) => r.attackVector },
    { key: 'matchedPatterns', header: 'Patterns', render: (r) => <span style={{ fontSize: 11, color: theme.colors.textMuted }}>{r.matchedPatterns.slice(0, 3).join(', ')}{r.matchedPatterns.length > 3 ? ` +${r.matchedPatterns.length - 3}` : ''}</span>, accessor: (r) => r.matchedPatterns.join(' ') },
    { key: 'falsePositive', header: 'FP', render: (r) => r.falsePositive ? <span style={{ color: theme.colors.threatMedium }}>FP</span> : <span style={{ color: theme.colors.textDim }}>{'\u2013'}</span>, accessor: (r) => r.falsePositive ? '1' : '0' },
  ]

  return (
    <div style={s.page}>
      <div style={s.header}>
        <h2 style={s.pageTitle}>Incident Feed</h2>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select value={threatFilter} onChange={(e) => setThreatFilter(e.target.value as ThreatLevel | '')} style={selectStyle}>
            <option value="">All Threats</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
          <select value={phaseFilter} onChange={(e) => setPhaseFilter(e.target.value as KillChainPhase | '')} style={selectStyle}>
            <option value="">All Phases</option>
            <option value="initial_access">Initial Access</option>
            <option value="privilege_escalation">Priv Escalation</option>
            <option value="reconnaissance">Recon</option>
            <option value="persistence">Persistence</option>
            <option value="command_and_control">C2</option>
            <option value="lateral_movement">Lateral Move</option>
            <option value="actions_on_objective">Objective</option>
          </select>
          <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
        </div>
      </div>

      <DataTable columns={columns} data={incidents} pageSize={20} filterable filterPlaceholder="Search incidents\u2026" getRowKey={(r) => r.id} />
    </div>
  )
}
