'use client'

import * as s from './styles'
import { useHealingLog, useTimeRange } from '../hooks'
import { StatCard } from '../components/StatCard'
import { DataTable } from '../components/DataTable'
import type { DataTableColumn } from '../components/DataTable'
import { ActionBadge } from '../components/ActionBadge'
import { PhaseBadge } from '../components/PhaseBadge'
import { ThreatBadge } from '../components/ThreatBadge'
import { TimeRangeSelector } from '../components/TimeRangeSelector'
import { LoadingSpinner } from '../components/LoadingSpinner'
import { theme } from '../theme'
import type { HealingLogEntry } from '../types'

export function HealingLog() {
  const { healingLog, loading } = useHealingLog()
  const { timeRange, setTimeRange } = useTimeRange()

  if (loading) return <LoadingSpinner />

  const blocked = healingLog.filter((e) => e.action === 'block').length
  const resets = healingLog.filter((e) => e.sessionResetPerformed).length
  const reported = healingLog.filter((e) => e.incidentReported).length

  const columns: DataTableColumn<HealingLogEntry>[] = [
    { key: 'timestamp', header: 'Time', render: (r) => new Date(r.timestamp).toLocaleString(), accessor: (r) => r.timestamp },
    { key: 'action', header: 'Action', render: (r) => <ActionBadge action={r.action} />, accessor: (r) => r.action },
    { key: 'phase', header: 'Phase', render: (r) => <PhaseBadge phase={r.phase} />, accessor: (r) => r.phase },
    { key: 'threatLevel', header: 'Threat', render: (r) => <ThreatBadge level={r.threatLevel} />, accessor: (r) => r.threatLevel },
    { key: 'strategyUsed', header: 'Strategy', accessor: (r) => r.strategyUsed },
    { key: 'sessionResetPerformed', header: 'Reset', render: (r) => r.sessionResetPerformed ? <span style={{ color: theme.colors.threatCritical }}>Yes</span> : <span style={{ color: theme.colors.textDim }}>{'\u2013'}</span>, accessor: (r) => r.sessionResetPerformed ? '1' : '0' },
    { key: 'incidentReported', header: 'Reported', render: (r) => r.incidentReported ? <span style={{ color: theme.colors.threatHigh }}>Yes</span> : <span style={{ color: theme.colors.textDim }}>{'\u2013'}</span>, accessor: (r) => r.incidentReported ? '1' : '0' },
  ]

  return (
    <div style={s.page}>
      <div style={s.header}><h2 style={s.pageTitle}>Healing Log</h2><TimeRangeSelector value={timeRange} onChange={setTimeRange} /></div>
      <div style={s.grid4}>
        <StatCard label="Total Actions" value={healingLog.length} />
        <StatCard label="Blocked" value={blocked} />
        <StatCard label="Session Resets" value={resets} />
        <StatCard label="Incidents Filed" value={reported} />
      </div>
      <div style={s.section}>
        <DataTable columns={columns} data={healingLog} pageSize={20} filterable filterPlaceholder="Search healing log\u2026" getRowKey={(r) => r.id} />
      </div>
    </div>
  )
}
