'use client'

import * as s from './styles'
import { theme } from '../theme'
import { useStats, useDrift, useIncidents } from '../hooks'
import { Card } from '../components/Card'
import { StatCard } from '../components/StatCard'
import { DataTable } from '../components/DataTable'
import type { DataTableColumn } from '../components/DataTable'
import { LoadingSpinner } from '../components/LoadingSpinner'
import { PatternDistribution } from '../charts/PatternDistribution'
import { FPRateTrend } from '../charts/FPRateTrend'
import { DriftChart } from '../charts/DriftChart'
import type { PatternRecord } from '../types'

export function LearningDashboard() {
  const { stats, loading } = useStats()
  const { drift } = useDrift()
  const { incidents } = useIncidents()

  if (loading) return <LoadingSpinner />

  const topPatterns = stats?.topPatterns ?? []

  const patternColumns: DataTableColumn<PatternRecord>[] = [
    { key: 'patternText', header: 'Pattern', accessor: (r) => r.patternText },
    { key: 'patternType', header: 'Type', accessor: (r) => r.patternType },
    { key: 'source', header: 'Source', accessor: (r) => r.source },
    { key: 'killChainPhase', header: 'Phase', accessor: (r) => r.killChainPhase },
    { key: 'hitCount', header: 'Hits', accessor: (r) => r.hitCount },
    { key: 'falsePositiveCount', header: 'FPs', render: (r) => <span style={{ color: r.falsePositiveCount > 5 ? theme.colors.threatCritical : theme.colors.textMuted }}>{r.falsePositiveCount}</span>, accessor: (r) => r.falsePositiveCount },
    { key: 'confidenceBase', header: 'Conf', render: (r) => `${(r.confidenceBase * 100).toFixed(0)}%`, accessor: (r) => r.confidenceBase },
    { key: 'enabled', header: 'Enabled', render: (r) => r.enabled ? <span style={{ color: theme.colors.threatNone }}>Yes</span> : <span style={{ color: theme.colors.threatCritical }}>No</span>, accessor: (r) => r.enabled ? '1' : '0' },
  ]

  return (
    <div style={s.page}>
      <div style={s.header}><h2 style={s.pageTitle}>Learning Engine</h2></div>

      <div style={s.grid4}>
        <StatCard label="Total Patterns" value={stats?.totalPatterns ?? 0} />
        <StatCard label="Learned" value={stats?.learnedPatterns ?? 0} />
        <StatCard label="FP Rate" value={`${((stats?.falsePositiveRate ?? 0) * 100).toFixed(1)}%`} invertDelta />
        <StatCard label="Drift Status" value={drift ? drift.driftType : 'Stable'} />
      </div>

      <div style={{ ...s.row, ...s.section }}>
        <div style={s.flex1}><Card title="Pattern Distribution"><PatternDistribution stats={stats} /></Card></div>
        <div style={s.flex1}><Card title="False Positive Trend"><FPRateTrend incidents={incidents} /></Card></div>
      </div>

      <div style={s.section}>
        <Card title="Concept Drift (CUSUM)">
          <DriftChart drift={drift} />
          {drift ? (
            <div style={{ display: 'flex', gap: 24, marginTop: 12, fontSize: 12, color: theme.colors.textMuted }}>
              <span>Type: <strong style={{ color: theme.colors.text }}>{drift.driftType}</strong></span>
              <span>Confidence Drop: <strong style={{ color: theme.colors.threatHigh }}>{(drift.confidenceDrop * 100).toFixed(1)}%</strong></span>
              <span>Suggested: <strong style={{ color: theme.colors.accent }}>{drift.suggestedAction}</strong></span>
            </div>
          ) : null}
        </Card>
      </div>

      <div style={s.section}>
        <Card title="Top Patterns">
          <DataTable columns={patternColumns} data={topPatterns} pageSize={10} filterable filterPlaceholder="Search patterns\u2026" getRowKey={(r) => r.id} />
        </Card>
      </div>
    </div>
  )
}
