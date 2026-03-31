'use client'

import React from 'react'
import * as s from './styles'
import { theme } from '../theme'
import { useStats, useIncidents, useKillChain } from '../hooks'
import { StatCard } from '../components/StatCard'
import { Card } from '../components/Card'
import { ThreatBadge } from '../components/ThreatBadge'
import { PhaseBadge } from '../components/PhaseBadge'
import { LoadingSpinner } from '../components/LoadingSpinner'
import { KillChainHeatmap } from '../charts/KillChainHeatmap'
import { ThreatTimeline } from '../charts/ThreatTimeline'
import { ScannerBreakdown } from '../charts/ScannerBreakdown'

const TH: React.CSSProperties = { textAlign: 'left', padding: '8px 12px', color: theme.colors.textMuted, fontSize: 11, textTransform: 'uppercase', borderBottom: `1px solid ${theme.colors.cardBorder}` }
const TD: React.CSSProperties = { padding: '8px 12px' }

export function DashboardHome() {
  const { stats, loading } = useStats()
  const { incidents } = useIncidents()
  const { distribution } = useKillChain()

  if (loading) return <LoadingSpinner />

  const totalScans = stats?.totalIncidents ?? 0
  const threats = incidents.filter((i) => i.threatLevel !== 'none').length
  const fpRate = stats?.falsePositiveRate ?? 0
  const recent = incidents.slice(0, 10)

  return (
    <div style={s.page}>
      <div style={s.grid4}>
        <StatCard label="Total Scans" value={totalScans.toLocaleString()} />
        <StatCard label="Threats Detected" value={threats.toLocaleString()} />
        <StatCard label="False Positive Rate" value={`${(fpRate * 100).toFixed(1)}%`} invertDelta />
        <StatCard label="Active Patterns" value={stats?.totalPatterns.toLocaleString() ?? '0'} />
      </div>

      <div style={s.section}>
        <h3 style={s.sectionTitle}>Kill Chain Distribution</h3>
        <KillChainHeatmap data={distribution} />
      </div>

      <div style={{ ...s.row, ...s.section }}>
        <div style={s.flex1}>
          <Card title="Threat Timeline">
            <ThreatTimeline incidents={incidents} />
          </Card>
        </div>
        <div style={s.flex1}>
          <Card title="Scanner Breakdown">
            <ScannerBreakdown incidents={incidents} />
          </Card>
        </div>
      </div>

      <div style={s.section}>
        <Card title="Recent Incidents">
          {recent.length === 0 ? (
            <div style={{ color: theme.colors.textDim, padding: 16, textAlign: 'center' }}>No recent incidents</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr>
                  <th style={TH}>Time</th>
                  <th style={TH}>Threat</th>
                  <th style={TH}>Phase</th>
                  <th style={TH}>Vector</th>
                  <th style={TH}>Action</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((inc) => (
                  <tr key={inc.id} style={{ borderBottom: `1px solid rgba(51,65,85,0.4)` }}>
                    <td style={{ ...TD, color: theme.colors.textMuted }}>{new Date(inc.timestamp).toLocaleTimeString()}</td>
                    <td style={TD}><ThreatBadge level={inc.threatLevel} /></td>
                    <td style={TD}><PhaseBadge phase={inc.killChainPhase} /></td>
                    <td style={{ ...TD, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.attackVector}</td>
                    <td style={{ ...TD, textTransform: 'uppercase', fontSize: 11, fontWeight: 600 }}>{inc.action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </div>
  )
}
