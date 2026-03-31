'use client'

import * as s from './styles'
import { useSessions } from '../hooks'
import { DataTable } from '../components/DataTable'
import type { DataTableColumn } from '../components/DataTable'
import { ProgressBar } from '../components/ProgressBar'
import { Badge } from '../components/Badge'
import { LoadingSpinner } from '../components/LoadingSpinner'
import { theme } from '../theme'
import type { ConversationState } from '../types'

export function BehavioralMonitor() {
  const { sessions, loading } = useSessions()

  if (loading) return <LoadingSpinner />

  const columns: DataTableColumn<ConversationState>[] = [
    { key: 'sessionId', header: 'Session', render: (r) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{r.sessionId.slice(0, 12)}{'\u2026'}</span>, accessor: (r) => r.sessionId },
    { key: 'turns', header: 'Turns', render: (r) => r.turns.length, accessor: (r) => r.turns.length },
    { key: 'suspicionScore', header: 'Suspicion', render: (r) => <ProgressBar value={r.suspicionScore * 100} showPercentage={false} color={r.suspicionScore > 0.7 ? 'red' : r.suspicionScore > 0.4 ? 'orange' : 'green'} />, accessor: (r) => r.suspicionScore },
    { key: 'escalationDetected', header: 'Escalation', render: (r) => r.escalationDetected ? <Badge variant="red">DETECTED</Badge> : <Badge variant="green">NONE</Badge>, accessor: (r) => r.escalationDetected ? '1' : '0' },
    { key: 'topicDrift', header: 'Topic Drift', render: (r) => <span style={{ color: r.topicDrift > 0.5 ? theme.colors.threatHigh : theme.colors.textMuted }}>{r.topicDrift.toFixed(2)}</span>, accessor: (r) => r.topicDrift },
    { key: 'authorityShifts', header: 'Auth Shifts', render: (r) => <span style={{ color: r.authorityShifts > 2 ? theme.colors.threatCritical : theme.colors.textMuted }}>{r.authorityShifts}</span>, accessor: (r) => r.authorityShifts },
    { key: 'lastUpdated', header: 'Last Activity', render: (r) => new Date(r.lastUpdated).toLocaleTimeString(), accessor: (r) => r.lastUpdated },
  ]

  return (
    <div style={s.page}>
      <div style={s.header}>
        <div>
          <h2 style={s.pageTitle}>Behavioral Monitor</h2>
          <p style={s.subtitle}>{sessions.length} active sessions</p>
        </div>
      </div>
      <DataTable columns={columns} data={sessions} pageSize={15} filterable filterPlaceholder="Search sessions\u2026" getRowKey={(r) => r.sessionId} />
    </div>
  )
}
