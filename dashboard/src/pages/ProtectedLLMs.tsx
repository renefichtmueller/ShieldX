'use client'

import * as s from './styles'
import { theme } from '../theme'
import { useProtectedEndpoints } from '../hooks'
import { DataTable } from '../components/DataTable'
import type { DataTableColumn } from '../components/DataTable'
import { Badge } from '../components/Badge'
import { LoadingSpinner } from '../components/LoadingSpinner'
import type { ProtectedEndpoint } from '../types'

export function ProtectedLLMs() {
  const { protectedEndpoints, loading } = useProtectedEndpoints()

  if (loading) return <LoadingSpinner />

  const columns: DataTableColumn<ProtectedEndpoint>[] = [
    { key: 'name', header: 'Name', render: (r) => <span style={{ fontWeight: 600, color: theme.colors.textBright }}>{r.name}</span>, accessor: (r) => r.name },
    { key: 'provider', header: 'Provider', render: (r) => <Badge variant={r.provider === 'anthropic' ? 'violet' : r.provider === 'ollama' ? 'blue' : 'default'}>{r.provider.toUpperCase()}</Badge>, accessor: (r) => r.provider },
    { key: 'endpoint', header: 'Endpoint', render: (r) => <span style={{ fontFamily: 'monospace', fontSize: 11, color: theme.colors.textMuted }}>{r.endpoint.length > 40 ? r.endpoint.slice(0, 38) + '\u2026' : r.endpoint}</span>, accessor: (r) => r.endpoint },
    { key: 'active', header: 'Status', render: (r) => r.active ? <Badge variant="green">ACTIVE</Badge> : <Badge variant="red">INACTIVE</Badge>, accessor: (r) => r.active ? '1' : '0' },
    { key: 'totalScans', header: 'Scans', render: (r) => r.totalScans.toLocaleString(), accessor: (r) => r.totalScans },
    { key: 'threatsBlocked', header: 'Blocked', render: (r) => <span style={{ color: r.threatsBlocked > 0 ? theme.colors.threatCritical : theme.colors.textMuted }}>{r.threatsBlocked.toLocaleString()}</span>, accessor: (r) => r.threatsBlocked },
    { key: 'lastIncident', header: 'Last Incident', render: (r) => r.lastIncident ? <span style={{ fontSize: 12, color: theme.colors.textMuted }}>{new Date(r.lastIncident).toLocaleDateString()}</span> : <span style={{ color: theme.colors.textDim }}>{'\u2013'}</span>, accessor: (r) => r.lastIncident ?? '' },
    { key: 'registeredAt', header: 'Registered', render: (r) => new Date(r.registeredAt).toLocaleDateString(), accessor: (r) => r.registeredAt },
  ]

  return (
    <div style={s.page}>
      <div style={s.header}>
        <div>
          <h2 style={s.pageTitle}>Protected LLMs</h2>
          <p style={s.subtitle}>{protectedEndpoints.length} registered endpoints</p>
        </div>
      </div>
      <DataTable columns={columns} data={protectedEndpoints} pageSize={15} filterable filterPlaceholder="Search endpoints\u2026" getRowKey={(r) => r.id} />
    </div>
  )
}
