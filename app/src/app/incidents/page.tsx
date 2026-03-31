'use client'

import { useState, useEffect, useMemo } from 'react'
import { getShieldX, type ShieldXResult, type ThreatLevel, type KillChainPhase } from '@/lib/shieldx'
import { ThreatBadge } from '@/components/ThreatBadge'
import { PhaseBadge } from '@/components/PhaseBadge'
import { DataTable, type Column } from '@/components/DataTable'

const THREAT_OPTIONS: readonly ThreatLevel[] = ['none', 'low', 'medium', 'high', 'critical']

const PHASE_OPTIONS: readonly { value: KillChainPhase; label: string }[] = [
  { value: 'none', label: 'All Phases' },
  { value: 'initial_access', label: 'Initial Access' },
  { value: 'privilege_escalation', label: 'Privilege Escalation' },
  { value: 'reconnaissance', label: 'Reconnaissance' },
  { value: 'persistence', label: 'Persistence' },
  { value: 'command_and_control', label: 'Command & Control' },
  { value: 'lateral_movement', label: 'Lateral Movement' },
  { value: 'actions_on_objective', label: 'Actions on Objective' },
]

interface IncidentRow {
  readonly id: string
  readonly timestamp: string
  readonly threatLevel: ThreatLevel
  readonly killChainPhase: KillChainPhase
  readonly action: string
  readonly patterns: string
  readonly latencyMs: number
  readonly input: string
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<readonly IncidentRow[]>([])
  const [threatFilter, setThreatFilter] = useState<ThreatLevel | 'all'>('all')
  const [phaseFilter, setPhaseFilter] = useState<KillChainPhase | 'all'>('all')
  const [search, setSearch] = useState('')

  useEffect(() => {
    const shield = getShieldX()
    const history = shield.getHistory()
    const rows: IncidentRow[] = history
      .filter((r) => r.detected)
      .map((r) => ({
        id: r.id,
        timestamp: r.timestamp,
        threatLevel: r.threatLevel,
        killChainPhase: r.killChainPhase,
        action: r.action,
        patterns: r.scanResults
          .filter((s) => s.detected)
          .flatMap((s) => [...s.matchedPatterns])
          .join(', '),
        latencyMs: r.latencyMs,
        input: r.input,
      }))
    setIncidents(rows)
  }, [])

  const filtered = useMemo(() => {
    let result = incidents
    if (threatFilter !== 'all') {
      result = result.filter((r) => r.threatLevel === threatFilter)
    }
    if (phaseFilter !== 'all') {
      result = result.filter((r) => r.killChainPhase === phaseFilter)
    }
    if (search.trim()) {
      const q = search.toLowerCase()
      result = result.filter(
        (r) =>
          r.input.toLowerCase().includes(q) ||
          r.patterns.toLowerCase().includes(q) ||
          r.action.toLowerCase().includes(q)
      )
    }
    return result
  }, [incidents, threatFilter, phaseFilter, search])

  const columns: Column<IncidentRow>[] = [
    {
      key: 'timestamp',
      label: 'Time',
      width: '120px',
      render: (row) => (
        <span className="font-mono text-sm text-muted">
          {new Date(row.timestamp).toLocaleTimeString()}
        </span>
      ),
    },
    {
      key: 'threatLevel',
      label: 'Threat',
      width: '100px',
      render: (row) => <ThreatBadge level={row.threatLevel} />,
    },
    {
      key: 'killChainPhase',
      label: 'Phase',
      width: '80px',
      render: (row) => <PhaseBadge phase={row.killChainPhase} />,
    },
    {
      key: 'action',
      label: 'Action',
      width: '90px',
      render: (row) => <span className="font-mono text-sm">{row.action}</span>,
    },
    {
      key: 'patterns',
      label: 'Matched Patterns',
      render: (row) => (
        <span className="text-sm text-secondary" style={{ maxWidth: 300, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {row.patterns || '--'}
        </span>
      ),
    },
    {
      key: 'latencyMs',
      label: 'Latency',
      width: '80px',
      render: (row) => (
        <span className="font-mono text-sm text-muted">{row.latencyMs.toFixed(1)}ms</span>
      ),
    },
  ]

  return (
    <div>
      <div className="page-header">
        <h1>Incident Feed</h1>
        <p>{filtered.length} incidents detected across {incidents.length} total</p>
      </div>

      {/* Filters */}
      <div className="filter-bar">
        <select
          className="input"
          value={threatFilter}
          onChange={(e) => setThreatFilter(e.target.value as ThreatLevel | 'all')}
        >
          <option value="all">All Threat Levels</option>
          {THREAT_OPTIONS.map((t) => (
            <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
          ))}
        </select>

        <select
          className="input"
          value={phaseFilter}
          onChange={(e) => setPhaseFilter(e.target.value as KillChainPhase | 'all')}
        >
          <option value="all">All Phases</option>
          {PHASE_OPTIONS.filter((p) => p.value !== 'none').map((p) => (
            <option key={p.value} value={p.value}>{p.label}</option>
          ))}
        </select>

        <input
          type="text"
          className="input"
          placeholder="Search patterns, actions..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: 1, minWidth: 200 }}
        />
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0 }}>
        <DataTable
          columns={columns}
          data={filtered}
          keyField="id"
        />
      </div>
    </div>
  )
}
