'use client'

import { useEffect, useState } from 'react'
import { getShieldX, type ShieldXResult } from '@/lib/shieldx'
import { StatCard } from '@/components/StatCard'
import { ThreatBadge } from '@/components/ThreatBadge'
import { PhaseBadge } from '@/components/PhaseBadge'

interface HealingEntry {
  readonly id: string
  readonly timestamp: string
  readonly action: string
  readonly threatLevel: ShieldXResult['threatLevel']
  readonly phase: ShieldXResult['killChainPhase']
  readonly inputPreview: string
  readonly latency: number
}

export default function HealingPage() {
  const [entries, setEntries] = useState<readonly HealingEntry[]>([])

  useEffect(() => {
    const shield = getShieldX()
    const history = shield.getHistory()
    const healingEntries = history
      .filter((r) => r.healingApplied)
      .map((r) => ({
        id: r.id,
        timestamp: r.timestamp,
        action: r.action,
        threatLevel: r.threatLevel,
        phase: r.killChainPhase,
        inputPreview: r.input.slice(0, 80),
        latency: r.latencyMs,
      }))
    setEntries(healingEntries)
  }, [])

  const sanitized = entries.filter((e) => e.action === 'sanitize').length
  const blocked = entries.filter((e) => e.action === 'block').length
  const warned = entries.filter((e) => e.action === 'warn').length
  const reset = entries.filter((e) => e.action === 'reset').length

  return (
    <div>
      <div className="page-header">
        <h1>Healing Log</h1>
        <p>Automated response actions taken against detected threats</p>
      </div>

      {/* Stats */}
      <div className="grid-4 mb-6">
        <StatCard
          value={entries.length}
          label="Total Healed"
          subtitle="All healing actions"
          color="#8b5cf6"
        />
        <StatCard
          value={sanitized}
          label="Sanitized"
          subtitle="Input cleaned and allowed"
          color="#eab308"
        />
        <StatCard
          value={blocked}
          label="Blocked"
          subtitle="Request denied"
          color="#ef4444"
        />
        <StatCard
          value={warned}
          label="Warned"
          subtitle="Flagged but allowed"
          color="#f97316"
        />
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0 }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>Threat</th>
              <th>Phase</th>
              <th>Input Preview</th>
              <th>Latency</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32 }}>
                  No healing actions recorded. Run scans from the Overview page first.
                </td>
              </tr>
            ) : (
              entries.map((e) => (
                <tr key={e.id}>
                  <td className="font-mono text-sm text-muted">
                    {new Date(e.timestamp).toLocaleTimeString()}
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        e.action === 'block'
                          ? 'badge-critical'
                          : e.action === 'sanitize'
                            ? 'badge-medium'
                            : e.action === 'warn'
                              ? 'badge-high'
                              : 'badge-low'
                      }`}
                    >
                      {e.action}
                    </span>
                  </td>
                  <td><ThreatBadge level={e.threatLevel} /></td>
                  <td><PhaseBadge phase={e.phase} /></td>
                  <td
                    className="font-mono text-sm text-secondary"
                    style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                  >
                    {e.inputPreview}
                  </td>
                  <td className="font-mono text-sm text-muted">
                    {e.latency.toFixed(1)}ms
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
