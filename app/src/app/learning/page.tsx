'use client'

import { useState, useEffect } from 'react'
import { getShieldX } from '@/lib/shieldx'
import { StatCard } from '@/components/StatCard'

interface PatternItem {
  readonly id: string
  readonly name: string
  readonly type: string
  readonly phase: string
  readonly hits: number
  readonly fpRate: number
  readonly enabled: boolean
  readonly source: string
}

const DEMO_PATTERNS: PatternItem[] = [
  { id: 'p1', name: 'Instruction override (ignore previous)', type: 'regex', phase: 'Initial Access', hits: 847, fpRate: 0.02, enabled: true, source: 'builtin' },
  { id: 'p2', name: 'DAN jailbreak variants', type: 'regex', phase: 'Privilege Escalation', hits: 623, fpRate: 0.01, enabled: true, source: 'builtin' },
  { id: 'p3', name: 'System prompt extraction', type: 'regex', phase: 'Reconnaissance', hits: 412, fpRate: 0.03, enabled: true, source: 'builtin' },
  { id: 'p4', name: 'Role delimiter injection', type: 'regex', phase: 'Command & Control', hits: 356, fpRate: 0.01, enabled: true, source: 'builtin' },
  { id: 'p5', name: 'Persistent behavior change', type: 'regex', phase: 'Persistence', hits: 289, fpRate: 0.04, enabled: true, source: 'builtin' },
  { id: 'p6', name: 'Unicode homoglyph attacks', type: 'embedding', phase: 'Initial Access', hits: 178, fpRate: 0.08, enabled: true, source: 'learned' },
  { id: 'p7', name: 'Base64 encoded payloads', type: 'entropy', phase: 'Initial Access', hits: 245, fpRate: 0.05, enabled: true, source: 'builtin' },
  { id: 'p8', name: 'Multi-turn escalation', type: 'behavioral', phase: 'Privilege Escalation', hits: 89, fpRate: 0.12, enabled: true, source: 'learned' },
  { id: 'p9', name: 'Tool chain exploitation', type: 'rule', phase: 'Lateral Movement', hits: 67, fpRate: 0.03, enabled: true, source: 'community' },
  { id: 'p10', name: 'Data exfiltration via output', type: 'canary', phase: 'Actions on Objective', hits: 134, fpRate: 0.02, enabled: true, source: 'builtin' },
  { id: 'p11', name: 'Indirect injection via RAG', type: 'embedding', phase: 'Initial Access', hits: 56, fpRate: 0.15, enabled: false, source: 'red_team' },
  { id: 'p12', name: 'Context window poisoning', type: 'behavioral', phase: 'Persistence', hits: 34, fpRate: 0.09, enabled: true, source: 'learned' },
]

export default function LearningPage() {
  const [patterns, setPatterns] = useState<PatternItem[]>(DEMO_PATTERNS)
  const [scanCount, setScanCount] = useState(0)

  useEffect(() => {
    const shield = getShieldX()
    const stats = shield.getStats()
    setScanCount(stats.total)
  }, [])

  const togglePattern = (id: string) => {
    setPatterns((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p))
    )
  }

  const totalPatterns = patterns.length
  const learned = patterns.filter((p) => p.source === 'learned').length
  const community = patterns.filter((p) => p.source === 'community').length
  const avgFp = patterns.reduce((sum, p) => sum + p.fpRate, 0) / patterns.length

  return (
    <div>
      <div className="page-header">
        <h1>Learning Engine</h1>
        <p>Self-evolving pattern detection with drift monitoring</p>
      </div>

      {/* Stats */}
      <div className="grid-4 mb-6">
        <StatCard value={totalPatterns} label="Total Patterns" subtitle="Across all sources" color="#8b5cf6" />
        <StatCard value={learned} label="Learned" subtitle="From feedback loop" color="#3b82f6" />
        <StatCard value={community} label="Community" subtitle="Federated sync" color="#22c55e" />
        <StatCard value={`${(avgFp * 100).toFixed(1)}%`} label="Avg FP Rate" subtitle="Target: <5%" color={avgFp > 0.05 ? '#f97316' : '#22c55e'} />
      </div>

      {/* Drift Status */}
      <div className="card mb-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="status-dot online" />
              <span style={{ fontWeight: 600 }}>Drift Status: Stable</span>
            </div>
            <div className="text-sm text-secondary mt-4" style={{ marginTop: 4 }}>
              No concept drift detected. Last check: {new Date().toLocaleTimeString()}
            </div>
          </div>
          <div className="text-sm font-mono text-muted">
            {scanCount} scans analyzed
          </div>
        </div>
      </div>

      {/* Pattern Table */}
      <div className="section-title">Pattern Library</div>
      <div className="card" style={{ padding: 0 }}>
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 50 }}>On</th>
              <th>Pattern</th>
              <th>Type</th>
              <th>Phase</th>
              <th>Hits</th>
              <th>FP Rate</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {patterns.map((p) => (
              <tr key={p.id}>
                <td>
                  <div
                    className={`toggle ${p.enabled ? 'active' : ''}`}
                    onClick={() => togglePattern(p.id)}
                  />
                </td>
                <td className="text-sm">{p.name}</td>
                <td>
                  <span className="badge-phase">{p.type}</span>
                </td>
                <td className="text-sm text-secondary">{p.phase}</td>
                <td className="font-mono text-sm">{p.hits}</td>
                <td className={`font-mono text-sm ${p.fpRate > 0.1 ? 'text-warning' : 'text-success'}`}>
                  {(p.fpRate * 100).toFixed(1)}%
                </td>
                <td className="text-sm text-muted">{p.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
