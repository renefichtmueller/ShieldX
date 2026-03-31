'use client'

import { useState, useEffect } from 'react'
import { getShieldX, type KillChainPhase, type ShieldXResult } from '@/lib/shieldx'
import { ThreatBadge } from '@/components/ThreatBadge'

const PHASES: {
  readonly phase: KillChainPhase
  readonly label: string
  readonly short: string
  readonly description: string
  readonly indicators: readonly string[]
  readonly mitigations: readonly string[]
  readonly color: string
}[] = [
  {
    phase: 'initial_access',
    label: 'Initial Access',
    short: 'IA',
    description: 'Attacker gains initial foothold through prompt injection, instruction override, or input manipulation.',
    indicators: ['Instruction override patterns', 'Role reassignment attempts', 'Direct injection keywords'],
    mitigations: ['Input sanitization', 'Pattern matching L1', 'Unicode normalization'],
    color: '#3b82f6',
  },
  {
    phase: 'privilege_escalation',
    label: 'Privilege Escalation',
    short: 'PE',
    description: 'Attacker attempts to bypass safety guardrails and gain unrestricted access to model capabilities.',
    indicators: ['DAN/jailbreak attempts', 'Mode switching requests', 'Restriction removal'],
    mitigations: ['Constitutional AI checks', 'Sentinel classifier', 'Behavioral monitoring'],
    color: '#f97316',
  },
  {
    phase: 'reconnaissance',
    label: 'Reconnaissance',
    short: 'RC',
    description: 'Attacker probes the system to extract system prompts, configuration, or behavioral patterns.',
    indicators: ['System prompt extraction', 'Configuration probing', 'Boundary testing'],
    mitigations: ['Canary tokens', 'Output sanitization', 'Prompt leakage detection'],
    color: '#eab308',
  },
  {
    phase: 'persistence',
    label: 'Persistence',
    short: 'PS',
    description: 'Attacker attempts to establish persistent changes to model behavior across conversations.',
    indicators: ['Behavioral modification requests', 'Memory injection', 'Future override attempts'],
    mitigations: ['Context integrity checks', 'Session isolation', 'Memory integrity monitoring'],
    color: '#8b5cf6',
  },
  {
    phase: 'command_and_control',
    label: 'Command & Control',
    short: 'C2',
    description: 'Attacker establishes a control channel through fake system messages or role delimiter injection.',
    indicators: ['Fake system tags', 'Role delimiter injection', 'Hidden instruction embedding'],
    mitigations: ['Tag sanitization', 'Role delimiter validation', 'Structural analysis'],
    color: '#ef4444',
  },
  {
    phase: 'lateral_movement',
    label: 'Lateral Movement',
    short: 'LM',
    description: 'Attacker attempts to access external resources, APIs, or systems through the LLM.',
    indicators: ['Code execution requests', 'API access attempts', 'Tool chain exploitation'],
    mitigations: ['MCP Guard', 'Tool chain monitoring', 'Resource governor'],
    color: '#f97316',
  },
  {
    phase: 'actions_on_objective',
    label: 'Actions on Objective',
    short: 'AO',
    description: 'Attacker achieves their goal: data exfiltration, system manipulation, or destructive actions.',
    indicators: ['Data exfiltration attempts', 'Destructive commands', 'Information leakage'],
    mitigations: ['Output sanitization', 'Data loss prevention', 'Incident response'],
    color: '#ef4444',
  },
]

export default function KillChainPage() {
  const [expanded, setExpanded] = useState<KillChainPhase | null>(null)
  const [phaseMap, setPhaseMap] = useState<Partial<Record<KillChainPhase, number>>>({})
  const [history, setHistory] = useState<readonly ShieldXResult[]>([])

  useEffect(() => {
    const shield = getShieldX()
    const stats = shield.getStats()
    setPhaseMap({ ...stats.phaseMap })
    setHistory(shield.getHistory())
  }, [])

  const toggle = (phase: KillChainPhase) => {
    setExpanded((prev) => (prev === phase ? null : phase))
  }

  return (
    <div>
      <div className="page-header">
        <h1>Promptware Kill Chain</h1>
        <p>Schneier 2026 kill chain mapping with 7 attack phases</p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {PHASES.map((p, idx) => {
          const isExpanded = expanded === p.phase
          const count = phaseMap[p.phase] ?? 0
          const phaseIncidents = history.filter(
            (r) => r.detected && r.killChainPhase === p.phase
          )

          return (
            <div key={p.phase}>
              {/* Phase card with arrow connector */}
              <div
                className="card"
                style={{
                  cursor: 'pointer',
                  borderLeft: `4px solid ${p.color}`,
                  transition: 'all 0.15s',
                }}
                onClick={() => toggle(p.phase)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div
                      style={{
                        width: 48,
                        height: 48,
                        borderRadius: 8,
                        background: `${p.color}20`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontFamily: 'monospace',
                        fontWeight: 700,
                        fontSize: 16,
                        color: p.color,
                        flexShrink: 0,
                      }}
                    >
                      {p.short}
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 15 }}>
                        <span className="text-muted" style={{ marginRight: 8 }}>
                          Phase {idx + 1}
                        </span>
                        {p.label}
                      </div>
                      <div className="text-sm text-secondary" style={{ marginTop: 2 }}>
                        {p.description}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div style={{ textAlign: 'right' }}>
                      <div className="font-mono font-bold" style={{ fontSize: 24, color: p.color }}>
                        {count}
                      </div>
                      <div className="text-xs text-muted">incidents</div>
                    </div>
                    <span className="text-muted" style={{ fontSize: 18 }}>
                      {isExpanded ? '\u25B2' : '\u25BC'}
                    </span>
                  </div>
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--border-color)' }}>
                    <div className="grid-3" style={{ marginBottom: 16 }}>
                      <div>
                        <div className="text-xs text-muted mb-2" style={{ textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 600 }}>
                          Indicators
                        </div>
                        {p.indicators.map((ind) => (
                          <div key={ind} className="text-sm" style={{ padding: '4px 0', color: 'var(--text-secondary)' }}>
                            {'\u2022'} {ind}
                          </div>
                        ))}
                      </div>
                      <div>
                        <div className="text-xs text-muted mb-2" style={{ textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 600 }}>
                          Mitigations
                        </div>
                        {p.mitigations.map((mit) => (
                          <div key={mit} className="text-sm" style={{ padding: '4px 0', color: 'var(--text-secondary)' }}>
                            {'\u2713'} {mit}
                          </div>
                        ))}
                      </div>
                      <div>
                        <div className="text-xs text-muted mb-2" style={{ textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 600 }}>
                          Recent Incidents
                        </div>
                        {phaseIncidents.length === 0 ? (
                          <div className="text-sm text-muted">No incidents in this phase</div>
                        ) : (
                          phaseIncidents.slice(0, 5).map((inc) => (
                            <div key={inc.id} className="flex items-center gap-2" style={{ padding: '4px 0' }}>
                              <ThreatBadge level={inc.threatLevel} />
                              <span className="text-sm font-mono text-secondary" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200 }}>
                                {inc.input.slice(0, 40)}...
                              </span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Arrow connector */}
              {idx < PHASES.length - 1 && (
                <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 18, padding: '2px 0' }}>
                  {'\u25BC'}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
