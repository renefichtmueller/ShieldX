'use client'

import { useState } from 'react'
import * as s from './styles'
import { theme } from '../theme'
import { useKillChain, useIncidents } from '../hooks'
import { Card } from '../components/Card'
import { ThreatBadge } from '../components/ThreatBadge'
import { LoadingSpinner } from '../components/LoadingSpinner'
import { KillChainHeatmap } from '../charts/KillChainHeatmap'
import type { KillChainPhase } from '../types'

const PHASE_DETAILS: Record<string, { description: string; mitigations: readonly string[] }> = {
  initial_access: { description: 'Attacker gains initial entry via prompt injection, adversarial input, or social engineering.', mitigations: ['Input validation', 'Unicode normalization', 'Delimiter hardening'] },
  privilege_escalation: { description: 'Attacker attempts to elevate privileges by impersonating system roles or overriding instructions.', mitigations: ['Trust tagging', 'Role integrity checks', 'Constitutional AI'] },
  reconnaissance: { description: 'Attacker probes the system to discover capabilities, model identity, or configuration.', mitigations: ['Self-consciousness scanner', 'Canary tokens', 'Output validation'] },
  persistence: { description: 'Attacker establishes persistent mechanisms to survive conversation resets.', mitigations: ['Memory integrity guard', 'Session checkpoints', 'Context integrity'] },
  command_and_control: { description: 'Attacker establishes covert communication channels or exfiltration paths.', mitigations: ['Tool chain guard', 'Resource governor', 'Output sanitization'] },
  lateral_movement: { description: 'Attacker moves across tools, APIs, or MCP servers to expand access.', mitigations: ['MCP inspector', 'Privilege checker', 'Tool call interceptor'] },
  actions_on_objective: { description: 'Attacker achieves their final goal: data exfiltration, system manipulation, or harm.', mitigations: ['RAG shield', 'Output validator', 'Credential redactor', 'Incident reporting'] },
}

export function KillChainView() {
  const { distribution, loading } = useKillChain()
  const { incidents } = useIncidents()
  const [selectedPhase, setSelectedPhase] = useState<KillChainPhase | null>(null)

  if (loading) return <LoadingSpinner />

  const detail = selectedPhase ? PHASE_DETAILS[selectedPhase] : null
  const phaseIncidents = selectedPhase ? incidents.filter((i) => i.killChainPhase === selectedPhase) : []

  return (
    <div style={s.page}>
      <div style={s.header}>
        <div>
          <h2 style={s.pageTitle}>Promptware Kill Chain</h2>
          <p style={s.subtitle}>Schneier et al. 2026 -- 7 phase attack lifecycle</p>
        </div>
      </div>

      <KillChainHeatmap data={distribution} onPhaseClick={(phase) => setSelectedPhase(phase as KillChainPhase)} />

      {selectedPhase && detail ? (
        <div style={s.detailPanel}>
          <h3 style={s.detailTitle}>{selectedPhase.replace(/_/g, ' ').toUpperCase()}</h3>
          <p style={{ fontSize: 13, color: '#cbd5e1', margin: '0 0 12px' }}>{detail.description}</p>
          <div style={s.detailRow}>
            <span style={s.detailLabel}>Incidents in this phase</span>
            <span style={s.detailValue}>{phaseIncidents.length}</span>
          </div>
          <h4 style={{ fontSize: 12, color: theme.colors.textMuted, margin: '16px 0 8px', textTransform: 'uppercase' }}>Mitigations</h4>
          <ul style={{ margin: 0, paddingLeft: 16 }}>
            {detail.mitigations.map((m) => (
              <li key={m} style={{ fontSize: 13, color: theme.colors.threatNone, padding: '2px 0' }}>{m}</li>
            ))}
          </ul>
          {phaseIncidents.length > 0 ? (
            <>
              <h4 style={{ fontSize: 12, color: theme.colors.textMuted, margin: '16px 0 8px', textTransform: 'uppercase' }}>Recent Phase Incidents</h4>
              {phaseIncidents.slice(0, 5).map((inc) => (
                <div key={inc.id} style={s.detailRow}>
                  <span style={s.detailLabel}>{new Date(inc.timestamp).toLocaleString()}</span>
                  <ThreatBadge level={inc.threatLevel} />
                </div>
              ))}
            </>
          ) : null}
        </div>
      ) : (
        <Card title="Select a Phase">
          <p style={{ color: theme.colors.textDim, fontSize: 13 }}>Click on a kill chain phase above to view details</p>
        </Card>
      )}
    </div>
  )
}
