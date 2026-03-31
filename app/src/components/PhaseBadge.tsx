'use client'

import type { KillChainPhase } from '@/lib/shieldx'

const PHASE_LABELS: Record<KillChainPhase, string> = {
  none: '--',
  initial_access: 'IA',
  privilege_escalation: 'PE',
  reconnaissance: 'RC',
  persistence: 'PS',
  command_and_control: 'C2',
  lateral_movement: 'LM',
  actions_on_objective: 'AO',
}

const PHASE_NAMES: Record<KillChainPhase, string> = {
  none: 'None',
  initial_access: 'Initial Access',
  privilege_escalation: 'Privilege Escalation',
  reconnaissance: 'Reconnaissance',
  persistence: 'Persistence',
  command_and_control: 'Command & Control',
  lateral_movement: 'Lateral Movement',
  actions_on_objective: 'Actions on Objective',
}

interface PhaseBadgeProps {
  readonly phase: KillChainPhase
  readonly showFull?: boolean
}

export function PhaseBadge({ phase, showFull }: PhaseBadgeProps) {
  const label = showFull ? PHASE_NAMES[phase] : PHASE_LABELS[phase]
  return (
    <span className="badge-phase" title={PHASE_NAMES[phase]}>
      {label}
    </span>
  )
}

export { PHASE_LABELS, PHASE_NAMES }
