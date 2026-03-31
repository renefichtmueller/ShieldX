'use client'

import { Badge } from './Badge'
import type { BadgeVariant } from './Badge'
import type { KillChainPhase } from '../types'

const PHASE_VARIANTS: Record<KillChainPhase, BadgeVariant> = {
  none: 'default',
  initial_access: 'blue',
  privilege_escalation: 'orange',
  reconnaissance: 'yellow',
  persistence: 'violet',
  command_and_control: 'red',
  lateral_movement: 'orange',
  actions_on_objective: 'red',
}

const PHASE_LABELS: Record<KillChainPhase, string> = {
  none: 'None',
  initial_access: 'Initial Access',
  privilege_escalation: 'Priv Escalation',
  reconnaissance: 'Recon',
  persistence: 'Persistence',
  command_and_control: 'C2',
  lateral_movement: 'Lateral Move',
  actions_on_objective: 'Objective',
}

export interface PhaseBadgeProps {
  readonly phase: KillChainPhase
  readonly className?: string
}

export function PhaseBadge({ phase, className }: PhaseBadgeProps) {
  return (
    <Badge variant={PHASE_VARIANTS[phase]} className={className}>
      {PHASE_LABELS[phase]}
    </Badge>
  )
}
