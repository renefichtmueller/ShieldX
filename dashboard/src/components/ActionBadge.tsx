'use client'

import { Badge } from './Badge'
import type { BadgeVariant } from './Badge'
import type { HealingAction } from '../types'

const ACTION_VARIANTS: Record<HealingAction, BadgeVariant> = {
  allow: 'green',
  sanitize: 'blue',
  warn: 'yellow',
  block: 'orange',
  reset: 'red',
  incident: 'red',
}

export interface ActionBadgeProps {
  readonly action: HealingAction | string
  readonly className?: string
}

export function ActionBadge({ action, className }: ActionBadgeProps) {
  const variant = ACTION_VARIANTS[action as HealingAction] ?? 'default'
  return (
    <Badge variant={variant} className={className}>
      {action.toUpperCase()}
    </Badge>
  )
}
