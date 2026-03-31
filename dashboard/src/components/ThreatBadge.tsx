'use client'

import { Badge } from './Badge'
import type { BadgeVariant } from './Badge'
import type { ThreatLevel } from '../types'

const THREAT_VARIANTS: Record<ThreatLevel, BadgeVariant> = {
  none: 'green',
  low: 'blue',
  medium: 'yellow',
  high: 'orange',
  critical: 'red',
}

export interface ThreatBadgeProps {
  readonly level: ThreatLevel
  readonly className?: string
}

export function ThreatBadge({ level, className }: ThreatBadgeProps) {
  return (
    <Badge variant={THREAT_VARIANTS[level]} className={className}>
      {level.toUpperCase()}
    </Badge>
  )
}
