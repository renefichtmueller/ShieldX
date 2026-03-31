'use client'

import type { ThreatLevel } from '@/lib/shieldx'

interface ThreatBadgeProps {
  readonly level: ThreatLevel
}

export function ThreatBadge({ level }: ThreatBadgeProps) {
  return (
    <span className={`badge badge-${level}`}>
      {level}
    </span>
  )
}
