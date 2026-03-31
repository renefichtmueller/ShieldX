'use client'

import React from 'react'
import { theme } from '../theme'

export type BadgeVariant = 'default' | 'green' | 'blue' | 'yellow' | 'orange' | 'red' | 'violet'

export interface BadgeProps {
  readonly children: React.ReactNode
  readonly variant?: BadgeVariant
  readonly className?: string
}

const VARIANT_STYLES: Record<BadgeVariant, { bg: string; color: string }> = {
  default: { bg: '#334155', color: '#cbd5e1' },
  green: { bg: 'rgba(34, 197, 94, 0.15)', color: theme.colors.threatNone },
  blue: { bg: 'rgba(59, 130, 246, 0.15)', color: theme.colors.threatLow },
  yellow: { bg: 'rgba(234, 179, 8, 0.15)', color: theme.colors.threatMedium },
  orange: { bg: 'rgba(249, 115, 22, 0.15)', color: theme.colors.threatHigh },
  red: { bg: 'rgba(239, 68, 68, 0.15)', color: theme.colors.threatCritical },
  violet: { bg: 'rgba(139, 92, 246, 0.15)', color: theme.colors.accent },
}

export function Badge({ children, variant = 'default', className }: BadgeProps) {
  const vs = VARIANT_STYLES[variant]
  return (
    <span
      className={className}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '2px 10px',
        borderRadius: 9999,
        fontSize: 11,
        fontWeight: 600,
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
        fontFamily: theme.font,
        whiteSpace: 'nowrap',
        background: vs.bg,
        color: vs.color,
      }}
    >
      {children}
    </span>
  )
}
