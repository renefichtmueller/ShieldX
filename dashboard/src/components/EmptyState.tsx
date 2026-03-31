'use client'

import { theme } from '../theme'

export interface EmptyStateProps {
  readonly message?: string
  readonly icon?: string
  readonly className?: string
}

export function EmptyState({ message = 'No data available', icon = '\u26A0', className }: EmptyStateProps) {
  return (
    <div
      className={className}
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '48px 24px',
        color: theme.colors.textDim,
        fontFamily: theme.font,
        textAlign: 'center',
      }}
    >
      <span style={{ fontSize: 36, marginBottom: 12, opacity: 0.5 }}>{icon}</span>
      <p style={{ fontSize: 14, margin: 0 }}>{message}</p>
    </div>
  )
}
