'use client'

import { theme } from '../theme'

export interface StatCardProps {
  readonly label: string
  readonly value: string | number
  readonly delta?: number
  readonly deltaLabel?: string
  readonly invertDelta?: boolean
  readonly className?: string
}

export function StatCard({ label, value, delta, deltaLabel, invertDelta = false, className }: StatCardProps) {
  const isUp = delta !== undefined && delta > 0
  const isDown = delta !== undefined && delta < 0
  const deltaColor = delta === undefined || delta === 0
    ? theme.colors.textMuted
    : (isUp && !invertDelta) || (isDown && invertDelta)
      ? theme.colors.threatCritical
      : theme.colors.threatNone

  return (
    <div
      className={className}
      style={{
        background: theme.colors.card,
        border: `1px solid ${theme.colors.cardBorder}`,
        borderRadius: 8,
        padding: 20,
        color: theme.colors.text,
        fontFamily: theme.font,
        minWidth: 160,
      }}
    >
      <p style={{ fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: theme.colors.textMuted, margin: '0 0 8px' }}>
        {label}
      </p>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
        <p style={{ fontSize: 32, fontWeight: 700, lineHeight: 1, color: theme.colors.textBright, margin: 0 }}>
          {value}
        </p>
        {delta !== undefined ? (
          <span style={{ fontSize: 13, fontWeight: 600, color: deltaColor }}>
            {isUp ? '\u25B2' : isDown ? '\u25BC' : '\u2013'}{' '}
            {Math.abs(delta).toFixed(1)}%
            {deltaLabel ? ` ${deltaLabel}` : ''}
          </span>
        ) : null}
      </div>
    </div>
  )
}
