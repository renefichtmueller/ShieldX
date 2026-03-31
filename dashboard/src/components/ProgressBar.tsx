'use client'

import { theme } from '../theme'

export type ProgressColor = 'green' | 'blue' | 'yellow' | 'orange' | 'red' | 'violet'

export interface ProgressBarProps {
  readonly value: number
  readonly max?: number
  readonly label?: string
  readonly color?: ProgressColor
  readonly showPercentage?: boolean
  readonly className?: string
}

const COLOR_MAP: Record<ProgressColor, string> = {
  green: theme.colors.threatNone,
  blue: theme.colors.threatLow,
  yellow: theme.colors.threatMedium,
  orange: theme.colors.threatHigh,
  red: theme.colors.threatCritical,
  violet: theme.colors.accent,
}

function autoColor(pct: number): ProgressColor {
  if (pct < 25) return 'green'
  if (pct < 50) return 'blue'
  if (pct < 75) return 'yellow'
  if (pct < 90) return 'orange'
  return 'red'
}

export function ProgressBar({
  value,
  max = 100,
  label,
  color,
  showPercentage = true,
  className,
}: ProgressBarProps) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100))
  const resolvedColor = color ?? autoColor(pct)

  return (
    <div className={className} style={{ display: 'flex', flexDirection: 'column', gap: 4, fontFamily: theme.font }}>
      {label || showPercentage ? (
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: theme.colors.textMuted }}>
          <span>{label ?? ''}</span>
          {showPercentage ? <span>{pct.toFixed(0)}%</span> : null}
        </div>
      ) : null}
      <div style={{ height: 6, borderRadius: 3, background: theme.colors.cardBorder, overflow: 'hidden' }}>
        <div
          style={{
            height: '100%',
            borderRadius: 3,
            background: COLOR_MAP[resolvedColor],
            width: `${pct}%`,
            transition: 'width 0.3s ease',
          }}
        />
      </div>
    </div>
  )
}
