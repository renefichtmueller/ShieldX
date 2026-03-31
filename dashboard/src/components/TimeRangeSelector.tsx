'use client'

import { theme } from '../theme'
import type { TimeRange } from '../types'

const TIME_RANGE_OPTIONS: readonly { value: TimeRange; label: string }[] = [
  { value: '1h', label: 'Last 1 hour' },
  { value: '6h', label: 'Last 6 hours' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: 'all', label: 'All time' },
]

export interface TimeRangeSelectorProps {
  readonly value: TimeRange
  readonly onChange: (range: TimeRange) => void
  readonly className?: string
}

export function TimeRangeSelector({ value, onChange, className }: TimeRangeSelectorProps) {
  return (
    <div className={className} style={{ position: 'relative', display: 'inline-flex' }}>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as TimeRange)}
        style={{
          appearance: 'none',
          background: theme.colors.bg,
          border: `1px solid ${theme.colors.cardBorder}`,
          borderRadius: 4,
          color: theme.colors.text,
          padding: '6px 28px 6px 10px',
          fontSize: 12,
          fontFamily: theme.font,
          cursor: 'pointer',
          outline: 'none',
        }}
      >
        {TIME_RANGE_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      <span style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none', color: theme.colors.textDim, fontSize: 10 }}>
        {'\u25BC'}
      </span>
    </div>
  )
}
