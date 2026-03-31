'use client'

import { theme } from '../theme'

export interface SliderProps {
  readonly label?: string
  readonly value: number
  readonly min?: number
  readonly max?: number
  readonly step?: number
  readonly onChange?: (value: number) => void
  readonly disabled?: boolean
  readonly className?: string
}

export function Slider({
  label,
  value,
  min = 0,
  max = 1,
  step = 0.01,
  onChange,
  disabled = false,
  className,
}: SliderProps) {
  return (
    <div className={className} style={{ display: 'flex', flexDirection: 'column', gap: 6, fontFamily: theme.font }}>
      {label ? (
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: theme.colors.textMuted }}>
          <span>{label}</span>
          <span>{value.toFixed(2)}</span>
        </div>
      ) : null}
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange?.(Number(e.target.value))}
        style={{ width: '100%', accentColor: theme.colors.accent }}
      />
    </div>
  )
}
