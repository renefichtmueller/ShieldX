'use client'

import { theme } from '../theme'

export interface ToggleProps {
  readonly checked: boolean
  readonly onChange?: (checked: boolean) => void
  readonly label?: string
  readonly disabled?: boolean
  readonly className?: string
}

export function Toggle({ checked, onChange, label, disabled = false, className }: ToggleProps) {
  return (
    <div
      className={className}
      onClick={!disabled ? () => onChange?.(!checked) : undefined}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        fontFamily: theme.font,
      }}
    >
      <div
        style={{
          width: 36,
          height: 20,
          borderRadius: 10,
          background: checked ? theme.colors.accent : theme.colors.cardBorder,
          position: 'relative',
          transition: 'background 0.2s',
        }}
      >
        <div
          style={{
            position: 'absolute',
            top: 2,
            left: checked ? 18 : 2,
            width: 16,
            height: 16,
            borderRadius: '50%',
            background: theme.colors.text,
            transition: 'left 0.2s',
          }}
        />
      </div>
      {label ? <span style={{ fontSize: 13, color: theme.colors.textMuted }}>{label}</span> : null}
    </div>
  )
}
