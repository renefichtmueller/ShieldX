'use client'

import { theme } from '../theme'

export interface LoadingSpinnerProps {
  readonly className?: string
}

export function LoadingSpinner({ className }: LoadingSpinnerProps) {
  return (
    <div className={className} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 32 }}>
      <div
        style={{
          width: 32,
          height: 32,
          border: `3px solid ${theme.colors.cardBorder}`,
          borderTopColor: theme.colors.accent,
          borderRadius: '50%',
          animation: 'shieldx-spin 0.8s linear infinite',
        }}
      />
      <style>{`@keyframes shieldx-spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}
