'use client'

import React from 'react'
import { theme } from '../theme'

export interface CardProps {
  readonly title?: string
  readonly className?: string
  readonly children: React.ReactNode
}

export function Card({ title, className, children }: CardProps) {
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
      }}
    >
      {title ? (
        <h3
          style={{
            fontSize: 13,
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            color: theme.colors.textMuted,
            margin: '0 0 16px',
            paddingBottom: 12,
            borderBottom: `1px solid ${theme.colors.cardBorder}`,
          }}
        >
          {title}
        </h3>
      ) : null}
      {children}
    </div>
  )
}
