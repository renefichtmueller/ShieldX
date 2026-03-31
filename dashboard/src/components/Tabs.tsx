'use client'

import React, { useState } from 'react'
import { theme } from '../theme'

export interface TabItem {
  readonly key: string
  readonly label: string
  readonly content: () => React.ReactNode
}

export interface TabsProps {
  readonly tabs: readonly TabItem[]
  readonly defaultTab?: string
  readonly className?: string
}

export function Tabs({ tabs, defaultTab, className }: TabsProps) {
  const [active, setActive] = useState(defaultTab ?? tabs[0]?.key ?? '')

  const activeTab = tabs.find((t) => t.key === active)

  return (
    <div className={className} style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div
        style={{
          display: 'flex',
          gap: 0,
          borderBottom: `1px solid ${theme.colors.cardBorder}`,
          overflowX: 'auto',
          flexShrink: 0,
        }}
      >
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActive(tab.key)}
            style={{
              padding: '10px 16px',
              fontSize: 12,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              color: tab.key === active ? theme.colors.accent : theme.colors.textDim,
              background: 'transparent',
              border: 'none',
              borderBottom: tab.key === active ? `2px solid ${theme.colors.accent}` : '2px solid transparent',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              fontFamily: theme.font,
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div style={{ flex: 1, overflowY: 'auto', paddingTop: 20 }}>
        {activeTab ? activeTab.content() : null}
      </div>
    </div>
  )
}
