'use client'

import { theme } from './theme'
import { Tabs } from './components/Tabs'
import type { TabItem } from './components/Tabs'
import { useShieldX } from './hooks'

import { DashboardHome } from './pages/DashboardHome'
import { KillChainView } from './pages/KillChainView'
import { IncidentFeed } from './pages/IncidentFeed'
import { LearningDashboard } from './pages/LearningDashboard'
import { AttackGraphViewer } from './pages/AttackGraphViewer'
import { BehavioralMonitor } from './pages/BehavioralMonitor'
import { ComplianceCenter } from './pages/ComplianceCenter'
import { HealingLog } from './pages/HealingLog'
import { ReviewQueue } from './pages/ReviewQueue'
import { ConfigPanel } from './pages/ConfigPanel'
import { ProtectedLLMs } from './pages/ProtectedLLMs'

export interface ShieldXDashboardProps {
  readonly defaultTab?: string
  readonly className?: string
}

const TABS: readonly TabItem[] = [
  { key: 'overview', label: 'Overview', content: () => <DashboardHome /> },
  { key: 'killchain', label: 'Kill Chain', content: () => <KillChainView /> },
  { key: 'incidents', label: 'Incidents', content: () => <IncidentFeed /> },
  { key: 'learning', label: 'Learning', content: () => <LearningDashboard /> },
  { key: 'attackgraph', label: 'Attack Graph', content: () => <AttackGraphViewer /> },
  { key: 'behavioral', label: 'Behavioral', content: () => <BehavioralMonitor /> },
  { key: 'compliance', label: 'Compliance', content: () => <ComplianceCenter /> },
  { key: 'healing', label: 'Healing', content: () => <HealingLog /> },
  { key: 'review', label: 'Review', content: () => <ReviewQueue /> },
  { key: 'config', label: 'Config', content: () => <ConfigPanel /> },
  { key: 'endpoints', label: 'Protected LLMs', content: () => <ProtectedLLMs /> },
]

export function ShieldXDashboard({ defaultTab, className }: ShieldXDashboardProps) {
  const { error } = useShieldX()

  return (
    <div
      className={className}
      style={{
        background: theme.colors.bg,
        color: theme.colors.text,
        fontFamily: theme.font,
        minHeight: 400,
        borderRadius: 8,
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '16px 24px',
          borderBottom: `1px solid ${theme.colors.card}`,
          background: 'rgba(15, 23, 42, 0.95)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: 6,
              background: `linear-gradient(135deg, ${theme.colors.accent}, #6366f1)`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 14,
              fontWeight: 800,
              color: '#fff',
            }}
          >
            SX
          </div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: theme.colors.textBright, letterSpacing: '-0.01em' }}>
              ShieldX
            </div>
            <div style={{ fontSize: 10, color: theme.colors.textDim, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              LLM Defense Dashboard
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: theme.colors.threatNone,
              animation: 'shieldx-pulse 2s infinite',
            }}
          />
          <span style={{ fontSize: 11, color: theme.colors.textDim }}>Live</span>
        </div>
      </div>

      {/* Error bar */}
      {error ? (
        <div
          style={{
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 6,
            padding: '12px 16px',
            margin: 24,
            color: theme.colors.threatCritical,
            fontSize: 13,
          }}
        >
          {error}
        </div>
      ) : null}

      {/* Content */}
      <div style={{ padding: 24 }}>
        <Tabs tabs={TABS} defaultTab={defaultTab ?? 'overview'} />
      </div>

      <style>{`
        @keyframes shieldx-pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  )
}
