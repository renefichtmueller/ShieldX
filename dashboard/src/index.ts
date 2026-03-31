'use client'

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------
export { ShieldXProvider } from './provider'
export type { ShieldXProviderProps, ShieldXContextValue } from './provider'

// ---------------------------------------------------------------------------
// Main Dashboard
// ---------------------------------------------------------------------------
export { ShieldXDashboard } from './ShieldXDashboard'
export type { ShieldXDashboardProps } from './ShieldXDashboard'

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------
export {
  useShieldX,
  useStats,
  useIncidents,
  useKillChain,
  useAttackGraph,
  useReviewQueue,
  useDrift,
  useCompliance,
  useConfig,
  useSessions,
  useHealingLog,
  useProtectedEndpoints,
  useTimeRange,
} from './hooks'
export type { IncidentFilters, KillChainDistribution } from './hooks'

// ---------------------------------------------------------------------------
// Pages (individual views)
// ---------------------------------------------------------------------------
export { DashboardHome } from './pages/DashboardHome'
export { KillChainView } from './pages/KillChainView'
export { IncidentFeed } from './pages/IncidentFeed'
export { LearningDashboard } from './pages/LearningDashboard'
export { AttackGraphViewer } from './pages/AttackGraphViewer'
export { BehavioralMonitor } from './pages/BehavioralMonitor'
export { ComplianceCenter } from './pages/ComplianceCenter'
export { HealingLog } from './pages/HealingLog'
export { ReviewQueue } from './pages/ReviewQueue'
export { ConfigPanel } from './pages/ConfigPanel'
export { ProtectedLLMs } from './pages/ProtectedLLMs'

// ---------------------------------------------------------------------------
// Base Components
// ---------------------------------------------------------------------------
export { Card } from './components/Card'
export type { CardProps } from './components/Card'

export { StatCard } from './components/StatCard'
export type { StatCardProps } from './components/StatCard'

export { Badge } from './components/Badge'
export type { BadgeProps, BadgeVariant } from './components/Badge'

export { ThreatBadge } from './components/ThreatBadge'
export type { ThreatBadgeProps } from './components/ThreatBadge'

export { PhaseBadge } from './components/PhaseBadge'
export type { PhaseBadgeProps } from './components/PhaseBadge'

export { ActionBadge } from './components/ActionBadge'
export type { ActionBadgeProps } from './components/ActionBadge'

export { DataTable } from './components/DataTable'
export type { DataTableProps, DataTableColumn } from './components/DataTable'

export { EmptyState } from './components/EmptyState'
export type { EmptyStateProps } from './components/EmptyState'

export { LoadingSpinner } from './components/LoadingSpinner'
export type { LoadingSpinnerProps } from './components/LoadingSpinner'

export { TimeRangeSelector } from './components/TimeRangeSelector'
export type { TimeRangeSelectorProps } from './components/TimeRangeSelector'

export { Tabs } from './components/Tabs'
export type { TabsProps, TabItem } from './components/Tabs'

export { Toggle } from './components/Toggle'
export type { ToggleProps } from './components/Toggle'

export { Slider } from './components/Slider'
export type { SliderProps } from './components/Slider'

export { ProgressBar } from './components/ProgressBar'
export type { ProgressBarProps, ProgressColor } from './components/ProgressBar'

// ---------------------------------------------------------------------------
// Charts
// ---------------------------------------------------------------------------
export { KillChainHeatmap } from './charts/KillChainHeatmap'
export type { KillChainHeatmapProps } from './charts/KillChainHeatmap'

export { ThreatTimeline } from './charts/ThreatTimeline'
export type { ThreatTimelineProps } from './charts/ThreatTimeline'

export { ScannerBreakdown } from './charts/ScannerBreakdown'
export type { ScannerBreakdownProps } from './charts/ScannerBreakdown'

export { FPRateTrend } from './charts/FPRateTrend'
export type { FPRateTrendProps } from './charts/FPRateTrend'

export { PatternDistribution } from './charts/PatternDistribution'
export type { PatternDistributionProps } from './charts/PatternDistribution'

export { ComplianceMeter } from './charts/ComplianceMeter'
export type { ComplianceMeterProps } from './charts/ComplianceMeter'

export { DriftChart } from './charts/DriftChart'
export type { DriftChartProps } from './charts/DriftChart'

export { AttackGraphViz } from './charts/AttackGraphViz'
export type { AttackGraphVizProps } from './charts/AttackGraphViz'
