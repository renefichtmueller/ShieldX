'use client'

import { theme } from '../theme'
import type { KillChainDistribution } from '../hooks'

export interface KillChainHeatmapProps {
  readonly data: readonly KillChainDistribution[]
  readonly onPhaseClick?: (phase: string) => void
  readonly className?: string
}

const INTENSITY_STYLES: readonly { bg: string; color: string; border: string }[] = [
  { bg: 'rgba(34, 197, 94, 0.1)', color: theme.colors.threatNone, border: 'rgba(34, 197, 94, 0.2)' },
  { bg: 'rgba(59, 130, 246, 0.15)', color: theme.colors.threatLow, border: 'rgba(59, 130, 246, 0.25)' },
  { bg: 'rgba(234, 179, 8, 0.15)', color: theme.colors.threatMedium, border: 'rgba(234, 179, 8, 0.25)' },
  { bg: 'rgba(249, 115, 22, 0.2)', color: theme.colors.threatHigh, border: 'rgba(249, 115, 22, 0.3)' },
  { bg: 'rgba(239, 68, 68, 0.25)', color: theme.colors.threatCritical, border: 'rgba(239, 68, 68, 0.35)' },
]

function getIntensity(count: number, maxCount: number): (typeof INTENSITY_STYLES)[number] {
  if (count === 0) return INTENSITY_STYLES[0]!
  const ratio = count / Math.max(maxCount, 1)
  if (ratio < 0.25) return INTENSITY_STYLES[1]!
  if (ratio < 0.5) return INTENSITY_STYLES[2]!
  if (ratio < 0.75) return INTENSITY_STYLES[3]!
  return INTENSITY_STYLES[4]!
}

export function KillChainHeatmap({ data, onPhaseClick, className }: KillChainHeatmapProps) {
  const maxCount = Math.max(...data.map((d) => d.count), 1)

  return (
    <div className={className} style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 4 }}>
      {data.map((item) => {
        const intensity = getIntensity(item.count, maxCount)
        return (
          <div
            key={item.phase}
            onClick={() => onPhaseClick?.(item.phase)}
            style={{
              borderRadius: 6,
              padding: '12px 8px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 6,
              cursor: 'pointer',
              background: intensity.bg,
              color: intensity.color,
              border: `1px solid ${intensity.border}`,
              transition: 'transform 0.15s',
            }}
          >
            <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.03em', textAlign: 'center', opacity: 0.9, fontFamily: theme.font }}>
              {item.label}
            </span>
            <span style={{ fontSize: 20, fontWeight: 700, fontFamily: theme.font }}>
              {item.count}
            </span>
          </div>
        )
      })}
    </div>
  )
}
