'use client'

import { useMemo } from 'react'
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
} from 'recharts'
import type { LearningStats } from '../types'

export interface PatternDistributionProps {
  readonly stats: LearningStats | null
  readonly className?: string
}

const COLORS = {
  builtin: '#3b82f6',
  learned: '#22c55e',
  community: '#8b5cf6',
  red_team: '#ef4444',
} as const

interface PieSlice {
  readonly name: string
  readonly value: number
  readonly color: string
}

export function PatternDistribution({ stats, className }: PatternDistributionProps) {
  const data = useMemo<readonly PieSlice[]>(() => {
    if (!stats) return []
    return [
      { name: 'Built-in', value: stats.builtinPatterns, color: COLORS.builtin },
      { name: 'Learned', value: stats.learnedPatterns, color: COLORS.learned },
      { name: 'Community', value: stats.communityPatterns, color: COLORS.community },
      { name: 'Red Team', value: stats.redTeamPatterns, color: COLORS.red_team },
    ].filter((d) => d.value > 0)
  }, [stats])

  if (data.length === 0) return null

  return (
    <div className={className} style={{ width: '100%', height: 260 }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={data as PieSlice[]}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={50}
            outerRadius={90}
            paddingAngle={2}
          >
            {data.map((entry) => (
              <Cell key={entry.name} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 12, color: '#e2e8f0' }}
          />
          <Legend
            wrapperStyle={{ fontSize: 11, color: '#94a3b8' }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
