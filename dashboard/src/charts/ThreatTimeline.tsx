'use client'

import { useMemo } from 'react'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts'
import type { IncidentFeedItem } from '../types'

export interface ThreatTimelineProps {
  readonly incidents: readonly IncidentFeedItem[]
  readonly className?: string
}

interface TimelineBucket {
  readonly time: string
  readonly none: number
  readonly low: number
  readonly medium: number
  readonly high: number
  readonly critical: number
}

function bucketIncidents(incidents: readonly IncidentFeedItem[]): readonly TimelineBucket[] {
  const buckets = new Map<string, TimelineBucket>()
  for (const inc of incidents) {
    const hour = inc.timestamp.slice(0, 13) + ':00'
    const existing = buckets.get(hour) ?? { time: hour, none: 0, low: 0, medium: 0, high: 0, critical: 0 }
    buckets.set(hour, {
      ...existing,
      [inc.threatLevel]: (existing[inc.threatLevel as keyof TimelineBucket] as number) + 1,
    })
  }
  return [...buckets.values()].sort((a, b) => a.time.localeCompare(b.time))
}

export function ThreatTimeline({ incidents, className }: ThreatTimelineProps) {
  const data = useMemo(() => bucketIncidents(incidents), [incidents])

  return (
    <div className={className} style={{ width: '100%', height: 260 }}>
      <ResponsiveContainer>
        <AreaChart data={data as TimelineBucket[]}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis
            dataKey="time"
            tick={{ fill: '#64748b', fontSize: 11 }}
            tickFormatter={(v: string) => v.slice(11, 16)}
            stroke="#334155"
          />
          <YAxis tick={{ fill: '#64748b', fontSize: 11 }} stroke="#334155" />
          <Tooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 12, color: '#e2e8f0' }}
          />
          <Area type="monotone" dataKey="critical" stackId="1" fill="#ef4444" stroke="#ef4444" fillOpacity={0.6} />
          <Area type="monotone" dataKey="high" stackId="1" fill="#f97316" stroke="#f97316" fillOpacity={0.6} />
          <Area type="monotone" dataKey="medium" stackId="1" fill="#eab308" stroke="#eab308" fillOpacity={0.5} />
          <Area type="monotone" dataKey="low" stackId="1" fill="#3b82f6" stroke="#3b82f6" fillOpacity={0.4} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
