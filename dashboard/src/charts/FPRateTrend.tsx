'use client'

import { useMemo } from 'react'
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
} from 'recharts'
import type { IncidentFeedItem } from '../types'

export interface FPRateTrendProps {
  readonly incidents: readonly IncidentFeedItem[]
  readonly className?: string
}

interface FPBucket {
  readonly time: string
  readonly fpRate: number
}

export function FPRateTrend({ incidents, className }: FPRateTrendProps) {
  const data = useMemo<readonly FPBucket[]>(() => {
    const buckets = new Map<string, { total: number; fp: number }>()
    for (const inc of incidents) {
      const day = inc.timestamp.slice(0, 10)
      const existing = buckets.get(day) ?? { total: 0, fp: 0 }
      buckets.set(day, {
        total: existing.total + 1,
        fp: existing.fp + (inc.falsePositive ? 1 : 0),
      })
    }
    return [...buckets.entries()]
      .map(([time, { total, fp }]) => ({
        time,
        fpRate: total > 0 ? (fp / total) * 100 : 0,
      }))
      .sort((a, b) => a.time.localeCompare(b.time))
  }, [incidents])

  return (
    <div className={className} style={{ width: '100%', height: 220 }}>
      <ResponsiveContainer>
        <LineChart data={data as FPBucket[]}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis
            dataKey="time"
            tick={{ fill: '#64748b', fontSize: 11 }}
            tickFormatter={(v: string) => v.slice(5)}
            stroke="#334155"
          />
          <YAxis
            tick={{ fill: '#64748b', fontSize: 11 }}
            stroke="#334155"
            tickFormatter={(v: number) => `${v}%`}
          />
          <Tooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 12, color: '#e2e8f0' }}
            formatter={(val: number) => [`${val.toFixed(1)}%`, 'FP Rate']}
          />
          <ReferenceLine y={5} stroke="#ef4444" strokeDasharray="4 4" label={{ value: '5% target', fill: '#ef4444', fontSize: 10, position: 'insideTopRight' }} />
          <Line type="monotone" dataKey="fpRate" stroke="#eab308" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
