'use client'

import { useMemo } from 'react'
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts'
import type { IncidentFeedItem } from '../types'

export interface ScannerBreakdownProps {
  readonly incidents: readonly IncidentFeedItem[]
  readonly className?: string
}

interface ScannerCount {
  readonly scanner: string
  readonly count: number
}

export function ScannerBreakdown({ incidents, className }: ScannerBreakdownProps) {
  const data = useMemo<readonly ScannerCount[]>(() => {
    const counts = new Map<string, number>()
    for (const inc of incidents) {
      if (inc.scanResults) {
        for (const sr of inc.scanResults) {
          if (sr.detected) {
            counts.set(sr.scannerType, (counts.get(sr.scannerType) ?? 0) + 1)
          }
        }
      }
    }
    return [...counts.entries()]
      .map(([scanner, count]) => ({ scanner, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12)
  }, [incidents])

  return (
    <div className={className} style={{ width: '100%', height: 260 }}>
      <ResponsiveContainer>
        <BarChart data={data as ScannerCount[]} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
          <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} stroke="#334155" />
          <YAxis
            type="category"
            dataKey="scanner"
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            width={120}
            stroke="#334155"
          />
          <Tooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 12, color: '#e2e8f0' }}
          />
          <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
