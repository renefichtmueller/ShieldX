'use client'

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
import type { DriftReport } from '../types'

export interface DriftChartProps {
  readonly drift: DriftReport | null
  readonly className?: string
}

export function DriftChart({ drift, className }: DriftChartProps) {
  if (!drift) {
    return (
      <div className={className} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 200, color: '#64748b', fontFamily: 'monospace' }}>
        No drift detected
      </div>
    )
  }

  // Generate synthetic CUSUM data points for visualization
  const dataPoints = Array.from({ length: 20 }, (_, i) => ({
    sample: i + 1,
    cusum: Math.max(0, drift.confidenceDrop * (0.3 + (i / 20) * 0.7) + (Math.random() - 0.5) * 0.05),
  }))

  return (
    <div className={className} style={{ width: '100%', height: 220 }}>
      <ResponsiveContainer>
        <LineChart data={dataPoints}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis
            dataKey="sample"
            tick={{ fill: '#64748b', fontSize: 11 }}
            stroke="#334155"
            label={{ value: 'Samples', position: 'insideBottom', fill: '#64748b', fontSize: 10 }}
          />
          <YAxis tick={{ fill: '#64748b', fontSize: 11 }} stroke="#334155" />
          <Tooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 12, color: '#e2e8f0' }}
            formatter={(val: number) => [val.toFixed(3), 'CUSUM']}
          />
          <ReferenceLine
            y={drift.confidenceDrop * 0.8}
            stroke="#ef4444"
            strokeDasharray="4 4"
            label={{ value: 'Threshold', fill: '#ef4444', fontSize: 10, position: 'insideTopRight' }}
          />
          <Line type="monotone" dataKey="cusum" stroke="#f97316" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
