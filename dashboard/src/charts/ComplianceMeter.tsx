'use client'

import {
  ResponsiveContainer,
  RadialBarChart,
  RadialBar,
  PolarAngleAxis,
} from 'recharts'

export interface ComplianceMeterProps {
  readonly score: number
  readonly label?: string
  readonly className?: string
}

function scoreColor(score: number): string {
  if (score >= 80) return '#22c55e'
  if (score >= 60) return '#eab308'
  if (score >= 40) return '#f97316'
  return '#ef4444'
}

export function ComplianceMeter({ score, label, className }: ComplianceMeterProps) {
  const color = scoreColor(score)
  const data = [{ name: label ?? 'Coverage', value: score, fill: color }]

  return (
    <div className={className} style={{ width: '100%', height: 200, position: 'relative' }}>
      <ResponsiveContainer>
        <RadialBarChart
          cx="50%"
          cy="50%"
          innerRadius="70%"
          outerRadius="100%"
          startAngle={180}
          endAngle={0}
          data={data}
          barSize={12}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
          <RadialBar
            dataKey="value"
            cornerRadius={6}
            background={{ fill: '#1e293b' }}
          />
        </RadialBarChart>
      </ResponsiveContainer>
      <div
        style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -30%)',
          textAlign: 'center',
          fontFamily: '-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, monospace',
        }}
      >
        <div style={{ fontSize: 28, fontWeight: 700, color }}>{score}%</div>
        {label ? <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 2 }}>{label}</div> : null}
      </div>
    </div>
  )
}
