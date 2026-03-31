'use client'

interface StatCardProps {
  readonly value: string | number
  readonly label: string
  readonly subtitle?: string
  readonly color?: string
}

export function StatCard({ value, label, subtitle, color }: StatCardProps) {
  return (
    <div className="stat-card">
      <div className="stat-value" style={color ? { color } : undefined}>
        {value}
      </div>
      <div className="stat-label">{label}</div>
      {subtitle && <div className="stat-sub">{subtitle}</div>}
    </div>
  )
}
