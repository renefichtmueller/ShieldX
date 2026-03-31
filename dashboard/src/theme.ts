/** SOC-style dark theme constants */
export const theme = {
  colors: {
    bg: '#0f172a',
    card: '#1e293b',
    cardBorder: '#334155',
    cardBorderHover: '#475569',
    text: '#e2e8f0',
    textBright: '#f1f5f9',
    textMuted: '#94a3b8',
    textDim: '#64748b',

    threatNone: '#22c55e',
    threatLow: '#3b82f6',
    threatMedium: '#eab308',
    threatHigh: '#f97316',
    threatCritical: '#ef4444',

    accent: '#8b5cf6',
    accentHover: '#7c3aed',
  },
  font: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace",
} as const

export type ThreatColorKey = 'none' | 'low' | 'medium' | 'high' | 'critical'

export const THREAT_COLORS: Record<ThreatColorKey, string> = {
  none: theme.colors.threatNone,
  low: theme.colors.threatLow,
  medium: theme.colors.threatMedium,
  high: theme.colors.threatHigh,
  critical: theme.colors.threatCritical,
}

/** Returns a CSSProperties-compatible inline style object for cards */
export function cardStyle(extra?: React.CSSProperties): React.CSSProperties {
  return {
    background: theme.colors.card,
    border: `1px solid ${theme.colors.cardBorder}`,
    borderRadius: 8,
    padding: 20,
    color: theme.colors.text,
    fontFamily: theme.font,
    ...extra,
  }
}
