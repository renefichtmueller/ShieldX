import { theme } from '../theme'

/** Shared page layout styles */
export const page: React.CSSProperties = {
  fontFamily: theme.font,
  color: theme.colors.text,
}

export const header: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  marginBottom: 20,
  flexWrap: 'wrap',
  gap: 12,
}

export const pageTitle: React.CSSProperties = {
  fontSize: 18,
  fontWeight: 700,
  color: theme.colors.textBright,
  margin: 0,
}

export const subtitle: React.CSSProperties = {
  fontSize: 13,
  color: theme.colors.textDim,
  margin: '4px 0 0',
}

export const grid2: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(2, 1fr)',
  gap: 16,
}

export const grid4: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(4, 1fr)',
  gap: 16,
}

export const section: React.CSSProperties = {
  marginTop: 24,
}

export const sectionTitle: React.CSSProperties = {
  fontSize: 14,
  fontWeight: 600,
  color: theme.colors.textMuted,
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
  margin: '0 0 12px',
}

export const row: React.CSSProperties = {
  display: 'flex',
  gap: 16,
  flexWrap: 'wrap',
}

export const flex1: React.CSSProperties = {
  flex: 1,
  minWidth: 300,
}

export const detailPanel: React.CSSProperties = {
  background: theme.colors.card,
  border: `1px solid ${theme.colors.cardBorder}`,
  borderRadius: 8,
  padding: 20,
  marginTop: 16,
}

export const detailTitle: React.CSSProperties = {
  fontSize: 15,
  fontWeight: 600,
  color: theme.colors.textBright,
  margin: '0 0 12px',
}

export const detailRow: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  padding: '6px 0',
  fontSize: 13,
  borderBottom: 'rgba(51, 65, 85, 0.4)',
}

export const detailLabel: React.CSSProperties = {
  color: theme.colors.textMuted,
}

export const detailValue: React.CSSProperties = {
  color: theme.colors.text,
  fontWeight: 500,
}

export const actions: React.CSSProperties = {
  display: 'flex',
  gap: 8,
}

export const btn: React.CSSProperties = {
  padding: '6px 16px',
  borderRadius: 4,
  border: `1px solid ${theme.colors.cardBorder}`,
  background: 'transparent',
  color: theme.colors.text,
  fontSize: 12,
  fontWeight: 600,
  cursor: 'pointer',
  fontFamily: theme.font,
}

export const btnPrimary: React.CSSProperties = {
  ...btn,
  background: theme.colors.accent,
  borderColor: theme.colors.accent,
  color: '#fff',
}

export const btnDanger: React.CSSProperties = {
  ...btn,
  background: 'rgba(239, 68, 68, 0.15)',
  borderColor: theme.colors.threatCritical,
  color: theme.colors.threatCritical,
}

export const configRow: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  padding: '8px 0',
  borderBottom: `1px solid rgba(51, 65, 85, 0.3)`,
}

export const configLabel: React.CSSProperties = {
  fontSize: 13,
  color: '#cbd5e1',
}
