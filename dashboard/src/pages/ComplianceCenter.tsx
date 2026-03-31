'use client'

import React, { useState, useCallback } from 'react'
import * as s from './styles'
import { theme } from '../theme'
import { useCompliance, useShieldX } from '../hooks'
import { Card } from '../components/Card'
import { LoadingSpinner } from '../components/LoadingSpinner'
import { ComplianceMeter } from '../charts/ComplianceMeter'
import type { ComplianceReport } from '../types'

type CTab = 'mitre' | 'owasp' | 'eu'

export function ComplianceCenter() {
  const { compliance, loading } = useCompliance()
  const { api } = useShieldX()
  const [tab, setTab] = useState<CTab>('mitre')
  const [reports, setReports] = useState<Partial<Record<CTab, ComplianceReport>>>({})

  const getReport = useCallback((): ComplianceReport | null => {
    if (!api) return compliance
    if (reports[tab]) return reports[tab]!
    const fw = tab === 'mitre' ? 'mitre_atlas' : tab === 'owasp' ? 'owasp_llm' : 'eu_ai_act' as const
    const r = api.generateComplianceReport(fw)
    if (r) setReports((prev) => ({ ...prev, [tab]: r }))
    return r
  }, [tab, api, compliance, reports])

  if (loading) return <LoadingSpinner />

  const report = getReport()

  const tabBtn = (key: CTab, label: string): React.ReactNode => (
    <button key={key} onClick={() => setTab(key)} style={{
      padding: '10px 20px', background: 'transparent', border: 'none',
      borderBottom: tab === key ? `2px solid ${theme.colors.accent}` : '2px solid transparent',
      color: tab === key ? theme.colors.accent : theme.colors.textDim,
      cursor: 'pointer', fontSize: 13, fontWeight: 600, fontFamily: theme.font, textTransform: 'uppercase',
    }}>{label}</button>
  )

  return (
    <div style={s.page}>
      <div style={s.header}><h2 style={s.pageTitle}>Compliance Center</h2></div>
      <div style={{ display: 'flex', gap: 0, borderBottom: `1px solid ${theme.colors.cardBorder}`, marginBottom: 20 }}>
        {tabBtn('mitre', 'MITRE ATLAS')}{tabBtn('owasp', 'OWASP LLM')}{tabBtn('eu', 'EU AI Act')}
      </div>
      {report ? (
        <div style={s.grid2}>
          <Card title="Coverage Score">
            <ComplianceMeter score={Math.round(report.coverageScore * 100)} label={`${report.coveredTechniques} / ${report.totalTechniques} techniques`} />
          </Card>
          <Card title="Gaps & Recommendations">
            {report.gaps.length > 0 ? (
              <>
                <h4 style={{ fontSize: 12, color: theme.colors.threatHigh, margin: '0 0 8px', textTransform: 'uppercase' }}>Gaps ({report.gaps.length})</h4>
                <ul style={{ listStyle: 'none', padding: 0, margin: '8px 0 0' }}>
                  {report.gaps.slice(0, 8).map((gap, idx) => (
                    <li key={idx} style={{ padding: '6px 0', fontSize: 13, color: theme.colors.threatHigh, borderBottom: `1px solid rgba(51,65,85,0.3)` }}>{'\u26A0'} {gap}</li>
                  ))}
                </ul>
              </>
            ) : <p style={{ color: theme.colors.threatNone, fontSize: 13 }}>No compliance gaps detected</p>}
            {report.recommendations.length > 0 ? (
              <>
                <h4 style={{ fontSize: 12, color: theme.colors.accent, margin: '16px 0 8px', textTransform: 'uppercase' }}>Recommendations</h4>
                <ul style={{ margin: 0, paddingLeft: 16 }}>
                  {report.recommendations.slice(0, 5).map((rec, idx) => (
                    <li key={idx} style={{ fontSize: 13, color: '#cbd5e1', padding: '4px 0' }}>{rec}</li>
                  ))}
                </ul>
              </>
            ) : null}
          </Card>
        </div>
      ) : <Card><p style={{ color: theme.colors.textDim, fontSize: 13 }}>No compliance report available</p></Card>}
    </div>
  )
}
