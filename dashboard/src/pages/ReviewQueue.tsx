'use client'

import { useCallback } from 'react'
import * as s from './styles'
import { theme } from '../theme'
import { useReviewQueue } from '../hooks'
import { Card } from '../components/Card'
import { ThreatBadge } from '../components/ThreatBadge'
import { PhaseBadge } from '../components/PhaseBadge'
import { LoadingSpinner } from '../components/LoadingSpinner'
import { EmptyState } from '../components/EmptyState'
import type { ScanResult } from '../types'

export function ReviewQueue() {
  const { reviewQueue, loading, api } = useReviewQueue()

  const handleConfirm = useCallback((scanId: string) => { api?.submitReview(scanId, true) }, [api])
  const handleFP = useCallback((scanId: string) => { api?.submitReview(scanId, false) }, [api])

  if (loading) return <LoadingSpinner />

  return (
    <div style={s.page}>
      <div style={s.header}>
        <div>
          <h2 style={s.pageTitle}>Review Queue</h2>
          <p style={s.subtitle}>{reviewQueue.length} items pending human review</p>
        </div>
      </div>
      {reviewQueue.length === 0 ? (
        <EmptyState message="No items pending review" icon={'\u2705'} />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {reviewQueue.map((item: ScanResult) => (
            <Card key={item.scannerId}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', gap: 8, marginBottom: 8, alignItems: 'center' }}>
                    <ThreatBadge level={item.threatLevel} />
                    <PhaseBadge phase={item.killChainPhase} />
                    <span style={{ fontSize: 11, color: theme.colors.textDim }}>Scanner: {item.scannerType}</span>
                  </div>
                  <div style={{ fontSize: 12, color: theme.colors.textMuted, marginBottom: 6 }}>
                    Confidence: {(item.confidence * 100).toFixed(1)}% | Latency: {item.latencyMs}ms
                  </div>
                  {item.matchedPatterns.length > 0 ? (
                    <div style={{ fontSize: 11, color: theme.colors.textDim }}>Matched: {item.matchedPatterns.join(', ')}</div>
                  ) : null}
                </div>
                <div style={s.actions}>
                  <button style={s.btnPrimary} onClick={() => handleConfirm(item.scannerId)}>Confirm Attack</button>
                  <button style={s.btnDanger} onClick={() => handleFP(item.scannerId)}>False Positive</button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
