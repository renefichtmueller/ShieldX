'use client'

import React from 'react'
import * as s from './styles'
import { theme } from '../theme'
import { useConfig } from '../hooks'
import { Card } from '../components/Card'
import { Toggle } from '../components/Toggle'
import { Slider } from '../components/Slider'
import { LoadingSpinner } from '../components/LoadingSpinner'

export function ConfigPanel() {
  const { config, loading } = useConfig()

  if (loading || !config) return <LoadingSpinner />

  const Row = ({ label, children }: { label: string; children: React.ReactNode }) => (
    <div style={s.configRow}><span style={s.configLabel}>{label}</span>{children}</div>
  )

  return (
    <div style={s.page}>
      <div style={s.header}>
        <div>
          <h2 style={s.pageTitle}>Configuration</h2>
          <p style={s.subtitle}>Read-only view of current ShieldX configuration</p>
        </div>
      </div>

      <div style={s.grid2}>
        <Card title="Scanner Modules">
          <Row label="Rule Engine"><Toggle checked={config.scanners.rules} disabled /></Row>
          <Row label="Sentinel Classifier"><Toggle checked={config.scanners.sentinel} disabled /></Row>
          <Row label="Constitutional AI"><Toggle checked={config.scanners.constitutional} disabled /></Row>
          <Row label="Embedding Scanner"><Toggle checked={config.scanners.embedding} disabled /></Row>
          <Row label="Embedding Anomaly"><Toggle checked={config.scanners.embeddingAnomaly} disabled /></Row>
          <Row label="Entropy Scanner"><Toggle checked={config.scanners.entropy} disabled /></Row>
          <Row label="YARA Rules"><Toggle checked={config.scanners.yara} disabled /></Row>
          <Row label="Attention Scanner"><Toggle checked={config.scanners.attention} disabled /></Row>
          <Row label="Canary Tokens"><Toggle checked={config.scanners.canary} disabled /></Row>
          <Row label="Indirect Injection"><Toggle checked={config.scanners.indirect} disabled /></Row>
          <Row label="Self-Consciousness"><Toggle checked={config.scanners.selfConsciousness} disabled /></Row>
          <Row label="Cross-Model"><Toggle checked={config.scanners.crossModel} disabled /></Row>
          <Row label="Behavioral"><Toggle checked={config.scanners.behavioral} disabled /></Row>
          <Row label="Unicode Normalizer"><Toggle checked={config.scanners.unicode} disabled /></Row>
          <Row label="Tokenizer"><Toggle checked={config.scanners.tokenizer} disabled /></Row>
          <Row label="Compressed Payload"><Toggle checked={config.scanners.compressedPayload} disabled /></Row>
        </Card>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Card title="Thresholds">
            <Slider label="Low" value={config.thresholds.low} disabled />
            <div style={{ height: 8 }} />
            <Slider label="Medium" value={config.thresholds.medium} disabled />
            <div style={{ height: 8 }} />
            <Slider label="High" value={config.thresholds.high} disabled />
            <div style={{ height: 8 }} />
            <Slider label="Critical" value={config.thresholds.critical} disabled />
          </Card>
          <Card title="Healing">
            <Row label="Enabled"><Toggle checked={config.healing.enabled} disabled /></Row>
            <Row label="Auto Sanitize"><Toggle checked={config.healing.autoSanitize} disabled /></Row>
            <Row label="Session Reset"><Toggle checked={config.healing.sessionReset} disabled /></Row>
          </Card>
          <Card title="Learning">
            <Row label="Enabled"><Toggle checked={config.learning.enabled} disabled /></Row>
            <Row label="Backend"><span style={{ fontSize: 13, color: theme.colors.text }}>{config.learning.storageBackend}</span></Row>
            <Row label="Feedback Loop"><Toggle checked={config.learning.feedbackLoop} disabled /></Row>
            <Row label="Community Sync"><Toggle checked={config.learning.communitySync} disabled /></Row>
            <Row label="Drift Detection"><Toggle checked={config.learning.driftDetection} disabled /></Row>
            <Row label="Active Learning"><Toggle checked={config.learning.activelearning} disabled /></Row>
            <Row label="Attack Graph"><Toggle checked={config.learning.attackGraph} disabled /></Row>
          </Card>
          <Card title="Compliance">
            <Row label="MITRE ATLAS"><Toggle checked={config.compliance.mitreAtlas} disabled /></Row>
            <Row label="OWASP LLM Top 10"><Toggle checked={config.compliance.owaspLlm} disabled /></Row>
            <Row label="EU AI Act"><Toggle checked={config.compliance.euAiAct} disabled /></Row>
          </Card>
        </div>
      </div>
    </div>
  )
}
