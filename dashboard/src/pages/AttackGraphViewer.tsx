'use client'

import { useState } from 'react'
import * as s from './styles'
import { theme } from '../theme'
import { useAttackGraph } from '../hooks'
import { Card } from '../components/Card'
import { PhaseBadge } from '../components/PhaseBadge'
import { LoadingSpinner } from '../components/LoadingSpinner'
import { AttackGraphViz } from '../charts/AttackGraphViz'
import type { AttackGraphNode } from '../types'

export function AttackGraphViewer() {
  const { nodes, edges, loading } = useAttackGraph()
  const [selectedNode, setSelectedNode] = useState<AttackGraphNode | null>(null)

  if (loading) return <LoadingSpinner />

  return (
    <div style={s.page}>
      <div style={s.header}>
        <div>
          <h2 style={s.pageTitle}>Attack Knowledge Graph</h2>
          <p style={s.subtitle}>{nodes.length} techniques, {edges.length} relationships</p>
        </div>
      </div>

      <AttackGraphViz nodes={nodes} edges={edges} onNodeClick={setSelectedNode} />

      {selectedNode ? (
        <div style={s.detailPanel}>
          <h3 style={s.detailTitle}>{selectedNode.technique}</h3>
          <div style={s.detailRow}><span style={s.detailLabel}>Phase</span><PhaseBadge phase={selectedNode.killChainPhase} /></div>
          <div style={s.detailRow}><span style={s.detailLabel}>Frequency</span><span style={s.detailValue}>{selectedNode.frequency}</span></div>
          <div style={s.detailRow}><span style={s.detailLabel}>Success Rate</span><span style={s.detailValue}>{(selectedNode.successRate * 100).toFixed(1)}%</span></div>
          <div style={s.detailRow}><span style={s.detailLabel}>First Seen</span><span style={s.detailValue}>{new Date(selectedNode.firstSeen).toLocaleDateString()}</span></div>
          <div style={s.detailRow}><span style={s.detailLabel}>Last Seen</span><span style={s.detailValue}>{new Date(selectedNode.lastSeen).toLocaleDateString()}</span></div>
          <div style={s.detailRow}><span style={s.detailLabel}>Variants</span><span style={s.detailValue}>{selectedNode.variants.length}</span></div>
          {selectedNode.variants.length > 0 ? <div style={{ marginTop: 8, fontSize: 11, color: theme.colors.textDim }}>{selectedNode.variants.join(', ')}</div> : null}
        </div>
      ) : (
        <Card title="Node Details"><p style={{ color: theme.colors.textDim, fontSize: 13 }}>Click a node in the graph to view details</p></Card>
      )}
    </div>
  )
}
