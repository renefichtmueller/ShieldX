'use client'

import { useMemo } from 'react'
import { theme } from '../theme'
import type { AttackGraphNode, AttackGraphEdge } from '../types'
import type { KillChainPhase } from '../types'

export interface AttackGraphVizProps {
  readonly nodes: readonly AttackGraphNode[]
  readonly edges: readonly AttackGraphEdge[]
  readonly onNodeClick?: (node: AttackGraphNode) => void
  readonly className?: string
}

const PHASE_COLORS: Record<KillChainPhase, string> = {
  none: '#64748b',
  initial_access: theme.colors.threatLow,
  privilege_escalation: theme.colors.threatHigh,
  reconnaissance: theme.colors.threatMedium,
  persistence: theme.colors.accent,
  command_and_control: theme.colors.threatCritical,
  lateral_movement: theme.colors.threatHigh,
  actions_on_objective: theme.colors.threatCritical,
}

const PHASE_X: Record<KillChainPhase, number> = {
  none: 50,
  initial_access: 100,
  reconnaissance: 230,
  privilege_escalation: 360,
  persistence: 490,
  command_and_control: 620,
  lateral_movement: 750,
  actions_on_objective: 880,
}

interface Positioned {
  readonly node: AttackGraphNode
  readonly x: number
  readonly y: number
  readonly r: number
}

export function AttackGraphViz({ nodes, edges, onNodeClick, className }: AttackGraphVizProps) {
  const positioned = useMemo<readonly Positioned[]>(() => {
    const groups = new Map<KillChainPhase, AttackGraphNode[]>()
    for (const node of nodes) {
      const g = groups.get(node.killChainPhase) ?? []
      g.push(node)
      groups.set(node.killChainPhase, g)
    }
    const result: Positioned[] = []
    for (const [phase, group] of groups) {
      const baseX = PHASE_X[phase] ?? 500
      const spacing = 60
      const startY = 200 - ((group.length - 1) * spacing) / 2
      for (let i = 0; i < group.length; i++) {
        const n = group[i]!
        result.push({
          node: n,
          x: baseX + ((i % 3) - 1) * 15,
          y: startY + i * spacing,
          r: Math.max(8, Math.min(20, n.frequency / 2)),
        })
      }
    }
    return result
  }, [nodes])

  const nodeMap = useMemo(() => {
    const m = new Map<string, Positioned>()
    for (const pn of positioned) m.set(pn.node.id, pn)
    return m
  }, [positioned])

  if (nodes.length === 0) {
    return (
      <div className={className} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 400, background: theme.colors.bg, borderRadius: 8, color: theme.colors.textDim, fontFamily: theme.font }}>
        No attack graph data
      </div>
    )
  }

  return (
    <div className={className} style={{ width: '100%', minHeight: 400, position: 'relative', background: theme.colors.bg, borderRadius: 8, overflow: 'hidden' }}>
      <svg style={{ width: '100%', height: '100%' }} viewBox="0 0 960 400" preserveAspectRatio="xMidYMid meet">
        {edges.map((edge, idx) => {
          const source = nodeMap.get(edge.sourceId)
          const target = nodeMap.get(edge.targetId)
          if (!source || !target) return null
          return (
            <line
              key={idx}
              x1={source.x} y1={source.y}
              x2={target.x} y2={target.y}
              stroke="#475569"
              strokeWidth={Math.max(1, edge.weight * 2)}
              strokeOpacity={0.4}
            />
          )
        })}
        {positioned.map((pn) => (
          <g key={pn.node.id} onClick={() => onNodeClick?.(pn.node)} style={{ cursor: 'pointer' }}>
            <circle cx={pn.x} cy={pn.y} r={pn.r} fill={PHASE_COLORS[pn.node.killChainPhase]} opacity={0.8} />
            <text
              x={pn.x} y={pn.y + pn.r + 14}
              fill={theme.colors.text}
              fontSize={10}
              fontFamily={theme.font}
              textAnchor="middle"
            >
              {pn.node.technique.length > 16 ? pn.node.technique.slice(0, 14) + '\u2026' : pn.node.technique}
            </text>
          </g>
        ))}
      </svg>
      <div style={{ position: 'absolute', bottom: 12, left: 12, display: 'flex', gap: 12, fontSize: 10, color: theme.colors.textMuted, fontFamily: theme.font }}>
        {Object.entries(PHASE_COLORS)
          .filter(([k]) => k !== 'none')
          .map(([phase, color]) => (
            <span key={phase} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }} />
              {phase.replace(/_/g, ' ')}
            </span>
          ))}
      </div>
    </div>
  )
}
