/**
 * Attack knowledge graph.
 * In-memory graph for tracking attack technique relationships,
 * evolution chains, and predicting next attacks.
 */

import { randomUUID } from 'node:crypto'

import type { AttackGraphNode, AttackGraphEdge } from '../types/learning.js'
import type { KillChainPhase } from '../types/detection.js'

/**
 * AttackGraph — in-memory knowledge graph for attack evolution.
 *
 * Tracks relationships between attack techniques including:
 * - evolved_from: one technique evolved into another
 * - combined_with: techniques used together
 * - variant_of: techniques that are variations
 * - precedes: temporal ordering in multi-stage attacks
 */
export class AttackGraph {
  private readonly nodes: Map<string, AttackGraphNode> = new Map()
  private readonly edges: Map<string, AttackGraphEdge> = new Map()
  private readonly adjacency: Map<string, Set<string>> = new Map()

  /**
   * Add a new attack technique node to the graph.
   * @param technique - Technique name/description
   * @param phase - Kill chain phase
   * @returns The created node
   */
  addNode(technique: string, phase: KillChainPhase): AttackGraphNode {
    // Check if a node for this technique already exists
    for (const existing of this.nodes.values()) {
      if (existing.technique === technique) {
        // Update existing node
        const updated: AttackGraphNode = Object.freeze({
          ...existing,
          lastSeen: new Date().toISOString(),
          frequency: existing.frequency + 1,
        })
        this.nodes.set(existing.id, updated)
        return updated
      }
    }

    const node: AttackGraphNode = Object.freeze({
      id: randomUUID(),
      technique,
      killChainPhase: phase,
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      frequency: 1,
      successRate: 0,
      variants: Object.freeze([]),
    })

    this.nodes.set(node.id, node)
    this.adjacency.set(node.id, new Set())
    return node
  }

  /**
   * Add a directed edge between two technique nodes.
   * @param sourceId - Source node ID
   * @param targetId - Target node ID
   * @param relationship - Edge relationship type
   * @returns The created edge
   */
  addEdge(
    sourceId: string,
    targetId: string,
    relationship: AttackGraphEdge['relationship'],
  ): AttackGraphEdge {
    if (!this.nodes.has(sourceId) || !this.nodes.has(targetId)) {
      throw new Error(`Both source (${sourceId}) and target (${targetId}) nodes must exist`)
    }

    const edgeKey = `${sourceId}->${targetId}`
    const existing = this.edges.get(edgeKey)

    if (existing !== undefined) {
      // Update weight
      const updated: AttackGraphEdge = Object.freeze({
        ...existing,
        weight: existing.weight + 1,
      })
      this.edges.set(edgeKey, updated)
      return updated
    }

    const edge: AttackGraphEdge = Object.freeze({
      sourceId,
      targetId,
      relationship,
      weight: 1,
      firstSeen: new Date().toISOString(),
    })

    this.edges.set(edgeKey, edge)

    // Update adjacency
    const neighbors = this.adjacency.get(sourceId)
    if (neighbors !== undefined) {
      neighbors.add(targetId)
    }

    return edge
  }

  /**
   * Predict next likely attacks given a current technique.
   * Uses neighbor traversal weighted by edge weight and frequency.
   * @param currentTechnique - Current technique name
   * @returns Array of predicted technique names
   */
  predictNextAttacks(currentTechnique: string): readonly string[] {
    // Find the node for this technique
    let currentNodeId: string | undefined
    for (const [id, node] of this.nodes) {
      if (node.technique === currentTechnique) {
        currentNodeId = id
        break
      }
    }

    if (currentNodeId === undefined) return Object.freeze([])

    const neighbors = this.adjacency.get(currentNodeId)
    if (neighbors === undefined || neighbors.size === 0) return Object.freeze([])

    // Collect neighbors with their edge weights
    const predictions: { technique: string; score: number }[] = []

    for (const neighborId of neighbors) {
      const neighborNode = this.nodes.get(neighborId)
      const edgeKey = `${currentNodeId}->${neighborId}`
      const edge = this.edges.get(edgeKey)

      if (neighborNode !== undefined && edge !== undefined) {
        predictions.push({
          technique: neighborNode.technique,
          score: edge.weight * neighborNode.frequency,
        })
      }
    }

    // Sort by score descending
    predictions.sort((a, b) => b.score - a.score)

    return Object.freeze(predictions.map((p) => p.technique))
  }

  /**
   * Get the evolution chain for a technique (trace back through evolved_from edges).
   * @param techniqueId - Starting node ID
   * @returns Chain of nodes from earliest ancestor to current
   */
  getEvolutionChain(techniqueId: string): readonly AttackGraphNode[] {
    const chain: AttackGraphNode[] = []
    const visited = new Set<string>()
    let currentId: string | undefined = techniqueId

    while (currentId !== undefined && !visited.has(currentId)) {
      visited.add(currentId)
      const node = this.nodes.get(currentId)
      if (node === undefined) break

      chain.unshift(node) // prepend to build oldest-first chain

      // Find incoming evolved_from edge
      let parentId: string | undefined
      for (const [, edge] of this.edges) {
        if (edge.targetId === currentId && edge.relationship === 'evolved_from') {
          parentId = edge.sourceId
          break
        }
      }
      currentId = parentId
    }

    return Object.freeze(chain)
  }

  /**
   * Get a node by ID.
   */
  getNode(nodeId: string): AttackGraphNode | undefined {
    return this.nodes.get(nodeId)
  }

  /**
   * Get all nodes in the graph.
   */
  getAllNodes(): readonly AttackGraphNode[] {
    return Object.freeze([...this.nodes.values()])
  }

  /**
   * Get all edges in the graph.
   */
  getAllEdges(): readonly AttackGraphEdge[] {
    return Object.freeze([...this.edges.values()])
  }

  /**
   * Get graph statistics.
   */
  getStats(): { nodeCount: number; edgeCount: number } {
    return { nodeCount: this.nodes.size, edgeCount: this.edges.size }
  }
}
