/**
 * ShieldX n8n Custom Node.
 *
 * Provides prompt injection scanning as an n8n workflow node.
 * Supports both input scanning (pre-LLM) and output scanning (post-LLM).
 *
 * Install: Copy to `~/.n8n/custom/` or register via n8n community nodes.
 *
 * @example
 * Workflow: Webhook -> ShieldX (Scan Input) -> LLM -> ShieldX (Scan Output) -> Response
 */

import { ShieldX } from '../../core/ShieldX.js'
import type { ShieldXResult } from '../../types/detection.js'

// ---------------------------------------------------------------------------
// n8n Node Type Interfaces (minimal, avoids n8n SDK dependency)
// ---------------------------------------------------------------------------

/** n8n node property definition */
interface NodePropertyDefinition {
  readonly displayName: string
  readonly name: string
  readonly type: string
  readonly default?: unknown
  readonly options?: readonly { readonly name: string; readonly value: string }[]
  readonly description?: string
  readonly required?: boolean
}

/** n8n execution data item */
interface WorkflowDataItem {
  readonly json: Readonly<Record<string, unknown>>
}

/** n8n execution context (minimal interface) */
interface ExecutionContext {
  getInputData(): readonly WorkflowDataItem[]
  getNodeParameter(name: string, itemIndex: number): unknown
}

// ---------------------------------------------------------------------------
// Node Description
// ---------------------------------------------------------------------------

/** n8n node description */
const NODE_DESCRIPTION = {
  displayName: 'ShieldX',
  name: 'shieldX',
  group: ['transform'] as readonly string[],
  version: 1,
  description: 'Scan LLM input/output for prompt injection attacks',
  defaults: { name: 'ShieldX' },
  inputs: ['main'] as readonly string[],
  outputs: ['main'] as readonly string[],
  properties: [
    {
      displayName: 'Operation',
      name: 'operation',
      type: 'options',
      default: 'scanInput',
      options: [
        { name: 'Scan Input', value: 'scanInput' },
        { name: 'Scan Output', value: 'scanOutput' },
      ],
      description: 'Whether to scan LLM input (pre-send) or output (post-receive)',
    },
    {
      displayName: 'Input Field',
      name: 'inputField',
      type: 'string',
      default: 'message',
      description: 'JSON field name containing the text to scan',
      required: true,
    },
    {
      displayName: 'Threat Level Threshold',
      name: 'threshold',
      type: 'options',
      default: 'medium',
      options: [
        { name: 'Low', value: 'low' },
        { name: 'Medium', value: 'medium' },
        { name: 'High', value: 'high' },
        { name: 'Critical', value: 'critical' },
      ],
      description: 'Minimum threat level to flag as detected',
    },
    {
      displayName: 'Block on Detection',
      name: 'blockOnDetection',
      type: 'boolean',
      default: true,
      description: 'Whether to block (stop workflow) when a threat is detected above threshold',
    },
  ] satisfies readonly NodePropertyDefinition[],
} as const

// ---------------------------------------------------------------------------
// Threat severity for comparison
// ---------------------------------------------------------------------------

const THREAT_SEVERITY: Readonly<Record<string, number>> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
} as const

// ---------------------------------------------------------------------------
// ShieldX n8n Node
// ---------------------------------------------------------------------------

/**
 * ShieldX n8n custom node.
 *
 * Scans text fields in workflow items for prompt injection attacks.
 * Adds ShieldX scan results to each item's JSON output.
 */
export class ShieldXNode {
  /** Node description for n8n registration */
  readonly description = NODE_DESCRIPTION

  /** Lazily initialized ShieldX instance */
  private shield: ShieldX | null = null

  /**
   * Get or create the ShieldX instance.
   * Singleton per node instance to avoid repeated initialization.
   */
  private getShield(): ShieldX {
    if (this.shield === null) {
      this.shield = new ShieldX({
        logging: { level: 'warn', structured: true, incidentLog: true },
      })
    }
    return this.shield
  }

  /**
   * Execute the node for all input items.
   *
   * @param context - n8n execution context
   * @returns Array of output items with ShieldX scan results attached
   */
  async execute(context: ExecutionContext): Promise<readonly WorkflowDataItem[][]> {
    const items = context.getInputData()
    const shield = this.getShield()
    const outputItems: WorkflowDataItem[] = []

    for (let i = 0; i < items.length; i++) {
      const operation = context.getNodeParameter('operation', i) as string
      const inputField = context.getNodeParameter('inputField', i) as string
      const threshold = context.getNodeParameter('threshold', i) as string
      const blockOnDetection = context.getNodeParameter('blockOnDetection', i) as boolean

      const item = items[i]
      if (item === undefined) continue
      const text = this.extractText(item.json, inputField)

      if (text === null) {
        // No text found — pass through with warning
        outputItems.push({
          json: {
            ...item.json,
            shieldx: {
              error: `Field '${inputField}' not found or not a string`,
              detected: false,
            },
          },
        })
        continue
      }

      // Run scan
      const scanResult: ShieldXResult = operation === 'scanOutput'
        ? await shield.scanOutput(text)
        : await shield.scanInput(text)

      // Check threshold
      const detectedAboveThreshold =
        scanResult.detected &&
        (THREAT_SEVERITY[scanResult.threatLevel] ?? 0) >= (THREAT_SEVERITY[threshold] ?? 2)

      if (blockOnDetection && detectedAboveThreshold) {
        // Block: output item with block flag, workflow can branch on this
        outputItems.push({
          json: {
            ...item.json,
            shieldx: {
              blocked: true,
              scanId: scanResult.id,
              detected: scanResult.detected,
              threatLevel: scanResult.threatLevel,
              killChainPhase: scanResult.killChainPhase,
              action: scanResult.action,
              latencyMs: scanResult.latencyMs,
            },
          },
        })
      } else {
        // Allow: pass through with scan metadata
        outputItems.push({
          json: {
            ...item.json,
            ...(scanResult.sanitizedInput !== undefined
              ? { [inputField]: scanResult.sanitizedInput }
              : {}),
            shieldx: {
              blocked: false,
              scanId: scanResult.id,
              detected: scanResult.detected,
              threatLevel: scanResult.threatLevel,
              killChainPhase: scanResult.killChainPhase,
              action: scanResult.action,
              latencyMs: scanResult.latencyMs,
            },
          },
        })
      }
    }

    return [outputItems]
  }

  /**
   * Extract text from a JSON object using a dot-notation field path.
   */
  private extractText(json: Readonly<Record<string, unknown>>, field: string): string | null {
    const parts = field.split('.')
    let current: unknown = json

    for (const part of parts) {
      if (current === null || current === undefined || typeof current !== 'object') {
        return null
      }
      current = (current as Record<string, unknown>)[part]
    }

    return typeof current === 'string' ? current : null
  }
}
