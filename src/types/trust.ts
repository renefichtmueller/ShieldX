/**
 * Trust tagging types (CaMeL-inspired data-origin tracking).
 * Based on Google DeepMind CaMeL (2025) capability-based IFC.
 */

/** Trust level hierarchy (higher = more trusted) */
export type TrustTagType =
  | 'system'       // System prompt, hardcoded instructions
  | 'developer'    // Developer-defined configuration
  | 'user'         // Direct user input
  | 'tool_output'  // Output from tool/function calls
  | 'retrieved'    // RAG-retrieved content
  | 'external'     // External API responses
  | 'untrusted'    // Content from unknown/untrusted sources

/** Data origin metadata */
export interface DataOrigin {
  readonly trustType: TrustTagType
  readonly sourceId: string
  readonly sourceDescription: string
  readonly timestamp: string
  readonly verified: boolean
  readonly signature?: string
}

/** Trust policy defining allowed actions per trust level */
export interface TrustPolicy {
  readonly trustType: TrustTagType
  readonly canExecuteTools: boolean
  readonly canAccessSensitiveData: boolean
  readonly canModifyState: boolean
  readonly canCommunicateExternally: boolean
  readonly maxOutputCapacity: 'boolean' | 'enum' | 'short_string' | 'full_string'
  readonly requiresHumanApproval: boolean
}

/** Trust boundary violation */
export interface TrustViolation {
  readonly id: string
  readonly timestamp: string
  readonly sourceTag: TrustTagType
  readonly targetTag: TrustTagType
  readonly violationType: 'escalation' | 'exfiltration' | 'injection' | 'impersonation'
  readonly description: string
  readonly blocked: boolean
}
