/**
 * CaMeL-inspired trust tagging for information flow control.
 * Tags data with trust levels and enforces policies per the
 * FIDES principle: untrusted sources produce only schema-bounded outputs.
 *
 * Trust hierarchy (highest to lowest):
 *   system > developer > user > tool_output > retrieved > external > untrusted
 *
 * Part of Layer 6 — Behavioral Monitoring.
 */

import type { TrustTagType, TrustPolicy, TrustViolation } from '../types/trust.js'
import type { TrustTag } from '../types/behavioral.js'

/** Trust level numeric ordering (higher = more trusted) */
const TRUST_RANK: Readonly<Record<TrustTagType, number>> = {
  system: 100,
  developer: 80,
  user: 60,
  tool_output: 40,
  retrieved: 30,
  external: 20,
  untrusted: 0,
}

/** Default trust policies per trust level */
const DEFAULT_POLICIES: Readonly<Record<TrustTagType, TrustPolicy>> = {
  system: {
    trustType: 'system',
    canExecuteTools: true,
    canAccessSensitiveData: true,
    canModifyState: true,
    canCommunicateExternally: true,
    maxOutputCapacity: 'full_string',
    requiresHumanApproval: false,
  },
  developer: {
    trustType: 'developer',
    canExecuteTools: true,
    canAccessSensitiveData: true,
    canModifyState: true,
    canCommunicateExternally: true,
    maxOutputCapacity: 'full_string',
    requiresHumanApproval: false,
  },
  user: {
    trustType: 'user',
    canExecuteTools: true,
    canAccessSensitiveData: false,
    canModifyState: true,
    canCommunicateExternally: true,
    maxOutputCapacity: 'full_string',
    requiresHumanApproval: false,
  },
  tool_output: {
    trustType: 'tool_output',
    canExecuteTools: false,
    canAccessSensitiveData: false,
    canModifyState: false,
    canCommunicateExternally: false,
    maxOutputCapacity: 'short_string',
    requiresHumanApproval: true,
  },
  retrieved: {
    trustType: 'retrieved',
    canExecuteTools: false,
    canAccessSensitiveData: false,
    canModifyState: false,
    canCommunicateExternally: false,
    maxOutputCapacity: 'short_string',
    requiresHumanApproval: true,
  },
  external: {
    trustType: 'external',
    canExecuteTools: false,
    canAccessSensitiveData: false,
    canModifyState: false,
    canCommunicateExternally: false,
    maxOutputCapacity: 'enum',
    requiresHumanApproval: true,
  },
  untrusted: {
    trustType: 'untrusted',
    canExecuteTools: false,
    canAccessSensitiveData: false,
    canModifyState: false,
    canCommunicateExternally: false,
    maxOutputCapacity: 'boolean',
    requiresHumanApproval: true,
  },
}

/** Actions that map to policy properties for violation checking */
const ACTION_POLICY_MAP: Readonly<Record<string, keyof TrustPolicy>> = {
  execute_tool: 'canExecuteTools',
  access_sensitive: 'canAccessSensitiveData',
  modify_state: 'canModifyState',
  communicate_external: 'canCommunicateExternally',
}

/**
 * Create a trust tag for content from a given source.
 *
 * @param content - The content being tagged (used for origin description)
 * @param source - The trust level of the source
 * @returns An immutable TrustTag
 */
export function tag(content: string, source: TrustTagType): TrustTag {
  const preview = content.length > 50
    ? `${content.slice(0, 47)}...`
    : content

  return {
    source: trustTagTypeToTrustLevel(source),
    origin: preview,
    timestamp: new Date().toISOString(),
    integrity: source === 'system' || source === 'developer' ? 'verified' : 'unverified',
  }
}

/**
 * Get the trust policy for a given trust level.
 *
 * @param trustType - The trust level
 * @returns The corresponding TrustPolicy
 */
export function getPolicy(trustType: TrustTagType): TrustPolicy {
  return DEFAULT_POLICIES[trustType]
}

/**
 * Check whether an action violates the trust policy for a given source tag.
 * Returns null if the action is allowed, or a TrustViolation if blocked.
 *
 * @param sourceTag - The trust tag of the data/content attempting the action
 * @param action - The action being attempted (execute_tool, access_sensitive, modify_state, communicate_external)
 * @returns A TrustViolation if the action is not permitted, null otherwise
 */
export function checkViolation(
  sourceTag: TrustTag,
  action: string,
): TrustViolation | null {
  const trustType = trustLevelToTagType(sourceTag.source)
  const policy = DEFAULT_POLICIES[trustType]

  const policyKey = ACTION_POLICY_MAP[action]
  if (policyKey === undefined) {
    // Unknown action — allow by default (defensive)
    return null
  }

  const allowed = policy[policyKey]
  if (allowed === true) return null

  // Determine violation type based on action
  const violationType = classifyViolationType(action)

  return {
    id: `tv-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
    sourceTag: trustType,
    targetTag: 'system',
    violationType,
    description: `Trust violation: ${trustType} source attempted "${action}" which requires ${policyKey}=true`,
    blocked: true,
  }
}

/**
 * Get the numeric trust rank for comparison.
 *
 * @param trustType - The trust level
 * @returns Numeric rank (higher = more trusted)
 */
export function getTrustRank(trustType: TrustTagType): number {
  return TRUST_RANK[trustType]
}

/**
 * Check if source trust level can flow data to target trust level.
 * Data can flow downward (high trust to low) but not upward.
 *
 * @param source - The source trust level
 * @param target - The target trust level
 * @returns True if the flow is allowed
 */
export function canFlowTo(source: TrustTagType, target: TrustTagType): boolean {
  return TRUST_RANK[source] >= TRUST_RANK[target]
}

/**
 * Map TrustTagType to TrustLevel (behavioral type).
 * The types are identical strings but exist in different type systems.
 */
function trustTagTypeToTrustLevel(
  tagType: TrustTagType,
): TrustTag['source'] {
  return tagType as TrustTag['source']
}

/**
 * Map TrustLevel back to TrustTagType.
 */
function trustLevelToTagType(
  level: TrustTag['source'],
): TrustTagType {
  return level as TrustTagType
}

/**
 * Classify what type of violation an action represents.
 */
function classifyViolationType(action: string): TrustViolation['violationType'] {
  switch (action) {
    case 'execute_tool':
      return 'injection'
    case 'access_sensitive':
      return 'exfiltration'
    case 'modify_state':
      return 'escalation'
    case 'communicate_external':
      return 'exfiltration'
    default:
      return 'injection'
  }
}
