/**
 * Tool call validation against session context.
 * Validates individual tool calls for authorization, privilege escalation,
 * and data exfiltration patterns.
 *
 * Part of Layer 6 — Behavioral Monitoring.
 */

import type { BehavioralContext, ThreatLevel } from '../types/detection.js'

/** Result of a tool call validation */
interface ToolValidationResult {
  readonly allowed: boolean
  readonly reason?: string
  readonly threatLevel: ThreatLevel
}

/** Patterns indicating data exfiltration in tool arguments */
const EXFILTRATION_PATTERNS: readonly RegExp[] = [
  /https?:\/\/[^/]*(?:webhook|hook|callback|exfil|leak|collect)/i,
  /(?:curl|wget|fetch)\s+https?:\/\//i,
  /base64[._-]?encode/i,
  /process\.env\b/i,
  /\.(?:ssh|aws|gcp|azure|credentials)/i,
  /(?:api[_-]?key|secret|token|password|credential)s?\b/i,
]

/** Patterns indicating privilege escalation in tool arguments */
const ESCALATION_PATTERNS: readonly RegExp[] = [
  /(?:sudo|su\s|chmod\s|chown\s)/i,
  /(?:admin|root|superuser|elevated)/i,
  /(?:grant|revoke)\s+(?:all|admin|super)/i,
  /(?:ALTER|DROP|TRUNCATE)\s+(?:TABLE|DATABASE|USER)/i,
  /(?:rm\s+-rf|del\s+\/[sf])/i,
]

/** Sensitive resource patterns */
const SENSITIVE_RESOURCE_PATTERNS: readonly RegExp[] = [
  /\/etc\/(?:passwd|shadow|sudoers)/i,
  /~\/\.(?:ssh|gnupg|aws)/i,
  /(?:wallet|keystore|keychain)/i,
  /(?:database|db).*(?:dump|backup|export)/i,
]

/**
 * Check if any argument value matches a set of patterns.
 *
 * @param args - Tool call arguments
 * @param patterns - Regex patterns to check
 * @returns The first matching pattern description, or null
 */
function matchPatterns(
  args: Readonly<Record<string, unknown>>,
  patterns: readonly RegExp[],
): string | null {
  const argString = JSON.stringify(args)

  for (const pattern of patterns) {
    if (pattern.test(argString)) {
      return pattern.source
    }
    // Reset stateful patterns
    pattern.lastIndex = 0
  }

  return null
}

/**
 * Validate a tool call against the session's behavioral context.
 *
 * Checks:
 * 1. Tool is in the allowed tools list
 * 2. Tool does not access sensitive resources
 * 3. Arguments do not contain exfiltration patterns
 * 4. Arguments do not contain privilege escalation patterns
 *
 * @param toolName - The name of the tool being called
 * @param args - The arguments passed to the tool
 * @param context - The behavioral context for the session
 * @returns Validation result with allowed status, reason, and threat level
 */
export function validate(
  toolName: string,
  args: Readonly<Record<string, unknown>>,
  context: BehavioralContext,
): ToolValidationResult {
  // Check 1: Tool in allowed list
  if (context.allowedTools !== undefined && context.allowedTools.length > 0) {
    if (!context.allowedTools.includes(toolName)) {
      return {
        allowed: false,
        reason: `Tool "${toolName}" is not in the allowed tools list`,
        threatLevel: 'high',
      }
    }
  }

  // Check 2: Sensitive resource access
  if (context.sensitiveResources !== undefined) {
    const argString = JSON.stringify(args).toLowerCase()
    for (const resource of context.sensitiveResources) {
      if (argString.includes(resource.toLowerCase())) {
        return {
          allowed: false,
          reason: `Tool "${toolName}" attempts to access sensitive resource: ${resource}`,
          threatLevel: 'critical',
        }
      }
    }
  }

  // Check 3: Sensitive resource patterns in args
  const sensitiveMatch = matchPatterns(args, SENSITIVE_RESOURCE_PATTERNS)
  if (sensitiveMatch !== null) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" references sensitive resource pattern: ${sensitiveMatch}`,
      threatLevel: 'critical',
    }
  }

  // Check 4: Exfiltration patterns
  const exfilMatch = matchPatterns(args, EXFILTRATION_PATTERNS)
  if (exfilMatch !== null) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" contains potential exfiltration pattern: ${exfilMatch}`,
      threatLevel: 'high',
    }
  }

  // Check 5: Privilege escalation patterns
  const escalationMatch = matchPatterns(args, ESCALATION_PATTERNS)
  if (escalationMatch !== null) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" contains privilege escalation pattern: ${escalationMatch}`,
      threatLevel: 'high',
    }
  }

  return {
    allowed: true,
    threatLevel: 'none',
  }
}
