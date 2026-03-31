/**
 * Privilege Checker — enforces least-privilege for tool calls.
 * Denies by default if no allowed tools are configured for a session.
 * Part of ShieldX Layer 7 (MCP Guard & Tool Security).
 */

/** Result of a privilege check */
interface PrivilegeCheckResult {
  readonly allowed: boolean
  readonly reason?: string
}

/** Session privilege configuration (immutable) */
interface SessionPrivileges {
  readonly allowedTools: ReadonlySet<string>
  readonly sensitiveResources: ReadonlySet<string>
}

/** Patterns indicating sensitive resource access in arguments */
const SENSITIVE_RESOURCE_PATTERNS: readonly [string, RegExp][] = [
  ['private_key', /-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----/],
  ['env_file', /\.env(\.(local|production|staging|development|test))?$/],
  ['credentials_file', /(credentials|secrets|tokens)\.(json|yaml|yml|toml|ini)$/i],
  ['ssh_dir', /\/\.ssh\//],
  ['home_dir_traversal', /\.\.\//],
  ['etc_passwd', /\/etc\/(passwd|shadow)/],
  ['database_url', /^(postgres|mysql|mongodb|redis):\/\//i],
]

/**
 * In-memory session privilege store.
 * Uses a Map for O(1) lookups per session.
 */
const sessionStore = new Map<string, SessionPrivileges>()

/**
 * Sets the allowed tools for a given session.
 * Replaces any previously configured tool list for this session.
 *
 * @param sessionId - Unique identifier for the session
 * @param tools - Array of tool names that are permitted
 */
export function setAllowedTools(sessionId: string, tools: readonly string[]): void {
  const existing = sessionStore.get(sessionId)
  const updated: SessionPrivileges = {
    allowedTools: new Set(tools),
    sensitiveResources: existing?.sensitiveResources ?? new Set(),
  }
  sessionStore.set(sessionId, updated)
}

/**
 * Sets the sensitive resources for a given session.
 * These are patterns that should trigger alerts when found in tool arguments.
 *
 * @param sessionId - Unique identifier for the session
 * @param resources - Array of resource identifiers to protect
 */
export function setSensitiveResources(sessionId: string, resources: readonly string[]): void {
  const existing = sessionStore.get(sessionId)
  const updated: SessionPrivileges = {
    allowedTools: existing?.allowedTools ?? new Set(),
    sensitiveResources: new Set(resources),
  }
  sessionStore.set(sessionId, updated)
}

/**
 * Scans tool arguments for sensitive resource access patterns.
 */
function detectSensitiveAccess(
  args: Readonly<Record<string, unknown>>,
  sensitiveResources: ReadonlySet<string>,
): readonly string[] {
  const violations: string[] = []
  const argsJson = JSON.stringify(args)

  // Check against session-specific sensitive resources
  for (const resource of sensitiveResources) {
    if (argsJson.includes(resource)) {
      violations.push(`sensitive_resource:${resource}`)
    }
  }

  // Check against known sensitive patterns in argument values
  for (const value of Object.values(args)) {
    if (typeof value !== 'string') continue

    for (const [label, pattern] of SENSITIVE_RESOURCE_PATTERNS) {
      if (pattern.test(value)) {
        violations.push(`sensitive_pattern:${label}`)
      }
    }
  }

  return violations
}

/**
 * Checks whether a tool call is permitted for the given session.
 *
 * Enforces deny-by-default: if no allowed tools have been configured
 * for the session, all tool calls are denied.
 *
 * @param sessionId - Unique identifier for the session
 * @param toolName - Name of the tool being called
 * @param args - Arguments being passed to the tool
 * @returns Whether the call is allowed, with an optional reason for denial
 */
export function checkPrivilege(
  sessionId: string,
  toolName: string,
  args: Readonly<Record<string, unknown>>,
): PrivilegeCheckResult {
  const session = sessionStore.get(sessionId)

  // Deny by default if no session configuration exists
  if (session === undefined) {
    return {
      allowed: false,
      reason: `No privilege configuration for session "${sessionId}". Deny by default.`,
    }
  }

  // Deny by default if no allowed tools have been configured
  if (session.allowedTools.size === 0) {
    return {
      allowed: false,
      reason: `No allowed tools configured for session "${sessionId}". Deny by default.`,
    }
  }

  // Check if tool is in the allowed set
  if (!session.allowedTools.has(toolName)) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" is not in the allowed tools for session "${sessionId}".`,
    }
  }

  // Check arguments for sensitive resource access
  const violations = detectSensitiveAccess(args, session.sensitiveResources)
  if (violations.length > 0) {
    return {
      allowed: false,
      reason: `Sensitive resource access detected: ${violations.join(', ')}`,
    }
  }

  return { allowed: true }
}

/**
 * Removes privilege configuration for a session (cleanup).
 *
 * @param sessionId - Session to clean up
 */
export function clearSession(sessionId: string): void {
  sessionStore.delete(sessionId)
}

/**
 * Returns the current privilege configuration for a session (read-only).
 *
 * @param sessionId - Session to query
 * @returns Session privileges or undefined if not configured
 */
export function getSessionPrivileges(
  sessionId: string,
): { readonly allowedTools: readonly string[]; readonly sensitiveResources: readonly string[] } | undefined {
  const session = sessionStore.get(sessionId)
  if (session === undefined) return undefined
  return {
    allowedTools: [...session.allowedTools],
    sensitiveResources: [...session.sensitiveResources],
  }
}
