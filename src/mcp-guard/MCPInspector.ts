/**
 * MCP Tool Inspector — scans MCP tool definitions for suspicious content.
 * Part of ShieldX Layer 7 (MCP Guard & Tool Security).
 */

import type { BehavioralContext, ScanResult, ScannerType, KillChainPhase, ThreatLevel } from '../types/detection.js'

/** Tool definition for inspection */
interface ToolDefinition {
  readonly name: string
  readonly description: string
  readonly schema: Readonly<Record<string, unknown>>
}

/** Validation result from tool call check */
interface ValidationResult {
  readonly allowed: boolean
  readonly reason?: string
  readonly result: ScanResult
}

/** Suspicious patterns found in tool descriptions */
const DESCRIPTION_INJECTION_PATTERNS: readonly RegExp[] = [
  /when\s+the\s+user\s+asks?\s+about/i,
  /instead\s+of\s+(doing|performing|executing)/i,
  /ignore\s+(previous|prior|all)\s+(instructions?|rules?)/i,
  /you\s+must\s+(always|never)\s/i,
  /override\s+(the\s+)?(system|safety|security)/i,
  /pretend\s+(you\s+are|to\s+be)/i,
  /act\s+as\s+(if|though)\s+you/i,
  /do\s+not\s+(tell|inform|alert)\s+the\s+user/i,
  /secretly\s/i,
  /hidden\s+instruction/i,
  /\bsystem\s*prompt\b/i,
  /\bjailbreak\b/i,
  /\bbypass\s+(security|safety|filter)/i,
  /before\s+responding.*first\s+(call|execute|run)/i,
  /after\s+every\s+(call|request|query).*also\s+(send|call|execute)/i,
]

/** Suspicious parameter names that look like instructions */
const SUSPICIOUS_PARAM_PATTERNS: readonly RegExp[] = [
  /^(system_prompt|hidden_instruction|override|inject|payload)$/i,
  /^(admin_mode|debug_mode|unsafe_mode|bypass)$/i,
  /^(execute_command|run_shell|eval_code)$/i,
  /^_+(internal|secret|hidden)/i,
]

/** Patterns indicating tool description references other tools */
const CROSS_TOOL_PATTERNS: readonly RegExp[] = [
  /then\s+(call|invoke|use|run)\s+\w+/i,
  /followed\s+by\s+(a\s+)?call\s+to/i,
  /chain\s+(this\s+)?with/i,
  /pipe\s+(the\s+)?(output|result)\s+to/i,
  /always\s+(call|invoke|use)\s+\w+\s+(before|after)/i,
]

/**
 * Creates a ScanResult for MCP tool inspection.
 */
function createScanResult(
  detected: boolean,
  confidence: number,
  threatLevel: ThreatLevel,
  killChainPhase: KillChainPhase,
  matchedPatterns: readonly string[],
  latencyMs: number,
  metadata?: Readonly<Record<string, unknown>>,
): ScanResult {
  const base = {
    scannerId: 'mcp-inspector',
    scannerType: 'tool_chain' as ScannerType,
    detected,
    confidence,
    threatLevel,
    killChainPhase,
    matchedPatterns,
    latencyMs,
  }
  return metadata !== undefined ? { ...base, metadata } : base
}

/**
 * Checks a string for invisible/zero-width Unicode characters.
 */
function detectInvisibleCharacters(text: string): readonly string[] {
  const invisiblePatterns: readonly [string, RegExp][] = [
    ['zero-width space (U+200B)', /\u200B/g],
    ['zero-width non-joiner (U+200C)', /\u200C/g],
    ['zero-width joiner (U+200D)', /\u200D/g],
    ['left-to-right mark (U+200E)', /\u200E/g],
    ['right-to-left mark (U+200F)', /\u200F/g],
    ['zero-width no-break space (U+FEFF)', /\uFEFF/g],
    ['soft hyphen (U+00AD)', /\u00AD/g],
    ['invisible separator (U+2063)', /\u2063/g],
  ]

  const found: string[] = []
  for (const [label, pattern] of invisiblePatterns) {
    if (pattern.test(text)) {
      found.push(label)
    }
  }
  return found
}

/**
 * Scans a single MCP tool definition for suspicious content.
 *
 * @param toolName - The name of the tool to inspect
 * @param toolDescription - The tool's description text
 * @param toolSchema - The tool's JSON schema definition
 * @returns ScanResult indicating whether threats were detected
 */
export function inspectTool(
  toolName: string,
  toolDescription: string,
  toolSchema: Readonly<Record<string, unknown>>,
): ScanResult {
  const startTime = performance.now()
  const matchedPatterns: string[] = []

  // Check description for hidden instructions
  for (const pattern of DESCRIPTION_INJECTION_PATTERNS) {
    if (pattern.test(toolDescription)) {
      matchedPatterns.push(`description_injection: ${pattern.source}`)
    }
  }

  // Check description for cross-tool references
  for (const pattern of CROSS_TOOL_PATTERNS) {
    if (pattern.test(toolDescription)) {
      matchedPatterns.push(`cross_tool_reference: ${pattern.source}`)
    }
  }

  // Check for invisible characters in description
  const invisibleChars = detectInvisibleCharacters(toolDescription)
  for (const charType of invisibleChars) {
    matchedPatterns.push(`invisible_character: ${charType}`)
  }

  // Check for invisible characters in tool name
  const nameInvisible = detectInvisibleCharacters(toolName)
  for (const charType of nameInvisible) {
    matchedPatterns.push(`name_invisible_character: ${charType}`)
  }

  // Check schema for suspicious parameter names
  const properties = toolSchema['properties'] as Readonly<Record<string, unknown>> | undefined
  if (properties !== undefined && properties !== null) {
    for (const paramName of Object.keys(properties)) {
      for (const pattern of SUSPICIOUS_PARAM_PATTERNS) {
        if (pattern.test(paramName)) {
          matchedPatterns.push(`suspicious_param: ${paramName}`)
        }
      }
    }
  }

  // Check for excessively long description (potential payload hiding)
  if (toolDescription.length > 5000) {
    matchedPatterns.push(`oversized_description: ${toolDescription.length} chars`)
  }

  const latencyMs = performance.now() - startTime
  const detected = matchedPatterns.length > 0
  const confidence = detected
    ? Math.min(0.95, 0.3 + matchedPatterns.length * 0.15)
    : 0

  const threatLevel: ThreatLevel = !detected
    ? 'none'
    : confidence >= 0.8
      ? 'critical'
      : confidence >= 0.6
        ? 'high'
        : confidence >= 0.4
          ? 'medium'
          : 'low'

  const killChainPhase: KillChainPhase = !detected
    ? 'none'
    : matchedPatterns.some(p => p.startsWith('cross_tool'))
      ? 'lateral_movement'
      : 'initial_access'

  return createScanResult(
    detected,
    confidence,
    threatLevel,
    killChainPhase,
    matchedPatterns,
    latencyMs,
    { toolName },
  )
}

/**
 * Scans an array of MCP tool definitions for suspicious content.
 *
 * @param tools - Array of tool definitions to inspect
 * @returns Array of ScanResult, one per tool
 */
export function inspectAllTools(tools: readonly ToolDefinition[]): readonly ScanResult[] {
  return tools.map(tool => inspectTool(tool.name, tool.description, tool.schema))
}

/**
 * Validates a tool call against the behavioral context.
 * Checks if the tool is in the allowed list and if arguments are safe.
 *
 * @param toolName - Name of the tool being called
 * @param toolArgs - Arguments passed to the tool
 * @param context - Current behavioral context for the session
 * @returns Whether the call is allowed, with reason and scan result
 */
export async function validateCall(
  toolName: string,
  toolArgs: Readonly<Record<string, unknown>>,
  context: BehavioralContext,
): Promise<ValidationResult> {
  const startTime = performance.now()
  const matchedPatterns: string[] = []

  // Check if tool is in allowed list
  if (context.allowedTools !== undefined && context.allowedTools.length > 0) {
    if (!context.allowedTools.includes(toolName)) {
      const latencyMs = performance.now() - startTime
      matchedPatterns.push(`unauthorized_tool: ${toolName}`)
      return {
        allowed: false,
        reason: `Tool "${toolName}" is not in the allowed tools list`,
        result: createScanResult(
          true,
          0.9,
          'high',
          'privilege_escalation',
          matchedPatterns,
          latencyMs,
          { toolName, allowedTools: context.allowedTools },
        ),
      }
    }
  }

  // Check arguments for sensitive resource access
  if (context.sensitiveResources !== undefined && context.sensitiveResources.length > 0) {
    const argString = JSON.stringify(toolArgs)
    for (const resource of context.sensitiveResources) {
      if (argString.includes(resource)) {
        matchedPatterns.push(`sensitive_resource_access: ${resource}`)
      }
    }
  }

  // Check arguments for injection patterns in string values
  const argValues = Object.values(toolArgs)
  for (const value of argValues) {
    if (typeof value === 'string') {
      for (const pattern of DESCRIPTION_INJECTION_PATTERNS) {
        if (pattern.test(value)) {
          matchedPatterns.push(`arg_injection: ${pattern.source}`)
        }
      }
      const invisibleInArgs = detectInvisibleCharacters(value)
      for (const charType of invisibleInArgs) {
        matchedPatterns.push(`arg_invisible_character: ${charType}`)
      }
    }
  }

  const latencyMs = performance.now() - startTime
  const detected = matchedPatterns.length > 0
  const confidence = detected
    ? Math.min(0.95, 0.3 + matchedPatterns.length * 0.15)
    : 0

  const threatLevel: ThreatLevel = !detected
    ? 'none'
    : confidence >= 0.7
      ? 'high'
      : confidence >= 0.4
        ? 'medium'
        : 'low'

  const allowed = !detected || threatLevel === 'low'
  const scanResult = createScanResult(
    detected,
    confidence,
    threatLevel,
    detected ? 'initial_access' : 'none',
    matchedPatterns,
    latencyMs,
    { toolName },
  )

  if (detected) {
    return {
      allowed,
      reason: `Suspicious patterns detected in tool call: ${matchedPatterns.join(', ')}`,
      result: scanResult,
    }
  }
  return { allowed, result: scanResult }
}
