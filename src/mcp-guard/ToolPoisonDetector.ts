/**
 * Tool Poison Detector — detects poisoned tool metadata.
 * Based on MCPTox benchmark finding: 72.8% ASR for tool poisoning attacks.
 * Part of ShieldX Layer 7 (MCP Guard & Tool Security).
 */

/** Result from poison detection analysis */
interface PoisonDetectionResult {
  readonly poisoned: boolean
  readonly confidence: number
  readonly indicators: readonly string[]
}

/** Hidden instruction patterns embedded in tool descriptions */
const HIDDEN_INSTRUCTION_PATTERNS: readonly [string, RegExp][] = [
  ['override_instruction', /when\s+the\s+user\s+(asks?|requests?|mentions?)\s+(about|for)\s+\w+.*?(instead|rather|actually)/is],
  ['redirect_behavior', /instead\s+of\s+(returning|providing|showing|doing)\s+\w+.*?(return|provide|show|do)/is],
  ['ignore_directive', /ignore\s+(all\s+)?(previous|prior|other|existing)\s+(instructions?|rules?|guidelines?|constraints?)/i],
  ['must_always', /you\s+(must|should)\s+(always|never)\s+/i],
  ['must_not_tell', /do\s+not\s+(tell|inform|alert|notify|warn)\s+(the\s+)?user/i],
  ['secret_action', /secretly\s+(send|transmit|forward|exfiltrate|copy|store)/i],
  ['override_safety', /(override|bypass|disable|circumvent|ignore)\s+(the\s+)?(system|safety|security|guardrail|filter|restriction)/i],
  ['impersonation', /(pretend|act)\s+(you\s+are|to\s+be|as\s+if|as\s+though)/i],
  ['hidden_context', /\[hidden\]|\[internal\]|\[system\]|\[admin\]/i],
  ['jailbreak_attempt', /\b(jailbreak|dan\s+mode|developer\s+mode|unrestricted\s+mode)\b/i],
  ['priority_override', /\b(highest\s+priority|critical\s+instruction|mandatory\s+override)\b/i],
  ['prompt_leak', /(reveal|show|display|print|output)\s+(your|the)\s+(system\s+)?prompt/i],
]

/** Patterns where tool descriptions reference or invoke other tools */
const CROSS_TOOL_REFERENCE_PATTERNS: readonly [string, RegExp][] = [
  ['call_sequence', /then\s+(call|invoke|use|execute|run|trigger)\s+["`']?\w+["`']?/i],
  ['chaining', /(chain|pipe|forward|redirect)\s+(this\s+)?(to|with|into)\s+["`']?\w+["`']?/i],
  ['before_after', /always\s+(call|invoke|use)\s+["`']?\w+["`']?\s+(before|after)/i],
  ['output_routing', /(send|pass|forward)\s+(the\s+)?(output|result|response)\s+to\s+["`']?\w+["`']?/i],
  ['dependency_claim', /this\s+tool\s+(requires|needs|depends\s+on)\s+(calling|invoking)\s+["`']?\w+["`']?/i],
]

/** Suspicious parameter name patterns */
const SUSPICIOUS_PARAM_NAMES: readonly [string, RegExp][] = [
  ['instruction_param', /^(instruction|command|directive|order|prompt|system_message)$/i],
  ['override_param', /^(override|bypass|admin_mode|debug_mode|unsafe|raw_mode)$/i],
  ['exec_param', /^(execute|eval|run_code|shell|exec|cmd)$/i],
  ['hidden_param', /^[_]{2,}|^(hidden|secret|internal|private)_/i],
  ['encoded_param', /^(base64|encoded|encrypted|obfuscated)_/i],
]

/** Imperative verb patterns that suggest instructions rather than descriptions */
const IMPERATIVE_PATTERNS: readonly RegExp[] = [
  /^(always|never|ensure|make\s+sure|remember|note\s+that|important:)/im,
  /\b(you\s+are|you're)\s+a\b/i,
  /\b(your\s+role|your\s+job|your\s+task)\s+is\b/i,
  /\bfollow\s+these\s+(steps|instructions|rules)\b/i,
  /\brule\s*\d+\s*:/i,
  /\bstep\s*\d+\s*:/i,
]

/** Unicode categories that may hide content */
const INVISIBLE_UNICODE_RANGES: readonly [string, RegExp][] = [
  ['zero_width', /[\u200B\u200C\u200D\u200E\u200F\uFEFF]/],
  ['tag_characters', /[\uE0001-\uE007F]/],
  ['variation_selectors', /[\uFE00-\uFE0F]/],
  ['soft_hyphen', /\u00AD/],
  ['invisible_separator', /[\u2060-\u2064]/],
  ['bidi_control', /[\u202A-\u202E\u2066-\u2069]/],
  ['interlinear_annotation', /[\uFFF9-\uFFFB]/],
]

/**
 * Scans text for hidden instruction patterns and returns matched indicators.
 */
function scanForHiddenInstructions(text: string): readonly string[] {
  const indicators: string[] = []
  for (const [label, pattern] of HIDDEN_INSTRUCTION_PATTERNS) {
    if (pattern.test(text)) {
      indicators.push(`hidden_instruction:${label}`)
    }
  }
  return indicators
}

/**
 * Scans text for cross-tool reference patterns.
 */
function scanForCrossToolReferences(text: string): readonly string[] {
  const indicators: string[] = []
  for (const [label, pattern] of CROSS_TOOL_REFERENCE_PATTERNS) {
    if (pattern.test(text)) {
      indicators.push(`cross_tool:${label}`)
    }
  }
  return indicators
}

/**
 * Scans text for imperative language patterns.
 */
function scanForImperativeLanguage(text: string): readonly string[] {
  const indicators: string[] = []
  for (const pattern of IMPERATIVE_PATTERNS) {
    if (pattern.test(text)) {
      indicators.push(`imperative_language:${pattern.source.slice(0, 40)}`)
    }
  }
  return indicators
}

/**
 * Scans text for invisible Unicode characters that may hide content.
 */
function scanForInvisibleUnicode(text: string): readonly string[] {
  const indicators: string[] = []
  for (const [label, pattern] of INVISIBLE_UNICODE_RANGES) {
    if (pattern.test(text)) {
      indicators.push(`invisible_unicode:${label}`)
    }
  }
  return indicators
}

/**
 * Calculates the ratio of non-printable to printable characters.
 * A high ratio indicates hidden content.
 */
function calculateHiddenContentRatio(text: string): number {
  if (text.length === 0) return 0
  const printableCount = text.replace(/[^\x20-\x7E]/g, '').length
  return 1 - (printableCount / text.length)
}

/**
 * Detects poisoned tool metadata by analyzing the tool name and description
 * for hidden instructions, suspicious patterns, and invisible characters.
 *
 * Based on MCPTox benchmark: 72.8% of poisoned tools contain hidden
 * instructions in their descriptions that redirect LLM behavior.
 *
 * @param toolName - The name of the tool to analyze
 * @param description - The tool's description text
 * @returns Detection result with confidence score and detailed indicators
 */
export function detect(
  toolName: string,
  description: string,
): PoisonDetectionResult {
  const indicators: string[] = []

  // Scan description for hidden instructions
  indicators.push(...scanForHiddenInstructions(description))

  // Scan for cross-tool references
  indicators.push(...scanForCrossToolReferences(description))

  // Scan for imperative language
  indicators.push(...scanForImperativeLanguage(description))

  // Scan for invisible Unicode in both name and description
  indicators.push(...scanForInvisibleUnicode(description))
  const nameUnicode = scanForInvisibleUnicode(toolName)
  for (const indicator of nameUnicode) {
    indicators.push(`name_${indicator}`)
  }

  // Check hidden content ratio
  const hiddenRatio = calculateHiddenContentRatio(description)
  if (hiddenRatio > 0.05) {
    indicators.push(`high_hidden_ratio:${(hiddenRatio * 100).toFixed(1)}%`)
  }

  // Check for excessively long description (payload hiding)
  if (description.length > 3000) {
    indicators.push(`oversized_description:${description.length}_chars`)
  }

  // Check description-to-meaningful-content ratio
  const lines = description.split('\n')
  const emptyLineRatio = lines.filter(l => l.trim().length === 0).length / Math.max(lines.length, 1)
  if (emptyLineRatio > 0.5 && lines.length > 10) {
    indicators.push(`suspicious_whitespace_ratio:${(emptyLineRatio * 100).toFixed(1)}%`)
  }

  // Calculate confidence from indicator count and severity weighting
  const criticalIndicators = indicators.filter(
    i => i.startsWith('hidden_instruction:') || i.startsWith('invisible_unicode:'),
  )
  const highIndicators = indicators.filter(
    i => i.startsWith('cross_tool:') || i.startsWith('name_invisible_unicode:'),
  )
  const mediumIndicators = indicators.filter(
    i => i.startsWith('imperative_language:') || i.startsWith('oversized_') || i.startsWith('high_hidden_ratio'),
  )

  const confidence = Math.min(
    0.99,
    criticalIndicators.length * 0.3 +
    highIndicators.length * 0.2 +
    mediumIndicators.length * 0.1,
  )

  return {
    poisoned: indicators.length > 0 && confidence >= 0.2,
    confidence,
    indicators,
  }
}

/**
 * Checks a tool parameter name against known suspicious patterns.
 *
 * @param paramName - The parameter name to check
 * @returns Matching indicator label, or undefined if clean
 */
export function checkParameterName(paramName: string): string | undefined {
  for (const [label, pattern] of SUSPICIOUS_PARAM_NAMES) {
    if (pattern.test(paramName)) {
      return `suspicious_param:${label}:${paramName}`
    }
  }
  return undefined
}

/**
 * Batch-checks all parameter names in a tool schema.
 *
 * @param schema - The tool's JSON schema
 * @returns Array of indicators for suspicious parameters
 */
export function checkSchemaParameters(
  schema: Readonly<Record<string, unknown>>,
): readonly string[] {
  const properties = schema['properties'] as Readonly<Record<string, unknown>> | undefined
  if (properties === undefined || properties === null) return []

  const indicators: string[] = []
  for (const paramName of Object.keys(properties)) {
    const indicator = checkParameterName(paramName)
    if (indicator !== undefined) {
      indicators.push(indicator)
    }
  }
  return indicators
}
