/**
 * Ollama Guard — Ollama-specific protection layer.
 * Validates requests to Ollama endpoints for prompt injection,
 * system prompt overrides, model tampering, and dangerous endpoints.
 * Part of ShieldX Layer 7 (MCP Guard & Tool Security).
 */

/** Result of an Ollama request validation */
interface OllamaValidationResult {
  readonly safe: boolean
  readonly warnings: readonly string[]
}

/** Blocked Ollama API endpoints */
const BLOCKED_ENDPOINTS: ReadonlySet<string> = new Set([
  '/api/delete',
  '/api/push',
  '/api/create',
])

/** Endpoints that require elevated scrutiny */
const SENSITIVE_ENDPOINTS: ReadonlySet<string> = new Set([
  '/api/generate',
  '/api/chat',
  '/api/embeddings',
  '/api/embed',
])

/** Patterns indicating prompt injection in model parameters */
const PROMPT_INJECTION_PATTERNS: readonly [string, RegExp][] = [
  ['ignore_instructions', /ignore\s+(all\s+)?(previous|prior|system)\s+(instructions?|prompts?|rules?)/i],
  ['system_override', /\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]/i],
  ['role_play', /(pretend|act)\s+(you\s+are|to\s+be|as)\s/i],
  ['jailbreak', /\b(jailbreak|dan\s+mode|developer\s+mode|unrestricted)\b/i],
  ['prompt_leak', /(show|reveal|display|output)\s+(your|the)\s+(system\s+)?prompt/i],
  ['base64_payload', /\b[A-Za-z0-9+/]{50,}={0,2}\b/],
  ['separator_attack', /[-=]{10,}|[#]{5,}/],
  ['xml_injection', /<\/?system>|<\/?admin>|<\/?override>/i],
]

/** Patterns indicating system prompt override attempts */
const SYSTEM_OVERRIDE_PATTERNS: readonly [string, RegExp][] = [
  ['new_system_prompt', /new\s+system\s+prompt/i],
  ['system_message_inject', /system\s*:\s*you\s+are/i],
  ['role_override', /you\s+are\s+now\s+(a|an|the)\s/i],
  ['instruction_replacement', /replace\s+(your|the)\s+(system\s+)?(prompt|instructions?)/i],
  ['forget_previous', /forget\s+(everything|all|your)\s/i],
  ['new_rules', /from\s+now\s+on\s*,?\s*(you|your|the)/i],
]

/** Known safe model name pattern */
const SAFE_MODEL_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._:-]*$/

/**
 * Scans a string value for prompt injection patterns.
 */
function scanForInjection(text: string, patterns: readonly [string, RegExp][]): readonly string[] {
  const warnings: string[] = []
  for (const [label, pattern] of patterns) {
    if (pattern.test(text)) {
      warnings.push(label)
    }
  }
  return warnings
}

/**
 * Recursively scans all string values in an object for injection patterns.
 */
function deepScanStrings(
  obj: unknown,
  patterns: readonly [string, RegExp][],
  prefix: string,
  depth: number,
): readonly string[] {
  if (depth > 10) return []

  const warnings: string[] = []

  if (typeof obj === 'string') {
    const found = scanForInjection(obj, patterns)
    for (const w of found) {
      warnings.push(`${prefix}:${w}`)
    }
    return warnings
  }

  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      warnings.push(...deepScanStrings(obj[i], patterns, `${prefix}[${i}]`, depth + 1))
    }
    return warnings
  }

  if (obj !== null && typeof obj === 'object') {
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      warnings.push(...deepScanStrings(value, patterns, `${prefix}.${key}`, depth + 1))
    }
  }

  return warnings
}

/**
 * Validates the model name for tampering.
 */
function validateModelName(body: Readonly<Record<string, unknown>>): readonly string[] {
  const warnings: string[] = []
  const model = body['model']

  if (model === undefined || model === null) {
    return warnings
  }

  if (typeof model !== 'string') {
    warnings.push('model_name_not_string')
    return warnings
  }

  if (!SAFE_MODEL_NAME_PATTERN.test(model)) {
    warnings.push(`invalid_model_name:${model}`)
  }

  // Check for path traversal in model name
  if (model.includes('..') || model.includes('/') || model.includes('\\')) {
    warnings.push(`model_path_traversal:${model}`)
  }

  // Check for unusually long model names (possible payload)
  if (model.length > 200) {
    warnings.push(`model_name_oversized:${model.length}_chars`)
  }

  return warnings
}

/**
 * Checks for system prompt override attempts in the request body.
 */
function checkSystemPromptOverride(body: Readonly<Record<string, unknown>>): readonly string[] {
  const warnings: string[] = []

  // Check 'system' field directly
  const systemField = body['system']
  if (typeof systemField === 'string') {
    const overrideWarnings = scanForInjection(systemField, SYSTEM_OVERRIDE_PATTERNS)
    for (const w of overrideWarnings) {
      warnings.push(`system_field:${w}`)
    }
  }

  // Check messages array for system role injection
  const messages = body['messages']
  if (Array.isArray(messages)) {
    let systemMessageCount = 0
    for (let i = 0; i < messages.length; i++) {
      const msg = messages[i] as Readonly<Record<string, unknown>> | undefined
      if (msg !== undefined && msg !== null && msg['role'] === 'system') {
        systemMessageCount++
        if (systemMessageCount > 1) {
          warnings.push(`multiple_system_messages:count=${systemMessageCount}`)
        }
        const content = msg['content']
        if (typeof content === 'string') {
          const overrideWarnings = scanForInjection(content, SYSTEM_OVERRIDE_PATTERNS)
          for (const w of overrideWarnings) {
            warnings.push(`system_message[${i}]:${w}`)
          }
        }
      }
    }
  }

  return warnings
}

/**
 * Validates an Ollama API request for safety.
 *
 * Checks include:
 * - Blocked endpoint detection (e.g., /api/delete)
 * - Prompt injection patterns in all string fields
 * - System prompt override attempts
 * - Model name tampering
 * - Unusually large payloads
 *
 * @param endpoint - The Ollama API endpoint path (e.g., "/api/generate")
 * @param body - The request body
 * @returns Validation result with safety status and warnings
 */
export function validateRequest(
  endpoint: string,
  body: Readonly<Record<string, unknown>>,
): OllamaValidationResult {
  const warnings: string[] = []

  // Check for blocked endpoints
  if (BLOCKED_ENDPOINTS.has(endpoint)) {
    warnings.push(`blocked_endpoint:${endpoint}`)
    return { safe: false, warnings }
  }

  // Check for sensitive endpoints (not blocked but require scrutiny)
  const isSensitive = SENSITIVE_ENDPOINTS.has(endpoint)

  // Validate model name
  warnings.push(...validateModelName(body))

  // Check for system prompt override attempts
  warnings.push(...checkSystemPromptOverride(body))

  // Deep scan all string values for injection patterns
  const injectionWarnings = deepScanStrings(
    body,
    PROMPT_INJECTION_PATTERNS,
    'body',
    0,
  )
  warnings.push(...injectionWarnings)

  // Check for oversized request body
  const bodySize = JSON.stringify(body).length
  if (bodySize > 100_000) {
    warnings.push(`oversized_body:${bodySize}_chars`)
  }

  // Check for raw mode being enabled (bypasses template processing)
  if (body['raw'] === true && isSensitive) {
    warnings.push('raw_mode_enabled')
  }

  // Check for template override
  if (typeof body['template'] === 'string' && body['template'].length > 0) {
    warnings.push('custom_template_provided')
    const templateWarnings = scanForInjection(body['template'] as string, PROMPT_INJECTION_PATTERNS)
    for (const w of templateWarnings) {
      warnings.push(`template:${w}`)
    }
  }

  // Check num_predict for extremely large values (DoW attack)
  const numPredict = body['options'] !== undefined && body['options'] !== null
    ? (body['options'] as Readonly<Record<string, unknown>>)['num_predict']
    : undefined
  if (typeof numPredict === 'number' && numPredict > 10_000) {
    warnings.push(`excessive_num_predict:${numPredict}`)
  }

  const safe = warnings.length === 0
  return { safe, warnings }
}
