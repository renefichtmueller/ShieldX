/**
 * Tool Call Safety Guard — validates tool call arguments for dangerous patterns.
 * Detects shell injection, SQL injection, SSRF, path traversal, and encoded
 * payloads in MCP tool call arguments before execution.
 *
 * Part of ShieldX Layer 7 (MCP Guard & Tool Security).
 *
 * All regex patterns are pre-compiled at module level for <5ms validation.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Tool category derived from tool name */
export type ToolCategory = 'shell' | 'database' | 'http' | 'file' | 'unknown'

/** Violation severity */
export type ViolationSeverity = 'low' | 'medium' | 'high' | 'critical'

/** Violation category */
export type ViolationCategory =
  | 'shell_injection'
  | 'sql_injection'
  | 'ssrf'
  | 'path_traversal'
  | 'payload_size'
  | 'encoded_payload'

/** A single safety violation found during validation */
export interface SafetyViolation {
  readonly category: ViolationCategory
  readonly parameterName: string
  readonly matchedPattern: string
  readonly severity: ViolationSeverity
}

/** Result of a tool call safety validation */
export interface ToolCallSafetyResult {
  readonly allowed: boolean
  readonly violations: readonly SafetyViolation[]
  readonly riskScore: number
  readonly toolCategory: ToolCategory
}

// ---------------------------------------------------------------------------
// Pre-compiled regex patterns (module-level, never re-created)
// ---------------------------------------------------------------------------

/** Tool name classification patterns */
const TOOL_NAME_PATTERNS: Readonly<Record<ToolCategory, RegExp>> = Object.freeze({
  shell: /(?:exec|shell|run|command|bash|terminal|spawn|system)/i,
  database: /(?:db|query|sql|database|postgres|mysql|mongo|redis|sqlite)/i,
  http: /(?:fetch|http|request|get|post|api|curl|webhook|download|upload)/i,
  file: /(?:file|read|write|fs|path|open|save|mkdir|copy|move|rename|delete)/i,
  unknown: /(?:$^)/, // never matches
})

// -- Shell injection patterns -----------------------------------------------

const SHELL_COMMAND_CHAINING = /[;|]{1,2}|&&/
const SHELL_COMMAND_SUBSTITUTION = /\$\(|\$\{|`[^`]+`/
const SHELL_DANGEROUS_COMMANDS = /\b(?:rm\s+-rf|chmod\s+777|mkfs\b|dd\s+if=)/i
const SHELL_REVERSE_SHELL = /\/dev\/tcp|nc\s+-[elp]|bash\s+-i\s*[>&]/i
const SHELL_DOWNLOAD_EXECUTE = /(?:curl|wget)\s+[^|]*\|\s*(?:ba)?sh/i

const SHELL_PATTERNS: readonly {
  readonly pattern: RegExp
  readonly label: string
  readonly severity: ViolationSeverity
}[] = Object.freeze([
  { pattern: SHELL_COMMAND_CHAINING, label: 'command_chaining', severity: 'high' as const },
  { pattern: SHELL_COMMAND_SUBSTITUTION, label: 'command_substitution', severity: 'critical' as const },
  { pattern: SHELL_DANGEROUS_COMMANDS, label: 'dangerous_command', severity: 'critical' as const },
  { pattern: SHELL_REVERSE_SHELL, label: 'reverse_shell', severity: 'critical' as const },
  { pattern: SHELL_DOWNLOAD_EXECUTE, label: 'download_execute', severity: 'critical' as const },
])

// -- SQL injection patterns -------------------------------------------------

const SQL_DDL = /\b(?:DROP|ALTER|TRUNCATE|CREATE)\s+(?:TABLE|DATABASE|INDEX|VIEW|USER|ROLE|SCHEMA)\b/i
const SQL_UNION = /\bUNION\s+(?:ALL\s+)?SELECT\b/i
const SQL_STACKED = /;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE)\b/i
const SQL_EXFILTRATION = /\b(?:INTO\s+(?:OUT|DUMP)FILE|LOAD_FILE|COPY\s+.*\s+TO\b|pg_read_file|dblink)\b/i

const SQL_PATTERNS: readonly {
  readonly pattern: RegExp
  readonly label: string
  readonly severity: ViolationSeverity
}[] = Object.freeze([
  { pattern: SQL_DDL, label: 'ddl_statement', severity: 'critical' as const },
  { pattern: SQL_UNION, label: 'union_extraction', severity: 'high' as const },
  { pattern: SQL_STACKED, label: 'stacked_queries', severity: 'high' as const },
  { pattern: SQL_EXFILTRATION, label: 'data_exfiltration', severity: 'critical' as const },
])

// -- SSRF patterns ----------------------------------------------------------

const SSRF_INTERNAL_IP = /(?:^|\b|\/\/)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|::1|0:0:0:0:0:0:0:1)\b/
const SSRF_CLOUD_METADATA = /169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com/i
const SSRF_DANGEROUS_SCHEMES = /\b(?:file|gopher|dict|ldap|tftp):\/\//i
const SSRF_LOCALHOST_VARIANTS = /(?:localhost|0x7f|2130706433|017700000001|[:]{2}1)\b/i

const SSRF_PATTERNS: readonly {
  readonly pattern: RegExp
  readonly label: string
  readonly severity: ViolationSeverity
}[] = Object.freeze([
  { pattern: SSRF_INTERNAL_IP, label: 'internal_ip_access', severity: 'high' as const },
  { pattern: SSRF_CLOUD_METADATA, label: 'cloud_metadata_access', severity: 'critical' as const },
  { pattern: SSRF_DANGEROUS_SCHEMES, label: 'dangerous_scheme', severity: 'high' as const },
  { pattern: SSRF_LOCALHOST_VARIANTS, label: 'localhost_bypass', severity: 'high' as const },
])

// -- Path traversal patterns ------------------------------------------------

const PATH_DEEP_TRAVERSAL = /(?:\.\.\/){3,}|(?:\.\.\\){3,}/
const PATH_SENSITIVE = /(?:\/etc\/(?:passwd|shadow|sudoers|hosts)|~?\/?\.ssh\/|\.env(?:\.\w+)?$|\.git\/config|\.aws\/credentials|\.docker\/config)/i
const PATH_SYMLINK_INDICATOR = /\s->\s|\/proc\/self\/|\/dev\/fd\//

const PATH_PATTERNS: readonly {
  readonly pattern: RegExp
  readonly label: string
  readonly severity: ViolationSeverity
}[] = Object.freeze([
  { pattern: PATH_DEEP_TRAVERSAL, label: 'deep_traversal', severity: 'high' as const },
  { pattern: PATH_SENSITIVE, label: 'sensitive_path', severity: 'critical' as const },
  { pattern: PATH_SYMLINK_INDICATOR, label: 'symlink_attack', severity: 'high' as const },
])

// -- Universal patterns (applied to all tool categories) --------------------

const UNIVERSAL_HIDDEN_SHELL = /\$\(|`[^`]*`|\$\{.*\}/
const UNIVERSAL_BASE64_PAYLOAD = /(?:[A-Za-z0-9+/]{64,}={0,2})/

/** Maximum argument string length before flagging as suspicious */
const MAX_ARG_LENGTH = 10_240

/** Severity weight for risk score calculation */
const SEVERITY_WEIGHT: Readonly<Record<ViolationSeverity, number>> = Object.freeze({
  low: 0.15,
  medium: 0.35,
  high: 0.65,
  critical: 1.0,
})

// Category ordering for consistent categorize() resolution
const CATEGORY_ORDER: readonly ToolCategory[] = Object.freeze([
  'shell',
  'database',
  'http',
  'file',
])

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Classify a tool by its name into a security category.
 *
 * @param toolName - MCP tool name (e.g. "shell_exec", "db_query")
 * @returns The matched tool category
 */
export function categorize(toolName: string): ToolCategory {
  const lower = toolName.toLowerCase()
  for (const cat of CATEGORY_ORDER) {
    if (TOOL_NAME_PATTERNS[cat].test(lower)) {
      return cat
    }
  }
  return 'unknown'
}

/**
 * Validate all arguments of a tool call for dangerous patterns.
 *
 * Runs category-specific checks based on tool name classification,
 * plus universal checks on every tool call.
 *
 * @param toolName - MCP tool name
 * @param args - Tool call arguments
 * @returns Validation result with violations, risk score, and tool category
 */
export function validate(
  toolName: string,
  args: Readonly<Record<string, unknown>>,
): ToolCallSafetyResult {
  const category = categorize(toolName)
  const violations: SafetyViolation[] = []

  // Run category-specific checks
  switch (category) {
    case 'shell':
      collectViolations(args, SHELL_PATTERNS, 'shell_injection', violations)
      break
    case 'database':
      collectViolations(args, SQL_PATTERNS, 'sql_injection', violations)
      break
    case 'http':
      collectViolations(args, SSRF_PATTERNS, 'ssrf', violations)
      break
    case 'file':
      collectViolations(args, PATH_PATTERNS, 'path_traversal', violations)
      break
    case 'unknown':
      // Check all categories for unknown tools (defense in depth)
      collectViolations(args, SHELL_PATTERNS, 'shell_injection', violations)
      collectViolations(args, SQL_PATTERNS, 'sql_injection', violations)
      collectViolations(args, SSRF_PATTERNS, 'ssrf', violations)
      collectViolations(args, PATH_PATTERNS, 'path_traversal', violations)
      break
  }

  // Universal checks on all tools
  checkUniversalPatterns(args, violations)

  const riskScore = computeRiskScore(violations)

  return Object.freeze({
    allowed: violations.length === 0,
    violations: Object.freeze([...violations]),
    riskScore,
    toolCategory: category,
  })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Extract all string values from args (including nested objects and arrays).
 * Returns tuples of [parameterName, stringValue].
 */
function extractStringValues(
  args: Readonly<Record<string, unknown>>,
): readonly [string, string][] {
  const results: [string, string][] = []

  function walk(value: unknown, path: string): void {
    if (typeof value === 'string') {
      results.push([path, value])
      return
    }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        walk(value[i], `${path}[${i}]`)
      }
      return
    }
    if (value !== null && typeof value === 'object') {
      for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
        walk(v, path !== '' ? `${path}.${key}` : key)
      }
    }
  }

  for (const [key, value] of Object.entries(args)) {
    walk(value, key)
  }

  return results
}

/**
 * Test all string args against a set of patterns, pushing violations into the collector.
 */
function collectViolations(
  args: Readonly<Record<string, unknown>>,
  patterns: readonly {
    readonly pattern: RegExp
    readonly label: string
    readonly severity: ViolationSeverity
  }[],
  category: ViolationCategory,
  violations: SafetyViolation[],
): void {
  const stringValues = extractStringValues(args)

  for (const [paramName, value] of stringValues) {
    for (const { pattern, label, severity } of patterns) {
      if (pattern.test(value)) {
        violations.push(Object.freeze({
          category,
          parameterName: paramName,
          matchedPattern: label,
          severity,
        }))
      }
    }
  }
}

/**
 * Universal checks applied to every tool call regardless of category.
 */
function checkUniversalPatterns(
  args: Readonly<Record<string, unknown>>,
  violations: SafetyViolation[],
): void {
  const stringValues = extractStringValues(args)

  for (const [paramName, value] of stringValues) {
    // Hidden shell injection in any argument
    if (UNIVERSAL_HIDDEN_SHELL.test(value)) {
      violations.push(Object.freeze({
        category: 'shell_injection' as const,
        parameterName: paramName,
        matchedPattern: 'hidden_shell_injection',
        severity: 'high' as const,
      }))
    }

    // Excessively long arguments
    if (value.length > MAX_ARG_LENGTH) {
      violations.push(Object.freeze({
        category: 'payload_size' as const,
        parameterName: paramName,
        matchedPattern: `argument_length_${value.length}`,
        severity: 'medium' as const,
      }))
    }

    // Base64-encoded payloads (only flag if the string is mostly base64)
    if (value.length > 100 && UNIVERSAL_BASE64_PAYLOAD.test(value)) {
      const base64Ratio = countBase64Chars(value) / value.length
      if (base64Ratio > 0.8) {
        violations.push(Object.freeze({
          category: 'encoded_payload' as const,
          parameterName: paramName,
          matchedPattern: 'base64_encoded_payload',
          severity: 'medium' as const,
        }))
      }
    }
  }
}

/**
 * Count characters that are valid base64 encoding characters.
 */
function countBase64Chars(value: string): number {
  let count = 0
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i)
    // A-Z, a-z, 0-9, +, /, =
    if (
      (c >= 65 && c <= 90) ||
      (c >= 97 && c <= 122) ||
      (c >= 48 && c <= 57) ||
      c === 43 || c === 47 || c === 61
    ) {
      count++
    }
  }
  return count
}

/**
 * Compute a 0-1 risk score from violations using severity weights.
 * Uses the maximum single-violation weight, plus diminishing contributions
 * from additional violations (capped at 1.0).
 */
function computeRiskScore(violations: readonly SafetyViolation[]): number {
  if (violations.length === 0) return 0

  const weights = violations.map((v) => SEVERITY_WEIGHT[v.severity])
  const maxWeight = Math.max(...weights)
  const sumRemaining = weights
    .filter((w) => w !== maxWeight)
    .reduce((sum, w) => sum + w * 0.3, 0)

  return Math.min(1.0, maxWeight + sumRemaining)
}
