/**
 * OutputPayloadGuard — Scans LLM output for dangerous payloads BEFORE
 * returning to user/app.
 *
 * Detects 5 categories of dangerous content that an LLM might generate:
 * 1. SQL Injection patterns (DROP, UNION SELECT, etc.)
 * 2. XSS payloads (<script>, event handlers, javascript: URLs)
 * 3. SSRF indicators (internal IPs, cloud metadata endpoints)
 * 4. Shell command injection (reverse shells, rm -rf, pipe to shell)
 * 5. Path traversal (../ chains, sensitive file paths)
 *
 * Code fence awareness: patterns inside ```...``` blocks receive lower
 * confidence since they may be legitimate educational content.
 * Destructive commands inside code fences are still flagged.
 *
 * Performance target: <5ms for full scan.
 * All regex patterns are pre-compiled at module load time.
 *
 * Research references:
 * - OWASP LLM09:2025 — Improper Output Handling
 * - Schneier et al. 2026 Promptware Kill Chain (actions_on_objective)
 * - MITRE ATLAS AML.T0048.004 — Exfiltration via LLM Output
 */

import type { ScanResult, KillChainPhase, ThreatLevel } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a frozen ScanResult matching the orchestrator's expected shape */
function makeResult(
  ruleId: string,
  phase: KillChainPhase,
  confidence: number,
  threatLevel: ThreatLevel,
  description: string,
  matchedText: string,
  latencyMs: number,
): ScanResult {
  return Object.freeze({
    scannerId: ruleId,
    scannerType: 'canary' as const,
    detected: true,
    confidence,
    threatLevel,
    killChainPhase: phase,
    matchedPatterns: Object.freeze([matchedText.substring(0, 120)]),
    latencyMs,
    metadata: Object.freeze({ description, matchedText: matchedText.substring(0, 200) }),
  })
}

/** Map confidence to threat level using the same scale as RuleEngine */
function toThreatLevel(confidence: number): ThreatLevel {
  if (confidence >= 0.9) return 'critical'
  if (confidence >= 0.75) return 'high'
  if (confidence >= 0.5) return 'medium'
  if (confidence >= 0.25) return 'low'
  return 'none'
}

// ---------------------------------------------------------------------------
// Code fence detection
// ---------------------------------------------------------------------------

/**
 * Regex to match fenced code blocks (``` or ~~~).
 * Used to determine if a match falls inside a code fence,
 * which lowers confidence for non-destructive patterns.
 */
const CODE_FENCE_REGEX = /(?:```|~~~)[^\n]*\n[\s\S]*?(?:```|~~~)/g

/** Returns ranges [start, end] for all code fences in the text */
function getCodeFenceRanges(text: string): ReadonlyArray<readonly [number, number]> {
  const ranges: Array<readonly [number, number]> = []
  const regex = new RegExp(CODE_FENCE_REGEX.source, CODE_FENCE_REGEX.flags)
  let match: RegExpExecArray | null
  while ((match = regex.exec(text)) !== null) {
    ranges.push(Object.freeze([match.index, match.index + match[0].length] as const))
  }
  return Object.freeze(ranges)
}

/** Check if a character offset falls inside any code fence range */
function isInsideCodeFence(
  offset: number,
  ranges: ReadonlyArray<readonly [number, number]>,
): boolean {
  for (const [start, end] of ranges) {
    if (offset >= start && offset < end) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Pattern definition type
// ---------------------------------------------------------------------------

interface PayloadPattern {
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly baseConfidence: number
  /** If true, confidence is NOT reduced inside code fences (always dangerous) */
  readonly alwaysDangerous: boolean
}

// ---------------------------------------------------------------------------
// 1. SQL Injection Patterns
// ---------------------------------------------------------------------------

const SQL_INJECTION_PATTERNS: readonly PayloadPattern[] = Object.freeze([
  {
    pattern: /\bDROP\s+(?:TABLE|DATABASE|INDEX|VIEW|SCHEMA)\b/i,
    id: 'output-sql-drop',
    description: 'SQL DROP TABLE/DATABASE in LLM output',
    baseConfidence: 0.92,
    alwaysDangerous: true,
  },
  {
    pattern: /\bUNION\s+(?:ALL\s+)?SELECT\b[^;]*\bFROM\b/i,
    id: 'output-sql-union-select',
    description: 'UNION SELECT with data extraction pattern',
    baseConfidence: 0.88,
    alwaysDangerous: false,
  },
  {
    pattern: /['"];?\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER|EXEC)\b/i,
    id: 'output-sql-chained-command',
    description: 'SQL injection via string termination followed by SQL command',
    baseConfidence: 0.85,
    alwaysDangerous: false,
  },
  {
    pattern: /\bOR\s+['"]?1['"]?\s*=\s*['"]?1['"]?/i,
    id: 'output-sql-or-tautology',
    description: 'SQL tautology injection (OR 1=1)',
    baseConfidence: 0.82,
    alwaysDangerous: false,
  },
  {
    pattern: /\bAND\s+['"]?1['"]?\s*=\s*['"]?1['"]?/i,
    id: 'output-sql-and-tautology',
    description: 'SQL tautology injection (AND 1=1)',
    baseConfidence: 0.72,
    alwaysDangerous: false,
  },
  {
    pattern: /\b(?:EXEC|EXECUTE)\s+xp_cmdshell\b/i,
    id: 'output-sql-xp-cmdshell',
    description: 'SQL Server xp_cmdshell execution',
    baseConfidence: 0.95,
    alwaysDangerous: true,
  },
  {
    pattern: /\bLOAD_FILE\s*\(/i,
    id: 'output-sql-load-file',
    description: 'MySQL LOAD_FILE() file read attempt',
    baseConfidence: 0.9,
    alwaysDangerous: true,
  },
  {
    pattern: /\bINTO\s+(?:OUT|DUMP)FILE\b/i,
    id: 'output-sql-outfile',
    description: 'SQL INTO OUTFILE/DUMPFILE file write attempt',
    baseConfidence: 0.92,
    alwaysDangerous: true,
  },
  {
    pattern: /(?:--|\/\*)\s*(?:admin|bypass|drop|union|select|or\s+1)/i,
    id: 'output-sql-comment-injection',
    description: 'SQL comment used for injection bypass',
    baseConfidence: 0.78,
    alwaysDangerous: false,
  },
]) as readonly PayloadPattern[]

// ---------------------------------------------------------------------------
// 2. XSS Payload Patterns
// ---------------------------------------------------------------------------

const XSS_PATTERNS: readonly PayloadPattern[] = Object.freeze([
  {
    pattern: /<script\b[^>]*>[\s\S]*?<\/script>/i,
    id: 'output-xss-script-tag',
    description: 'HTML <script> tag with JavaScript content',
    baseConfidence: 0.92,
    alwaysDangerous: false,
  },
  {
    pattern: /\bon(?:error|load|click|mouseover|focus|blur|submit|change|input|keydown|keyup|keypress|mouseenter|mouseleave|dblclick|contextmenu)\s*=\s*["'][^"']*["']/i,
    id: 'output-xss-event-handler',
    description: 'HTML event handler attribute with JavaScript',
    baseConfidence: 0.88,
    alwaysDangerous: false,
  },
  {
    pattern: /\bjavascript\s*:/i,
    id: 'output-xss-javascript-url',
    description: 'javascript: URL scheme (XSS vector)',
    baseConfidence: 0.9,
    alwaysDangerous: false,
  },
  {
    pattern: /data\s*:\s*text\/html/i,
    id: 'output-xss-data-html',
    description: 'data:text/html payload (XSS vector)',
    baseConfidence: 0.88,
    alwaysDangerous: false,
  },
  {
    pattern: /<svg\b[^>]*\bon(?:load|error)\s*=/i,
    id: 'output-xss-svg',
    description: 'SVG-based XSS via onload/onerror handler',
    baseConfidence: 0.9,
    alwaysDangerous: false,
  },
  {
    pattern: /<img\b[^>]*\bsrc\s*=\s*["']?x["']?[^>]*\bon(?:error|load)\s*=/i,
    id: 'output-xss-img-onerror',
    description: '<img src=x onerror=...> XSS payload',
    baseConfidence: 0.92,
    alwaysDangerous: false,
  },
  {
    pattern: /(?:\{\{|\$\{|#\{)[^}]*(?:constructor|__proto__|prototype|eval|Function)\b/i,
    id: 'output-xss-expression-injection',
    description: 'Template expression injection targeting prototype/eval',
    baseConfidence: 0.85,
    alwaysDangerous: false,
  },
]) as readonly PayloadPattern[]

// ---------------------------------------------------------------------------
// 3. SSRF Indicator Patterns
// ---------------------------------------------------------------------------

const SSRF_PATTERNS: readonly PayloadPattern[] = Object.freeze([
  {
    pattern: /\bhttps?:\/\/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/i,
    id: 'output-ssrf-internal-ip',
    description: 'URL pointing to RFC 1918 internal IP address',
    baseConfidence: 0.82,
    alwaysDangerous: false,
  },
  {
    pattern: /\bhttps?:\/\/127\.0\.0\.1\b/i,
    id: 'output-ssrf-loopback',
    description: 'URL pointing to loopback address 127.0.0.1',
    baseConfidence: 0.8,
    alwaysDangerous: false,
  },
  {
    pattern: /\bhttps?:\/\/(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b/i,
    id: 'output-ssrf-cloud-metadata',
    description: 'URL pointing to cloud metadata endpoint (AWS/GCP/Alibaba)',
    baseConfidence: 0.95,
    alwaysDangerous: true,
  },
  {
    pattern: /\bhttps?:\/\/(?:0\.0\.0\.0|\[::1?\]|localhost)\b/i,
    id: 'output-ssrf-localhost-variant',
    description: 'URL pointing to localhost variant (0.0.0.0, [::], [::1], localhost)',
    baseConfidence: 0.78,
    alwaysDangerous: false,
  },
  {
    pattern: /\b(?:file|gopher|dict|ldap|tftp):\/\//i,
    id: 'output-ssrf-suspicious-scheme',
    description: 'Suspicious URL scheme (file://, gopher://, dict://, ldap://, tftp://)',
    baseConfidence: 0.88,
    alwaysDangerous: false,
  },
]) as readonly PayloadPattern[]

// ---------------------------------------------------------------------------
// 4. Shell Command Injection Patterns
// ---------------------------------------------------------------------------

const SHELL_INJECTION_PATTERNS: readonly PayloadPattern[] = Object.freeze([
  {
    pattern: /;\s*(?:rm|chmod|chown|wget|curl|nc|ncat|bash|sh|zsh|python|perl|ruby|php)\b/i,
    id: 'output-shell-chained-command',
    description: 'Shell command chaining via semicolon to dangerous command',
    baseConfidence: 0.85,
    alwaysDangerous: false,
  },
  {
    pattern: /&&\s*(?:rm|chmod|chown|wget|curl|nc|ncat|bash|sh|zsh|python|perl|ruby|php)\b/i,
    id: 'output-shell-and-chain',
    description: 'Shell command chaining via && to dangerous command',
    baseConfidence: 0.82,
    alwaysDangerous: false,
  },
  {
    pattern: /\$\([^)]*(?:rm|chmod|wget|curl|nc|bash|sh|python|perl|eval)\b/i,
    id: 'output-shell-command-substitution',
    description: 'Command substitution $(cmd) with dangerous command',
    baseConfidence: 0.88,
    alwaysDangerous: false,
  },
  {
    pattern: /`[^`]*(?:rm|chmod|wget|curl|nc|bash|sh|python|perl|eval)\b[^`]*`/i,
    id: 'output-shell-backtick-substitution',
    description: 'Backtick command substitution with dangerous command',
    baseConfidence: 0.85,
    alwaysDangerous: false,
  },
  {
    pattern: /\|\s*(?:bash|sh|zsh|dash|ksh|csh)\b/i,
    id: 'output-shell-pipe-to-shell',
    description: 'Pipe to shell interpreter (| bash, | sh)',
    baseConfidence: 0.9,
    alwaysDangerous: true,
  },
  {
    pattern: /\brm\s+-[rf]{1,2}[rf]?\s+\//i,
    id: 'output-shell-rm-rf',
    description: 'Destructive rm -rf with root-relative path',
    baseConfidence: 0.95,
    alwaysDangerous: true,
  },
  {
    pattern: /\bchmod\s+777\b/i,
    id: 'output-shell-chmod-777',
    description: 'chmod 777 — overly permissive file permissions',
    baseConfidence: 0.75,
    alwaysDangerous: false,
  },
  {
    pattern: /\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+/i,
    id: 'output-shell-reverse-shell-devtcp',
    description: 'Reverse shell via /dev/tcp',
    baseConfidence: 0.95,
    alwaysDangerous: true,
  },
  {
    pattern: /\bnc\s+-[elp]{1,3}\b/i,
    id: 'output-shell-netcat-listener',
    description: 'Netcat listener/reverse shell (nc -e, nc -l)',
    baseConfidence: 0.9,
    alwaysDangerous: true,
  },
  {
    pattern: /\bbash\s+-i\s+[>&]+\s*\/dev\//i,
    id: 'output-shell-bash-reverse-shell',
    description: 'Interactive bash reverse shell redirect',
    baseConfidence: 0.95,
    alwaysDangerous: true,
  },
]) as readonly PayloadPattern[]

// ---------------------------------------------------------------------------
// 5. Path Traversal Patterns
// ---------------------------------------------------------------------------

const PATH_TRAVERSAL_PATTERNS: readonly PayloadPattern[] = Object.freeze([
  {
    pattern: /(?:\.\.\/){3,}/,
    id: 'output-path-traversal-chain',
    description: 'Path traversal with 3+ levels of ../ directory escape',
    baseConfidence: 0.85,
    alwaysDangerous: false,
  },
  {
    pattern: /(?:\.\.\\){3,}/,
    id: 'output-path-traversal-backslash',
    description: 'Windows path traversal with 3+ levels of ..\\ directory escape',
    baseConfidence: 0.85,
    alwaysDangerous: false,
  },
  {
    pattern: /\/etc\/(?:passwd|shadow|sudoers|hosts)\b/,
    id: 'output-path-sensitive-unix',
    description: 'Reference to sensitive Unix system file',
    baseConfidence: 0.82,
    alwaysDangerous: false,
  },
  {
    pattern: /~\/\.ssh\/(?:id_rsa|id_ed25519|authorized_keys|known_hosts|config)\b/,
    id: 'output-path-ssh-keys',
    description: 'Reference to SSH key or configuration file',
    baseConfidence: 0.85,
    alwaysDangerous: false,
  },
  {
    pattern: /[A-Za-z]:\\Windows\\System32\\/i,
    id: 'output-path-windows-system32',
    description: 'Windows System32 path reference',
    baseConfidence: 0.72,
    alwaysDangerous: false,
  },
  {
    pattern: /(?:\.\.[\\/]){2,}(?:etc|Windows|usr|var|home|root)[\\/]/i,
    id: 'output-path-traversal-to-sensitive',
    description: 'Path traversal targeting sensitive system directories',
    baseConfidence: 0.9,
    alwaysDangerous: true,
  },
]) as readonly PayloadPattern[]

// ---------------------------------------------------------------------------
// All patterns combined (flat array for single-pass scan)
// ---------------------------------------------------------------------------

const ALL_PATTERNS: readonly PayloadPattern[] = Object.freeze([
  ...SQL_INJECTION_PATTERNS,
  ...XSS_PATTERNS,
  ...SSRF_PATTERNS,
  ...SHELL_INJECTION_PATTERNS,
  ...PATH_TRAVERSAL_PATTERNS,
])

// ---------------------------------------------------------------------------
// Code fence confidence reduction factor
// ---------------------------------------------------------------------------

/** Confidence multiplier when a match is inside a code fence */
const CODE_FENCE_CONFIDENCE_FACTOR = 0.55

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * OutputPayloadGuard — Scans LLM output for dangerous executable payloads.
 *
 * All patterns are pre-compiled at module load time for zero allocation
 * during scans. The class is instantiated once and reused across requests.
 *
 * Detects SQL injection, XSS, SSRF, shell command injection, and path
 * traversal patterns in LLM output. Code-fence-aware: patterns inside
 * fenced code blocks receive reduced confidence unless they are
 * inherently destructive (e.g., rm -rf /, reverse shells).
 *
 * Usage:
 * ```typescript
 * const guard = new OutputPayloadGuard()
 * const results = guard.scan(llmOutput)
 * ```
 */
export class OutputPayloadGuard {
  /**
   * Scan LLM output text for dangerous payload patterns.
   *
   * Iterates all pre-compiled patterns in a single pass and returns
   * a ScanResult for every detected pattern. Code-fence-aware:
   * matches inside ``` blocks get reduced confidence unless they
   * are always-dangerous patterns.
   *
   * @param output - Raw LLM output string
   * @returns Readonly array of ScanResult objects for detected threats
   */
  scan(output: string): readonly ScanResult[] {
    const start = performance.now()
    const results: ScanResult[] = []

    // Skip trivially short outputs
    if (output.length < 8) return Object.freeze([])

    // Pre-compute code fence ranges once for all pattern checks
    const codeFenceRanges = getCodeFenceRanges(output)

    for (const rule of ALL_PATTERNS) {
      // Create a fresh regex to avoid stateful exec issues
      const regex = new RegExp(rule.pattern.source, rule.pattern.flags)
      const match = regex.exec(output)
      if (match === null) continue

      const matchOffset = match.index
      const insideFence = isInsideCodeFence(matchOffset, codeFenceRanges)

      // Determine effective confidence
      const effectiveConfidence = insideFence && !rule.alwaysDangerous
        ? rule.baseConfidence * CODE_FENCE_CONFIDENCE_FACTOR
        : rule.baseConfidence

      results.push(
        makeResult(
          rule.id,
          'actions_on_objective',
          effectiveConfidence,
          toThreatLevel(effectiveConfidence),
          insideFence
            ? `${rule.description} (inside code fence)`
            : rule.description,
          match[0],
          performance.now() - start,
        ),
      )
    }

    return Object.freeze(results)
  }
}
