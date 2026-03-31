/**
 * Tool Chain Guard — monitors tool call sequences for attack patterns.
 * Based on CrowdStrike research: a single compromised agent poisons
 * 87% of downstream decisions within 4 hours.
 * Part of ShieldX Layer 7 (MCP Guard & Tool Security).
 */

/** Recorded tool call in the sliding window */
interface ToolCallEntry {
  readonly toolName: string
  readonly args: Readonly<Record<string, unknown>>
  readonly timestamp: number
}

/** Result of sequence analysis */
interface SequenceAnalysisResult {
  readonly suspicious: boolean
  readonly patterns: readonly string[]
  readonly confidence: number
}

/** Maximum sliding window size per session */
const MAX_WINDOW_SIZE = 50

/** Minimum interval (ms) between calls to flag rapid switching */
const RAPID_SWITCH_THRESHOLD_MS = 200

/** Minimum number of rapid calls to flag as automated */
const RAPID_SWITCH_MIN_COUNT = 5

/** Privilege escalation tool categories (ordered low -> high) */
const PRIVILEGE_LEVELS: readonly [string, readonly RegExp[]][] = [
  ['read', [/^(read|get|list|search|query|fetch|browse|view)/i]],
  ['write', [/^(write|create|update|set|put|post|patch)/i]],
  ['delete', [/^(delete|remove|drop|truncate|purge)/i]],
  ['execute', [/^(execute|run|invoke|call|trigger|deploy)/i]],
  ['admin', [/^(admin|config|manage|grant|revoke|sudo|root)/i, /(permission|role|access|policy)/i]],
]

/** Exfiltration-related tool patterns */
const EXFILTRATION_PATTERNS: readonly RegExp[] = [
  /^(send|email|post|upload|transmit|forward|push|publish|webhook)/i,
  /(external|remote|api|http|url|endpoint)/i,
]

/** Data gathering tool patterns */
const DATA_GATHERING_PATTERNS: readonly RegExp[] = [
  /^(read|get|list|search|query|fetch|scan|browse|download)/i,
  /(file|document|database|secret|credential|key|token|password|env)/i,
]

/** Per-session sliding window store */
const sessionWindows = new Map<string, readonly ToolCallEntry[]>()

/**
 * Determines the privilege level of a tool (0=read, 4=admin).
 */
function getPrivilegeLevel(toolName: string): number {
  for (let i = PRIVILEGE_LEVELS.length - 1; i >= 0; i--) {
    const entry = PRIVILEGE_LEVELS[i]
    if (entry === undefined) continue
    const [, patterns] = entry
    if (patterns.some((p: RegExp) => p.test(toolName))) {
      return i
    }
  }
  return 0
}

/**
 * Checks if a tool matches exfiltration patterns.
 */
function isExfiltrationTool(toolName: string): boolean {
  return EXFILTRATION_PATTERNS.some(p => p.test(toolName))
}

/**
 * Checks if a tool matches data gathering patterns.
 */
function isDataGatheringTool(toolName: string): boolean {
  return DATA_GATHERING_PATTERNS.some(p => p.test(toolName))
}

/**
 * Records a tool call in the session's sliding window.
 * Maintains a maximum of 50 entries per session (FIFO).
 *
 * @param sessionId - Session identifier
 * @param toolName - Name of the tool called
 * @param args - Arguments passed to the tool
 */
export function recordCall(
  sessionId: string,
  toolName: string,
  args: Readonly<Record<string, unknown>>,
): void {
  const existing = sessionWindows.get(sessionId) ?? []
  const entry: ToolCallEntry = {
    toolName,
    args,
    timestamp: Date.now(),
  }

  // Sliding window: keep last MAX_WINDOW_SIZE entries
  const updated = existing.length >= MAX_WINDOW_SIZE
    ? [...existing.slice(1), entry]
    : [...existing, entry]

  sessionWindows.set(sessionId, updated)
}

/**
 * Detects privilege escalation sequences (read -> write -> admin).
 */
function detectPrivilegeEscalation(entries: readonly ToolCallEntry[]): readonly string[] {
  const patterns: string[] = []
  let maxLevel = 0

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!
    const level = getPrivilegeLevel(entry.toolName)
    if (level > maxLevel + 1) {
      patterns.push(
        `privilege_escalation:${entry.toolName} jumped from level ${maxLevel} to ${level}`,
      )
    }
    if (level > maxLevel) {
      maxLevel = level
    }
  }

  return patterns
}

/**
 * Detects data gathering followed by exfiltration.
 */
function detectExfiltrationSequence(entries: readonly ToolCallEntry[]): readonly string[] {
  const patterns: string[] = []
  const gatherTools: string[] = []

  for (const entry of entries) {
    if (isDataGatheringTool(entry.toolName)) {
      gatherTools.push(entry.toolName)
    } else if (isExfiltrationTool(entry.toolName) && gatherTools.length > 0) {
      patterns.push(
        `data_exfiltration:gathered(${gatherTools.join(',')})->sent(${entry.toolName})`,
      )
    }
  }

  return patterns
}

/**
 * Detects rapid tool switching (sign of automated attack).
 */
function detectRapidSwitching(entries: readonly ToolCallEntry[]): readonly string[] {
  const patterns: string[] = []
  let rapidCount = 0

  for (let i = 1; i < entries.length; i++) {
    const current = entries[i]!
    const previous = entries[i - 1]!
    const delta = current.timestamp - previous.timestamp
    if (delta < RAPID_SWITCH_THRESHOLD_MS) {
      rapidCount++
    } else {
      rapidCount = 0
    }

    if (rapidCount >= RAPID_SWITCH_MIN_COUNT) {
      patterns.push(
        `rapid_switching:${rapidCount + 1} calls in <${RAPID_SWITCH_THRESHOLD_MS}ms intervals`,
      )
      break
    }
  }

  return patterns
}

/**
 * Detects circular tool call patterns (A -> B -> C -> A).
 */
function detectCircularPatterns(entries: readonly ToolCallEntry[]): readonly string[] {
  const patterns: string[] = []
  const windowSize = Math.min(entries.length, 20)
  const recent = entries.slice(-windowSize)

  // Build sequence of tool names
  const toolSequence = recent.map(e => e.toolName)

  // Look for repeating subsequences of length 2-5
  for (let patternLen = 2; patternLen <= 5; patternLen++) {
    if (toolSequence.length < patternLen * 2) continue

    for (let start = 0; start <= toolSequence.length - patternLen * 2; start++) {
      const subPattern = toolSequence.slice(start, start + patternLen)
      const nextChunk = toolSequence.slice(start + patternLen, start + patternLen * 2)

      if (JSON.stringify(subPattern) === JSON.stringify(nextChunk)) {
        patterns.push(
          `circular_pattern:${subPattern.join('->')} repeats`,
        )
        break
      }
    }
  }

  return patterns
}

/**
 * Detects calls to tools not in the declared task scope.
 */
function detectOutOfScopeTools(
  entries: readonly ToolCallEntry[],
  declaredTools: ReadonlySet<string>,
): readonly string[] {
  if (declaredTools.size === 0) return []

  const patterns: string[] = []
  for (const entry of entries) {
    if (!declaredTools.has(entry.toolName)) {
      patterns.push(`out_of_scope:${entry.toolName}`)
    }
  }

  return patterns
}

/**
 * Analyzes the tool call sequence for a session to detect attack patterns.
 *
 * Detected patterns:
 * - Privilege escalation sequences (read -> write -> admin)
 * - Data gathering followed by exfiltration
 * - Rapid tool switching (automated attack indicator)
 * - Circular tool call patterns (A -> B -> C -> A)
 * - Calls to tools outside declared task scope
 *
 * @param sessionId - Session identifier
 * @param declaredTools - Optional set of tools declared for the task
 * @returns Analysis result with detected patterns and confidence
 */
export function analyzeSequence(
  sessionId: string,
  declaredTools?: ReadonlySet<string>,
): SequenceAnalysisResult {
  const entries = sessionWindows.get(sessionId)

  if (entries === undefined || entries.length < 2) {
    return { suspicious: false, patterns: [], confidence: 0 }
  }

  const allPatterns: string[] = []

  allPatterns.push(...detectPrivilegeEscalation(entries))
  allPatterns.push(...detectExfiltrationSequence(entries))
  allPatterns.push(...detectRapidSwitching(entries))
  allPatterns.push(...detectCircularPatterns(entries))

  if (declaredTools !== undefined) {
    allPatterns.push(...detectOutOfScopeTools(entries, declaredTools))
  }

  const confidence = allPatterns.length === 0
    ? 0
    : Math.min(0.99, 0.3 + allPatterns.length * 0.12)

  return {
    suspicious: allPatterns.length > 0,
    patterns: allPatterns,
    confidence,
  }
}

/**
 * Clears the sliding window for a session (cleanup).
 *
 * @param sessionId - Session to clear
 */
export function clearSession(sessionId: string): void {
  sessionWindows.delete(sessionId)
}

/**
 * Returns the current window size for a session (diagnostics).
 *
 * @param sessionId - Session to query
 * @returns Number of recorded tool calls
 */
export function getWindowSize(sessionId: string): number {
  return sessionWindows.get(sessionId)?.length ?? 0
}
